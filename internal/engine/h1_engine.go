// FILENAME: internal/engine/h1_engine.go
package engine

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// RunH1Race executes the staged packet attack using HTTP/1.1 via the Racer service.
// It relies on PlanH1Attack (defined in planner.go) for split logic.
func (r *Racer) RunH1Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int) ([]models.ScanResult, error) {
	start := time.Now()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// 1. Plan Attack (Pure Logic)
	plan, err := PlanH1Attack(reqSpec)
	if err != nil {
		return nil, fmt.Errorf("attack planning failed: %w", err)
	}
	wireStages := plan.WireStages

	r.Logger.Info("Attack configured",
		zap.Int("concurrency", concurrency),
		zap.Int("stages", len(wireStages)),
		zap.Int64("content_length", plan.CleanRequest.ContentLength),
	)

	// 2. Setup Barriers
	numStages := len(wireStages)
	// ContextBarrier allows breaking the wait if context cancels
	intermediateBarriers := make([]*ContextBarrier, 0)
	if numStages > 1 {
		for i := 0; i < numStages-1; i++ {
			intermediateBarriers = append(intermediateBarriers, NewContextBarrier(concurrency))
		}
	}

	// 3. Execution
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 20 * time.Second
	conf.InsecureSkipVerify = true

	// CRITICAL FIX: Enforce a hard timeout on the context.
	// The parent ctx (m.Ctx) might be background/infinite. We must ensure
	// that if the network or PacketController hangs, we abort eventually.
	// We add a buffer to the config timeout to allow for setup overhead.
	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	// OPTIMIZATION: Disable GC for H1 pipeline synchronization
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	results := make([]models.ScanResult, concurrency)
	var activeWg sync.WaitGroup
	var readyWg sync.WaitGroup // For synchronizing the Spinlock Entry

	// Optimized Spinlock Barrier for attosecond-precision release
	var startFlag int32

	// drainBarriers ensures no worker is left stuck at a barrier if others fail/die
	drainBarriers := func(fromStage int) {
		for i := fromStage; i < len(intermediateBarriers); i++ {
			intermediateBarriers[i].ForceRelease()
		}
	}

	for i := 0; i < concurrency; i++ {
		client, err := r.Factory.NewH1Client(u, conf, r.Logger)
		if err != nil {
			results[i] = models.NewScanResult(i, 0, 0, nil, err)
			// Failed to start: drain all barriers for this missing worker
			drainBarriers(0)
			continue
		}

		activeWg.Add(1)
		readyWg.Add(1)
		go func(idx int, c H1Client) {
			defer activeWg.Done()
			defer c.Close()

			if err := c.Connect(raceCtx); err != nil {
				results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
				readyWg.Done() // Failed
				drainBarriers(0)
				return
			}

			// EXECUTE STAGES
			for step, stagePayload := range wireStages {
				isFinalStage := step == numStages-1

				// Check context before potential blocking operations
				if raceCtx.Err() != nil {
					results[idx] = models.NewScanResult(idx, 0, 0, nil, raceCtx.Err())
					if !isFinalStage {
						drainBarriers(step)
					}
					if step == numStages-2 {
						readyWg.Done()
					}
					return
				}

				if len(stagePayload) > 0 {
					// Use SendRaw to bypass standard serialization
					if err := c.SendRaw(raceCtx, stagePayload); err != nil {
						results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
						if !isFinalStage {
							// Failed during stage sending: drain remaining barriers
							drainBarriers(step)
						}
						if step == numStages-2 {
							readyWg.Done()
						}
						return
					}
				}

				if !isFinalStage {
					barrier := intermediateBarriers[step]
					barrier.Vote()

					// Barrier Synchronization
					if step == numStages-2 {
						// Final Pre-Flight Alignment
						readyWg.Done() // Signal that we are at the gate

						// OPTIMIZATION: Lock OS Thread.
						// Ensures the spinlock isn't preempted by the scheduler.
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()

						// SPIN BARRIER: High-Precision Busy Wait (Spinlock)
						// This avoids the scheduler overhead of 'select'
						for atomic.LoadInt32(&startFlag) == 0 {
							// Check context cheaply to allow aborts without locking up
							if raceCtx.Err() != nil {
								results[idx] = models.NewScanResult(idx, 0, 0, nil, raceCtx.Err())
								return
							}
						}
					} else {
						// Standard Barrier Wait
						if err := barrier.Wait(raceCtx); err != nil {
							results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
							return
						}
					}
				}
			}

			reqStart := time.Now()
			// This blocking call is now protected by raceCtx timeout
			responses, err := c.ReadPipelinedResponses(raceCtx, 1)
			duration := time.Since(reqStart)

			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			if len(responses) == 0 {
				results[idx] = models.NewScanResult(idx, 0, duration, nil, fmt.Errorf("empty response"))
				return
			}

			resp := responses[0]
			// Limit capture to prevent OOM on large responses
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()

			results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i, client)
	}

	// 4. Orchestrate
	if len(intermediateBarriers) > 0 {
		finalBarrier := intermediateBarriers[len(intermediateBarriers)-1]
		// Wait for all healthy clients to align at the final barrier
		if err := finalBarrier.Wait(raceCtx); err != nil {
			r.Logger.Warn("Context cancelled during alignment")
			atomic.StoreInt32(&startFlag, 1) // Release spinners
			activeWg.Wait()
			return nil, err
		}
	} else {
		// Safety sleep for Last-Byte sync fallback
		time.Sleep(100 * time.Millisecond)
	}

	// If we have stages, we wait for the final synchronization group
	if len(intermediateBarriers) > 0 {
		// Wait for all active routines to be spinning on the atomic flag
		readyWg.Wait()
	}

	time.Sleep(50 * time.Millisecond)

	r.Logger.Info("Releasing final stage...")
	// ATOMIC RELEASE: The fastest possible broadcast in userspace
	atomic.StoreInt32(&startFlag, 1)
	activeWg.Wait()

	r.Logger.Info("H1 Race complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}

// ContextBarrier is a WaitGroup alternative that respects context cancellation
type ContextBarrier struct {
	target int
	count  int
	done   chan struct{}
	mu     sync.Mutex
}

func NewContextBarrier(target int) *ContextBarrier {
	return &ContextBarrier{
		target: target,
		done:   make(chan struct{}),
	}
}

func (b *ContextBarrier) Vote() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	if b.count >= b.target {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
}

func (b *ContextBarrier) ForceRelease() {
	b.mu.Lock()
	defer b.mu.Unlock()
	select {
	case <-b.done:
	default:
		close(b.done)
	}
}

func (b *ContextBarrier) Wait(ctx context.Context) error {
	select {
	case <-b.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
