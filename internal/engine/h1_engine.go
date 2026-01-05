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

	// 1. Plan Attack
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

	// Create strict context to prevent hangs
	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	//  Disable GC safely.
	// capture the old value to restore it later.  Don't call runtime.GC().
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	results := make([]models.ScanResult, concurrency)
	var activeWg sync.WaitGroup
	var readyWg sync.WaitGroup
	var startFlag int32

	// Helper to unblock waiting routines if something fails
	drainBarriers := func(fromStage int) {
		for i := fromStage; i < len(intermediateBarriers); i++ {
			intermediateBarriers[i].ForceRelease()
		}
	}

	var successfulWorkers int32

	for i := 0; i < concurrency; i++ {
		activeWg.Add(1)
		readyWg.Add(1)

		// OPTIMIZATION: Initialize clients in parallel inside the goroutine
		go func(idx int) {
			defer activeWg.Done()

			client, err := r.Factory.NewH1Client(u, conf, r.Logger)
			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
				readyWg.Done()
				drainBarriers(0)
				return
			}
			defer client.Close()

			if err := client.Connect(raceCtx); err != nil {
				results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
				readyWg.Done()
				drainBarriers(0)
				return
			}

			atomic.AddInt32(&successfulWorkers, 1)

			// EXECUTE STAGES
			for step, stagePayload := range wireStages {
				isFinalStage := step == numStages-1

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
					if err := client.SendRaw(raceCtx, stagePayload); err != nil {
						results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
						if !isFinalStage {
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

					if step == numStages-2 {
						// Final Pre-Flight
						readyWg.Done()
						runtime.LockOSThread()
						defer runtime.UnlockOSThread()
						for atomic.LoadInt32(&startFlag) == 0 {
							if raceCtx.Err() != nil {
								results[idx] = models.NewScanResult(idx, 0, 0, nil, raceCtx.Err())
								return
							}
						}
					} else {
						// Standard Wait
						if err := barrier.Wait(raceCtx); err != nil {
							results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
							return
						}
					}
				}
			}

			reqStart := time.Now()
			responses, err := client.ReadPipelinedResponses(raceCtx, 1)
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
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			resp.Body.Close()
			results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i)
	}

	// 4. Orchestrate
	if len(intermediateBarriers) > 0 {
		finalBarrier := intermediateBarriers[len(intermediateBarriers)-1]
		if err := finalBarrier.Wait(raceCtx); err != nil {
			r.Logger.Warn("Context cancelled during alignment")
			atomic.StoreInt32(&startFlag, 1)
			activeWg.Wait()
			return nil, err
		}
	} else {
		// Reduced safe-guard sleep from 50ms to 1ms
		time.Sleep(1 * time.Millisecond)
	}

	if len(intermediateBarriers) > 0 {
		readyWg.Wait()
	}

	// Optimization: Only sleep if actual workers are waiting
	if atomic.LoadInt32(&successfulWorkers) > 0 {
		time.Sleep(1 * time.Millisecond)
	}

	r.Logger.Info("Releasing final stage...")
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
