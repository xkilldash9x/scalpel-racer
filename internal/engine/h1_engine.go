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
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/sync/barrier"
	"go.uber.org/zap"
)

// RunH1Race executes the staged packet attack using HTTP/1.1 via the Racer service.
// Updated to use SpinBarrier and streaming results (REF-001/REF-002).
func (r *Racer) RunH1Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int, results chan<- models.ScanResult) error {
	defer close(results)
	start := time.Now()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	plan, err := PlanH1Attack(reqSpec)
	if err != nil {
		return fmt.Errorf("attack planning failed: %w", err)
	}
	wireStages := plan.WireStages

	// Barrier Setup: One barrier per stage transition
	numStages := len(wireStages)
	intermediateBarriers := make([]*barrier.SpinBarrier, 0)
	if numStages > 1 {
		for i := 0; i < numStages-1; i++ {
			intermediateBarriers = append(intermediateBarriers, barrier.NewSpinBarrier(concurrency))
		}
	}

	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = config.H1RequestTimeout
	conf.InsecureSkipVerify = true

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()

			// Pin thread for the duration of the race
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			client, err := r.Factory.NewH1Client(u, conf, r.Logger)
			if err != nil {
				results <- models.NewScanResult(idx, 0, 0, nil, err)
				return
			}
			defer client.Close()

			if err := client.Connect(raceCtx); err != nil {
				results <- models.NewScanResult(idx, 0, 0, nil, err)
				return
			}

			// EXECUTE STAGES
			for step, stagePayload := range wireStages {
				isFinalStage := step == numStages-1

				if raceCtx.Err() != nil {
					results <- models.NewScanResult(idx, 0, 0, nil, raceCtx.Err())
					return
				}

				if len(stagePayload) > 0 {
					if err := client.SendRaw(raceCtx, stagePayload); err != nil {
						results <- models.NewScanResult(idx, 0, 0, nil, err)
						return
					}
				}

				if !isFinalStage {
					b := intermediateBarriers[step]
					if err := b.Await(raceCtx); err != nil {
						results <- models.NewScanResult(idx, 0, 0, nil, err)
						return
					}
				}
			}

			reqStart := time.Now()
			responses, err := client.ReadPipelinedResponses(raceCtx, 1)
			duration := time.Since(reqStart)

			if err != nil {
				results <- models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			if len(responses) == 0 {
				results <- models.NewScanResult(idx, 0, duration, nil, fmt.Errorf("empty response"))
				return
			}

			resp := responses[0]
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, config.MaxCaptureSize))
			resp.Body.Close()
			results <- models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i)
	}

	// Orchestration: Release barriers sequentially
	for _, b := range intermediateBarriers {
		if err := b.WaitReady(raceCtx); err != nil {
			r.Logger.Warn("Context cancelled during alignment")
			return err
		}
		// Small stabilization sleep between stages
		time.Sleep(1 * time.Millisecond)
		b.Release()
	}

	wg.Wait()
	r.Logger.Info("H1 Race complete", zap.Duration("total_duration", time.Since(start)))
	return nil
}
