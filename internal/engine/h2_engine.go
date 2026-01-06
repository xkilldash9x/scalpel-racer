// FILENAME: internal/engine/h2_engine.go
package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
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

// RunH2Race executes the Single Packet Attack (SPA) using HTTP/2.
// Refactored for OBJ-03: Optimized Spin Barrier and Scheduler alignment.
func (r *Racer) RunH2Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int) ([]models.ScanResult, error) {
	start := time.Now()

	// 1. Config
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 15 * time.Second
	conf.InsecureSkipVerify = true
	conf.H2Config.PingInterval = 0

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// 2. Connect
	client, err := r.Factory.NewH2Client(u, conf, r.Logger)
	if err != nil {
		return nil, fmt.Errorf("client init error: %w", err)
	}

	r.Logger.Info("Establishing H2 connection...")
	if err := client.Connect(raceCtx); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// 3. Prepare
	r.Logger.Info("Priming streams...", zap.Int("concurrency", concurrency))

	handles := make([]*customhttp.H2StreamHandle, concurrency)
	results := make([]models.ScanResult, concurrency)

	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	for i := 0; i < concurrency; i++ {
		if raceCtx.Err() != nil {
			return nil, raceCtx.Err()
		}

		req, _ := http.NewRequestWithContext(raceCtx, method, reqSpec.URL, bytes.NewReader(reqSpec.Body))

		// Explicitly set Host from spec if present.
		// Since the URL might be an IP address (rewritten by UI model), we must force
		// the correct Virtual Host in the :authority pseudo-header.
		if h, ok := reqSpec.Headers["Host"]; ok {
			req.Host = h
		}

		req.Header.Set("User-Agent", "Scalpel-Racer/Go-H2")
		req.Header.Set("X-Scalpel-ID", fmt.Sprintf("%d", i))
		for k, v := range reqSpec.Headers {
			req.Header.Set(k, v)
		}

		// PrepareRequest sends HEADERS frame immediately.
		handle, err := client.PrepareRequest(raceCtx, req)
		if err != nil {
			results[i] = models.NewScanResult(i, 0, 0, nil, err)
			continue
		}
		handles[i] = handle
	}

	// 4. Attack
	time.Sleep(1 * time.Millisecond) // Stabilize
	r.Logger.Info("Releasing payload (SPA)...")

	// DISABLE GC
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	var wg sync.WaitGroup
	var readyWg sync.WaitGroup
	var startFlag int32
	validWorkers := 0

	for i, h := range handles {
		if h == nil {
			continue
		}
		wg.Add(1)
		readyWg.Add(1)
		validWorkers++

		go func(idx int, handle *customhttp.H2StreamHandle) {
			defer wg.Done()

			// Lock OS thread to prevent preemption
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			readyWg.Done()

			// SPIN BARRIER: Busy loop on atomic.
			// Check context infrequently to maximize spin speed.
			spin := 0
			for atomic.LoadInt32(&startFlag) == 0 {
				spin++
				if spin&1023 == 0 {
					if raceCtx.Err() != nil {
						return
					}
				}
			}

			reqStart := time.Now()

			// Trigger
			if err := client.ReleaseBody(handle); err != nil {
				results[idx] = models.NewScanResult(idx, 0, time.Since(reqStart), nil, err)
				return
			}

			// Wait
			resp, err := client.WaitResponse(raceCtx, handle)
			duration := time.Since(reqStart)

			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i, h)
	}

	if validWorkers > 0 {
		readyWg.Wait()
		// Fire!
		atomic.StoreInt32(&startFlag, 1)
		wg.Wait()
	}

	r.Logger.Info("Race complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}
