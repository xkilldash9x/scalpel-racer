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
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/sync/barrier"
	"go.uber.org/zap"
)

// RunH2Race executes the Single Packet Attack (SPA) using HTTP/2.
// Implements streaming results via channel (REF-001) and SpinBarrier (REF-002).
func (r *Racer) RunH2Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int, results chan<- models.ScanResult) error {
	defer close(results)
	start := time.Now()

	// 1. Config
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = config.H2RequestTimeout
	conf.InsecureSkipVerify = true
	conf.H2Config.PingInterval = 0

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// 2. Connect
	client, err := r.Factory.NewH2Client(u, conf, r.Logger)
	if err != nil {
		return fmt.Errorf("client init error: %w", err)
	}

	r.Logger.Info("Establishing H2 connection...")
	if err := client.Connect(raceCtx); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// 3. Prepare
	r.Logger.Info("Priming streams...", zap.Int("concurrency", concurrency))

	handles := make([]*customhttp.H2StreamHandle, concurrency)
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	for i := 0; i < concurrency; i++ {
		if raceCtx.Err() != nil {
			return raceCtx.Err()
		}

		req, _ := http.NewRequestWithContext(raceCtx, method, reqSpec.URL, bytes.NewReader(reqSpec.Body))
		if h, ok := reqSpec.Headers["Host"]; ok {
			req.Host = h
		}
		req.Header.Set("User-Agent", "Scalpel-Racer/Go-H2")
		req.Header.Set("X-Scalpel-ID", fmt.Sprintf("%d", i))
		for k, v := range reqSpec.Headers {
			req.Header.Set(k, v)
		}

		handle, err := client.PrepareRequest(raceCtx, req)
		if err != nil {
			results <- models.NewScanResult(i, 0, 0, nil, err)
			continue
		}
		handles[i] = handle
	}

	// 4. Attack
	gate := barrier.NewSpinBarrier(concurrency)
	var wg sync.WaitGroup

	// Disable GC for stability
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	for i, h := range handles {
		if h == nil {
			// Vote but do not spin worker to prevent deadlock
			go func() {
				gate.Await(raceCtx)
			}()
			continue
		}
		wg.Add(1)

		go func(idx int, handle *customhttp.H2StreamHandle) {
			defer wg.Done()

			// Thread pinning for high precision
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			if err := gate.Await(raceCtx); err != nil {
				return
			}

			reqStart := time.Now()
			if err := client.ReleaseBody(handle); err != nil {
				results <- models.NewScanResult(idx, 0, time.Since(reqStart), nil, err)
				return
			}

			resp, err := client.WaitResponse(raceCtx, handle)
			duration := time.Since(reqStart)

			if err != nil {
				results <- models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, config.MaxCaptureSize))
			results <- models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i, h)
	}

	if err := gate.WaitReady(raceCtx); err != nil {
		return err
	}

	time.Sleep(1 * time.Millisecond) // Stabilize
	r.Logger.Info("Releasing H2 payload (SPA)...")
	gate.Release()

	wg.Wait()
	r.Logger.Info("H2 Race complete", zap.Duration("total_duration", time.Since(start)))
	return nil
}
