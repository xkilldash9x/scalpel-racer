// FILENAME: internal/engine/engine.go
package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"runtime"
	"runtime/debug" // Add this

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// Racer is the core service for executing synchronization attacks.
type Racer struct {
	Factory ClientFactory
	Logger  *zap.Logger
}

// NewRacer creates a racer with the provided factory.
func NewRacer(f ClientFactory, logger *zap.Logger) *Racer {
	return &Racer{
		Factory: f,
		Logger:  logger,
	}
}

// RunH2Race executes the Single Packet Attack (SPA) using HTTP/2.
// It leverages the opaque H2StreamHandle provided by customhttp.
func (r *Racer) RunH2Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int) ([]models.ScanResult, error) {
	start := time.Now()

	// 1. Configure
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 15 * time.Second
	conf.InsecureSkipVerify = true
	// Disable PINGs to keep the wire quiet during the race preparation
	conf.H2Config.PingInterval = 0

	// CRITICAL FIX: Create a context with the configured timeout.
	// This ensures that if the underlying client ignores conf.RequestTimeout in favor of the context,
	// we still enforce the deadline preventing infinite hangs.
	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	client, err := r.Factory.NewH2Client(u, conf, r.Logger)
	if err != nil {
		return nil, fmt.Errorf("client init error: %w", err)
	}

	// 2. Connect
	r.Logger.Info("Establishing H2 connection...")
	if err := client.Connect(raceCtx); err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	// 3. Prepare Phase
	r.Logger.Info("Priming streams (Sending HEADERS)...", zap.Int("concurrency", concurrency))

	handles := make([]*customhttp.H2StreamHandle, concurrency)
	results := make([]models.ScanResult, concurrency)

	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	for i := 0; i < concurrency; i++ {
		// Check context before heavy allocation loop
		if raceCtx.Err() != nil {
			return nil, raceCtx.Err()
		}

		// New Reader per request is critical for H2Client's body handling/retries
		req, _ := http.NewRequestWithContext(raceCtx, method, reqSpec.URL, bytes.NewReader(reqSpec.Body))
		req.Header.Set("User-Agent", "Scalpel-Racer/Go-H2")
		req.Header.Set("X-Scalpel-ID", fmt.Sprintf("%d", i))
		for k, v := range reqSpec.Headers {
			req.Header.Set(k, v)
		}

		// Call PrepareRequest: sends HEADERS, holds DATA
		handle, err := client.PrepareRequest(raceCtx, req)
		if err != nil {
			results[i] = models.NewScanResult(i, 0, 0, nil, err)
			continue
		}
		handles[i] = handle
	}

	// 4. Sync Warmup
	time.Sleep(50 * time.Millisecond)

	// 5. Attack
	r.Logger.Info("Releasing payload (Sending DATA)...")

	// OPTIMIZATION: Disable GC during critical race window
	// This prevents "Stop-the-World" pauses from desynchronizing the packet burst.
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	var wg sync.WaitGroup
	// Atomic flag for attosecond-level release precision (replacing channel broadcast)
	var startFlag int32

	var readyWg sync.WaitGroup
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
			readyWg.Done() // Signal ready

			// OPTIMIZATION: Lock OS Thread to prevent scheduler preemption during the race window.
			// This maximizes timing precision ("attosecond" optimization).
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// SPIN BARRIER (Precision Optimization)
			// Wait for the global atomic trigger without scheduler overhead
			for atomic.LoadInt32(&startFlag) == 0 {
				// Check context cheaply to allow aborts without locking up
				if raceCtx.Err() != nil {
					return
				}
			}
			reqStart := time.Now()

			// A. Trigger: Release DATA frame using the opaque handle
			if err := client.ReleaseBody(handle); err != nil {
				results[idx] = models.NewScanResult(idx, 0, time.Since(reqStart), nil, err)
				return
			}

			// B. Wait: Get Response
			resp, err := client.WaitResponse(raceCtx, handle)
			duration := time.Since(reqStart)

			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			defer resp.Body.Close()

			// C. Capture Body
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i, h)
	}

	if validWorkers > 0 {
		// Wait for all workers to reach the start line
		readyWg.Wait()
		// Release! (Atomic Store is instantaneous compared to Channel close)
		atomic.StoreInt32(&startFlag, 1)
		wg.Wait()
	}
	r.Logger.Info("Race complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}
