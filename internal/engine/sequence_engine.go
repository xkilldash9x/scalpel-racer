// FILENAME: internal/engine/sequence_engine.go
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

// RunSequenceRace targets Multi-Endpoint and Check-Then-Act variations.
// It coordinates two DISTINCT requests (reqA, reqB) to arrive simultaneously using independent connections.
func (r *Racer) RunSequenceRace(ctx context.Context, reqA, reqB *models.CapturedRequest) ([]models.ScanResult, error) {
	start := time.Now()

	// 1. Configuration & Context
	// We use a strict timeout to ensure we don't hang resources on failed syncs.
	// This covers connection, preparation, sync wait, and reading.
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 15 * time.Second
	conf.InsecureSkipVerify = true
	conf.H2Config.PingInterval = 0 // Silence the wire

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	// 2. Initialize Clients (Distinct Connections)
	// We force distinct clients to ensure distinct TCP connections.
	// This prevents HTTP/2 multiplexing from serializing the requests on a single socket.
	clientA, err := r.initClient(raceCtx, reqA, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to init client A: %w", err)
	}
	defer clientA.Close()

	clientB, err := r.initClient(raceCtx, reqB, conf)
	if err != nil {
		return nil, fmt.Errorf("failed to init client B: %w", err)
	}
	defer clientB.Close()

	// 3. Prepare Phase (Send Headers, Hold Data)
	r.Logger.Info("Priming sequence streams...")

	// Prepare A
	httpReqA, err := r.buildRequest(raceCtx, reqA, "A")
	if err != nil {
		return nil, err
	}
	handleA, err := clientA.PrepareRequest(raceCtx, httpReqA)
	if err != nil {
		return nil, fmt.Errorf("prepare A failed: %w", err)
	}

	// Prepare B
	httpReqB, err := r.buildRequest(raceCtx, reqB, "B")
	if err != nil {
		return nil, err
	}
	handleB, err := clientB.PrepareRequest(raceCtx, httpReqB)
	if err != nil {
		return nil, fmt.Errorf("prepare B failed: %w", err)
	}

	// 4. Synchronization Barrier Setup
	var wg sync.WaitGroup
	var readyWg sync.WaitGroup
	var startFlag int32 // Atomic trigger: 0 = Hold, 1 = Fire

	results := make([]models.ScanResult, 2)

	// Define the worker logic
	runWorker := func(idx int, client H2Client, handle *customhttp.H2StreamHandle) {
		defer wg.Done()

		// Signal we are at the barrier
		readyWg.Done()

		// CRITICAL: Lock OS Thread to prevent scheduler preemption.
		// This keeps the goroutine on the CPU core.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// SPIN BARRIER: Busy-wait for the atomic signal.
		// This is significantly faster than channel wake-ups.
		for atomic.LoadInt32(&startFlag) == 0 {
			// Cheap context check to avoid deadlocks if the coordinator dies
			if raceCtx.Err() != nil {
				return
			}
		}

		reqStart := time.Now()

		// ATOMIC RELEASE: Fire the data frame
		if err := client.ReleaseBody(handle); err != nil {
			results[idx] = models.NewScanResult(idx, 0, time.Since(reqStart), nil, err)
			return
		}

		// WAIT: Capture response
		resp, err := client.WaitResponse(raceCtx, handle)
		duration := time.Since(reqStart)

		if err != nil {
			results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
			return
		}
		defer resp.Body.Close()

		// Read Body (Limit 1MB to prevent OOM on large dumps)
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
	}

	wg.Add(2)
	readyWg.Add(2)

	// 5. Engage
	// Disable GC to prevent "Stop-the-World" during the critical microsecond window
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	go runWorker(0, clientA, handleA)
	go runWorker(1, clientB, handleB)

	// Wait for workers to lock onto their threads and hit the spin loop
	readyWg.Wait()

	// Small settle time for network stack and CPU pipelines
	time.Sleep(10 * time.Millisecond)

	r.Logger.Info("Releasing sequence...")

	// ATOMIC FIRE
	atomic.StoreInt32(&startFlag, 1)

	wg.Wait()

	r.Logger.Info("Sequence complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}

// Helper: Client Initialization
func (r *Racer) initClient(ctx context.Context, req *models.CapturedRequest, conf *customhttp.ClientConfig) (H2Client, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	client, err := r.Factory.NewH2Client(u, conf, r.Logger)
	if err != nil {
		return nil, err
	}

	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	return client, nil
}

// Helper: Request Building
func (r *Racer) buildRequest(ctx context.Context, reqSpec *models.CapturedRequest, label string) (*http.Request, error) {
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequestWithContext(ctx, method, reqSpec.URL, bytes.NewReader(reqSpec.Body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Scalpel-Racer/Sequence")
	req.Header.Set("X-Scalpel-Seq", label)
	for k, v := range reqSpec.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}
