// FILENAME: internal/engine/h3_engine.go
package engine

import (
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

// SyncReader implements the "Quic-Fin-Sync" technique.
// It proxies the request body but strictly withholds the final byte.
// It uses an atomic spin-barrier to hold the QUIC transport inside the Read() call.
type SyncReader struct {
	data    []byte
	offset  int
	flag    *int32 // Pointer to global atomic trigger (0=Hold, 1=Release)
	ctx     context.Context
	onReady func() // Callback to signal the engine we are at the barrier
}

// Read implements io.Reader with synchronization logic.
func (r *SyncReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}

	remaining := len(r.data) - r.offset
	canRead := remaining

	// LOGIC: Check if we are approaching the end of the stream.
	// If the barrier is still UP (flag == 0), we must NOT send the last byte.
	if atomic.LoadInt32(r.flag) == 0 {
		if remaining > 1 {
			// We have plenty of data left. Read up to N-1.
			// This allows the QUIC stack to transmit the bulk of the body.
			canRead = remaining - 1
		} else {
			// We are at the last byte (or the only byte). STOP.

			// 1. Signal the Orchestrator that this stream is primed.
			if r.onReady != nil {
				r.onReady()
			}

			// 2. Spin Barrier.
			// We busy-wait inside the Read call. This effectively pauses the
			// QUIC stream state machine exactly where we want it (before FIN).
			// Optimization: Check context and yield less frequently for lower latency.
			spin := 0
			for atomic.LoadInt32(r.flag) == 0 {
				spin++
				// Check safety every 1024 iterations to minimize overhead while
				// preventing thread starvation or deadlocks.
				if spin&1023 == 0 {
					if r.ctx.Err() != nil {
						return 0, r.ctx.Err()
					}
					runtime.Gosched()
				}
			}

			// 3. Barrier Dropped. Release the final byte.
			canRead = remaining
		}
	}

	// Safety check to ensure we don't overfill p
	if canRead > len(p) {
		canRead = len(p)
	}

	n = copy(p, r.data[r.offset:r.offset+canRead])
	r.offset += n
	return n, nil
}

func (r *SyncReader) Close() error {
	return nil
}

// RunH3Race executes the H3 race using Quic-Fin-Sync.
func (r *Racer) RunH3Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int) ([]models.ScanResult, error) {
	start := time.Now()

	// 1. Configuration
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 30 * time.Second
	conf.InsecureSkipVerify = true
	// Prevent NAT timeouts during hold; 2s is safe for most firewalls.
	conf.H3Config.KeepAlivePeriod = 2 * time.Second

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	r.Logger.Info("Initializing H3 clients...", zap.Int("concurrency", concurrency))

	// 2. Parallel Client Initialization
	// Critical Optimization: Initialize all QUIC connections in parallel.
	// Doing this serially for many threads causes massive setup latency.
	clients := make([]H3Client, concurrency)
	var initWg sync.WaitGroup
	var initErr error
	var initMu sync.Mutex

	initWg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer initWg.Done()
			c, err := r.Factory.NewH3Client(u, conf, r.Logger)
			if err != nil {
				initMu.Lock()
				if initErr == nil {
					initErr = err
				}
				initMu.Unlock()
				return
			}
			clients[idx] = c
		}(i)
	}
	initWg.Wait()

	// Ensure cleanup of all transports
	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	if initErr != nil {
		return nil, fmt.Errorf("h3 client initialization failed: %w", initErr)
	}

	// 3. Race Execution
	results := make([]models.ScanResult, concurrency)
	var wg sync.WaitGroup
	var readyWg sync.WaitGroup
	var startFlag int32

	wg.Add(concurrency)
	readyWg.Add(concurrency)

	r.Logger.Info("Priming H3 streams...")

	// Performance: Disable GC to prevent "stop-the-world" pauses during the burst.
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	for i := 0; i < concurrency; i++ {
		go func(idx int, client H3Client) {
			defer wg.Done()

			// Robustness: Ensure readyWg is decremented exactly once per worker,
			// regardless of success, failure, or panic.
			var signalOnce sync.Once
			signalReady := func() {
				signalOnce.Do(func() { readyWg.Done() })
			}
			defer signalReady()

			// Thread Pinning: Prevent OS scheduler from moving this goroutine
			// during the critical spin loop.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			// CRITICAL: Pad body if empty to enable synchronization.
			// SyncReader requires at least 1 byte to hold.
			bodyData := reqSpec.Body
			if len(bodyData) == 0 {
				bodyData = []byte(" ")
			}

			reader := &SyncReader{
				data:    bodyData,
				flag:    &startFlag,
				ctx:     raceCtx,
				onReady: signalReady, // SyncReader calls this when hitting the barrier
			}

			req, err := http.NewRequestWithContext(raceCtx, reqSpec.Method, reqSpec.URL, reader)
			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, 0, nil, err)
				return
			}
			req.ContentLength = int64(len(bodyData))
			req.Header.Set("User-Agent", "Scalpel-Racer/Go-H3")
			req.Header.Set("X-Scalpel-ID", fmt.Sprintf("%d", idx))
			for k, v := range reqSpec.Headers {
				req.Header.Set(k, v)
			}

			reqStart := time.Now()

			// Do() will block inside SyncReader.Read() at the last byte.
			resp, err := client.Do(raceCtx, req)

			duration := time.Since(reqStart)
			if err != nil {
				results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)

		}(i, clients[i])
	}

	// 4. Orchestration
	// Wait for all streams to reach the last byte.
	doneReady := make(chan struct{})
	go func() {
		readyWg.Wait()
		close(doneReady)
	}()

	select {
	case <-doneReady:
		// All streams primed successfully.
	case <-raceCtx.Done():
		r.Logger.Warn("Context cancelled while waiting for H3 streams", zap.Error(raceCtx.Err()))
		atomic.StoreInt32(&startFlag, 1) // Release anyone stuck
		wg.Wait()
		return nil, raceCtx.Err()
	}

	// Settle: Short sleep to ensure frames are flushed to the NIC buffer.
	time.Sleep(2 * time.Millisecond)

	r.Logger.Info("Releasing Quic-Fin-Sync burst...")
	atomic.StoreInt32(&startFlag, 1)

	wg.Wait()
	r.Logger.Info("H3 Race complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}
