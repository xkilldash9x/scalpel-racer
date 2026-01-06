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
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/sync/barrier"
	"go.uber.org/zap"
)

// SyncReader implements the "Quic-Fin-Sync" technique using SpinBarrier.
type SyncReader struct {
	data   []byte
	offset int
	gate   *barrier.SpinBarrier
	ctx    context.Context
}

func (r *SyncReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}

	remaining := len(r.data) - r.offset
	canRead := remaining

	// Barrier Logic: Hold before the final byte
	if r.offset == 0 || remaining > 1 {
		// Pass through everything except the last byte
		if remaining > 1 {
			canRead = remaining - 1
		}
		// If only 1 byte total, fall through to barrier immediately
	}

	// Check if we are at the critical last byte
	if remaining == 1 {
		// Spin until release
		if err := r.gate.Await(r.ctx); err != nil {
			return 0, err
		}
		canRead = remaining
	}

	if canRead > len(p) {
		canRead = len(p)
	}

	n = copy(p, r.data[r.offset:r.offset+canRead])
	r.offset += n
	return n, nil
}

func (r *SyncReader) Close() error { return nil }

// RunH3Race executes the H3 race using Quic-Fin-Sync and SpinBarrier.
func (r *Racer) RunH3Race(ctx context.Context, reqSpec *models.CapturedRequest, concurrency int, results chan<- models.ScanResult) error {
	defer close(results)
	start := time.Now()

	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = config.H3RequestTimeout
	conf.InsecureSkipVerify = true
	conf.H3Config.KeepAlivePeriod = 2 * time.Second

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	u, err := url.Parse(reqSpec.URL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Parallel Client Init
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

	defer func() {
		for _, c := range clients {
			if c != nil {
				c.Close()
			}
		}
	}()

	if initErr != nil {
		return initErr
	}

	// Race Execution
	gate := barrier.NewSpinBarrier(concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	for i := 0; i < concurrency; i++ {
		go func(idx int, client H3Client) {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			bodyData := reqSpec.Body
			if len(bodyData) == 0 {
				bodyData = []byte(" ")
			}

			reader := &SyncReader{
				data: bodyData,
				gate: gate,
				ctx:  raceCtx,
			}

			req, err := http.NewRequestWithContext(raceCtx, reqSpec.Method, reqSpec.URL, reader)
			if err != nil {
				results <- models.NewScanResult(idx, 0, 0, nil, err)
				return
			}
			req.ContentLength = int64(len(bodyData))

			if h, ok := reqSpec.Headers["Host"]; ok {
				req.Host = h
			}
			req.Header.Set("User-Agent", "Scalpel-Racer/Go-H3")
			req.Header.Set("X-Scalpel-ID", fmt.Sprintf("%d", idx))
			for k, v := range reqSpec.Headers {
				req.Header.Set(k, v)
			}

			reqStart := time.Now()
			resp, err := client.Do(raceCtx, req) // Blocks in SyncReader

			duration := time.Since(reqStart)
			if err != nil {
				results <- models.NewScanResult(idx, 0, duration, nil, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, config.MaxCaptureSize))
			results <- models.NewScanResult(idx, resp.StatusCode, duration, bodyBytes, nil)
		}(i, clients[i])
	}

	if err := gate.WaitReady(raceCtx); err != nil {
		return err
	}
	time.Sleep(2 * time.Millisecond)

	r.Logger.Info("Releasing H3 burst...")
	gate.Release()
	wg.Wait()

	r.Logger.Info("H3 Race complete", zap.Duration("total_duration", time.Since(start)))
	return nil
}
