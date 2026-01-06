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

// RunSequenceRace targets Multi-Endpoint logic with strict sync.
func (r *Racer) RunSequenceRace(ctx context.Context, reqA, reqB *models.CapturedRequest) ([]models.ScanResult, error) {
	start := time.Now()

	// 1. Config
	conf := customhttp.NewBrowserClientConfig()
	conf.RequestTimeout = 15 * time.Second
	conf.InsecureSkipVerify = true
	conf.H2Config.PingInterval = 0

	raceCtx, cancel := context.WithTimeout(ctx, conf.RequestTimeout+2*time.Second)
	defer cancel()

	// 2. Setup
	r.Logger.Info("Priming sequence streams...")

	var clientA, clientB H2Client
	var handleA, handleB *customhttp.H2StreamHandle
	var errA, errB error

	var setupWg sync.WaitGroup
	setupWg.Add(2)

	setupWorker := func(req *models.CapturedRequest, label string, cOut *H2Client, hOut **customhttp.H2StreamHandle, eOut *error) {
		defer setupWg.Done()
		c, err := r.initClient(raceCtx, req, conf)
		if err != nil {
			*eOut = err
			return
		}
		*cOut = c
		httpReq, err := r.buildRequest(raceCtx, req, label)
		if err == nil {
			*hOut, *eOut = c.PrepareRequest(raceCtx, httpReq)
		} else {
			*eOut = err
		}
	}

	go setupWorker(reqA, "A", &clientA, &handleA, &errA)
	go setupWorker(reqB, "B", &clientB, &handleB, &errB)

	setupWg.Wait()

	if clientA != nil {
		defer clientA.Close()
	}
	if clientB != nil {
		defer clientB.Close()
	}

	if errA != nil {
		return nil, fmt.Errorf("sequence A setup failed: %w", errA)
	}
	if errB != nil {
		return nil, fmt.Errorf("sequence B setup failed: %w", errB)
	}

	// 3. Barrier
	var wg sync.WaitGroup
	var readyWg sync.WaitGroup
	var startFlag int32
	results := make([]models.ScanResult, 2)

	runWorker := func(idx int, client H2Client, handle *customhttp.H2StreamHandle) {
		defer wg.Done()
		readyWg.Done()

		// Strict OS Thread Lock
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Spin Barrier
		spin := 0
		for atomic.LoadInt32(&startFlag) == 0 {
			spin++
			if spin&2047 == 0 {
				if raceCtx.Err() != nil {
					return
				}
			}
		}

		reqStart := time.Now()

		if err := client.ReleaseBody(handle); err != nil {
			results[idx] = models.NewScanResult(idx, 0, time.Since(reqStart), nil, err)
			return
		}

		resp, err := client.WaitResponse(raceCtx, handle)
		duration := time.Since(reqStart)

		if err != nil {
			results[idx] = models.NewScanResult(idx, 0, duration, nil, err)
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		results[idx] = models.NewScanResult(idx, resp.StatusCode, duration, body, nil)
	}

	wg.Add(2)
	readyWg.Add(2)

	// 4. Engage
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	go runWorker(0, clientA, handleA)
	go runWorker(1, clientB, handleB)

	readyWg.Wait()
	time.Sleep(1 * time.Millisecond)

	r.Logger.Info("Releasing sequence...")
	atomic.StoreInt32(&startFlag, 1)

	wg.Wait()
	r.Logger.Info("Sequence complete", zap.Duration("total_duration", time.Since(start)))
	return results, nil
}

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
		client.Close()
		return nil, err
	}
	return client, nil
}

func (r *Racer) buildRequest(ctx context.Context, reqSpec *models.CapturedRequest, label string) (*http.Request, error) {
	method := reqSpec.Method
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, reqSpec.URL, bytes.NewReader(reqSpec.Body))
	if err != nil {
		return nil, err
	}

	// Explicitly set Host from spec if present to handle IP-based URLs correctly
	if h, ok := reqSpec.Headers["Host"]; ok {
		req.Host = h
	}

	req.Header.Set("User-Agent", "Scalpel-Racer/Sequence")
	req.Header.Set("X-Scalpel-Seq", label)
	for k, v := range reqSpec.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}
