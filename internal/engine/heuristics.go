// FILENAME: internal/engine/heuristics.go
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

type LockingAnalysis struct {
	IsLocked         bool
	Confidence       float64
	SerialDuration   time.Duration
	ParallelDuration time.Duration
	TimeDelta        time.Duration
}

// ProbeSessionLocking measures the server's handling of concurrency.
func (r *Racer) ProbeSessionLocking(ctx context.Context, reqA, reqB *models.CapturedRequest) (*LockingAnalysis, error) {
	r.Logger.Info("Starting Heuristic: Session Locking Probe")

	// Helper to run a single request synchronously
	runSingle := func(req *models.CapturedRequest) (time.Duration, error) {
		ch := make(chan models.ScanResult, 2)
		var err error
		var wg sync.WaitGroup
		wg.Add(1)

		go func() {
			defer wg.Done()
			err = r.RunH2Race(ctx, req, 1, ch)
		}()

		var dur time.Duration
		for res := range ch {
			if res.Error == nil {
				dur = res.Duration
			}
		}
		wg.Wait()
		return dur, err
	}

	// 1. Baseline: Serial Execution
	tA, err := runSingle(reqA)
	if err != nil {
		return nil, fmt.Errorf("serial probe A failed: %w", err)
	}

	tB, err := runSingle(reqB)
	if err != nil {
		return nil, fmt.Errorf("serial probe B failed: %w", err)
	}

	maxSerial := tA
	if tB > tA {
		maxSerial = tB
	}
	sumSerial := tA + tB

	// 2. Variable: Parallel Execution
	ch := make(chan models.ScanResult, 2)
	go func() {
		_ = r.RunH2Race(ctx, reqA, 2, ch)
	}()

	var maxParallel time.Duration
	for res := range ch {
		if res.Duration > maxParallel {
			maxParallel = res.Duration
		}
	}

	// 3. Heuristic Calculation
	delta := maxParallel - maxSerial
	lockingFactor := 0.0
	if sumSerial > maxSerial {
		lockingFactor = float64(delta) / float64(sumSerial-maxSerial)
	}

	isLocked := lockingFactor > 0.7

	r.Logger.Info("Heuristic Complete",
		zap.Float64("locking_factor", lockingFactor),
		zap.Bool("locked", isLocked),
	)

	return &LockingAnalysis{
		IsLocked:         isLocked,
		Confidence:       lockingFactor,
		SerialDuration:   maxSerial,
		ParallelDuration: maxParallel,
		TimeDelta:        delta,
	}, nil
}
