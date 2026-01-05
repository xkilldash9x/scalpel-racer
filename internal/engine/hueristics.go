// FILENAME: internal/engine/heuristics.go
package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

type LockingAnalysis struct {
	IsLocked         bool
	Confidence       float64 // 0.0 to 1.0
	SerialDuration   time.Duration
	ParallelDuration time.Duration
	TimeDelta        time.Duration
}

// ProbeSessionLocking measures the server's handling of concurrency.
// It compares the execution time of running requests serially vs. running them in a race.
func (r *Racer) ProbeSessionLocking(ctx context.Context, reqA, reqB *models.CapturedRequest) (*LockingAnalysis, error) {
	r.Logger.Info("Starting Heuristic: Session Locking Probe")

	// 1. Baseline: Serial Execution
	// We run A then B to gauge natural latency without contention.
	// We use the existing RunH2Race with concurrency=1 to get an accurate single-request benchmark.

	// Measure A
	resA, err := r.RunH2Race(ctx, reqA, 1)
	if err != nil {
		return nil, fmt.Errorf("serial probe A failed: %w", err)
	}
	tA := resA[0].Duration

	// Measure B
	resB, err := r.RunH2Race(ctx, reqB, 1)
	if err != nil {
		return nil, fmt.Errorf("serial probe B failed: %w", err)
	}
	tB := resB[0].Duration

	// Analysis: In a serial world, total time is A + B.
	// In a parallel world, "Total Time" (wall clock) is Max(A, B).
	maxSerial := tA
	if tB > tA {
		maxSerial = tB
	}
	sumSerial := tA + tB

	// 2. Variable: Parallel Execution
	// We use the Sequence Engine to hit them at the exact same moment.
	resSeq, err := r.RunSequenceRace(ctx, reqA, reqB)
	if err != nil {
		return nil, fmt.Errorf("parallel probe failed: %w", err)
	}

	// We look at the duration of the *slowest* request in the parallel pair.
	tParA := resSeq[0].Duration
	tParB := resSeq[1].Duration
	maxParallel := tParA
	if tParB > tParA {
		maxParallel = tParB
	}

	// 3. Heuristic Calculation
	// Delta = ParallelTime - IdealTime
	delta := maxParallel - maxSerial

	// Locking Factor: How close is the parallel time to the sum of serial times?
	// If Factor -> 1.0, we are perfectly serialized.
	// If Factor -> 0.0, we are perfectly parallel.
	lockingFactor := 0.0
	if sumSerial > maxSerial {
		lockingFactor = float64(delta) / float64(sumSerial-maxSerial)
	}

	// Clamp values
	if lockingFactor < 0 {
		lockingFactor = 0
	}
	if lockingFactor > 1 {
		lockingFactor = 1
	}

	// Threshold: If we are more than 70% of the way to the serial sum, assume locking.
	isLocked := lockingFactor > 0.7

	r.Logger.Info("Heuristic Complete",
		zap.Duration("serial_max", maxSerial),
		zap.Duration("serial_sum", sumSerial),
		zap.Duration("parallel_max", maxParallel),
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
