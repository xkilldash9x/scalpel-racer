package engine_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// VulnerableServer simulates a race condition target.
// It detects if multiple requests arrive within a tight time window (5ms).
func NewVulnerableServer() (*httptest.Server, *int32) {
	var raceHits int32
	var lastArrival int64
	var mu sync.Mutex

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now().UnixNano()

		mu.Lock()
		if lastArrival != 0 {
			diff := time.Duration(now - lastArrival)
			if diff < 5*time.Millisecond {
				atomic.AddInt32(&raceHits, 1)
			}
		}
		lastArrival = now
		mu.Unlock()

		// Simulate Gap
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(200)
	}))
	return ts, &raceHits
}

func TestE2E_SynchronizationPrecision(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping E2E in short mode")
	}

	ts, raceHits := NewVulnerableServer()
	defer ts.Close()

	// Using implicit Last-Byte Sync
	req := &models.CapturedRequest{
		Method: "POST",
		URL:    ts.URL,
		Body:   []byte("race_payload"),
	}

	concurrency := 10
	logger := zap.NewNop()
	// Use RealClientFactory to test actual customhttp implementation integration
	racer := engine.NewRacer(&engine.RealClientFactory{}, logger)

	// Execute Real Network Race (no mocks)
	results, err := racer.RunH1Race(context.Background(), req, concurrency)
	if err != nil {
		t.Fatalf("Race failed: %v", err)
	}

	// Verify Success
	success := 0
	for _, r := range results {
		if r.StatusCode == 200 {
			success++
		}
	}
	if success != concurrency {
		t.Errorf("Expected %d successes, got %d", concurrency, success)
	}

	// Verify Timing
	hits := atomic.LoadInt32(raceHits)
	t.Logf("Precision Hits (<5ms gap): %d", hits)

	if hits == 0 {
		t.Log("Warning: Loose synchronization detected (no <5ms gaps).")
	}
}
