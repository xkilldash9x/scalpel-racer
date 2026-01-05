package benchmarks

import (
	"context"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// BenchmarkPlanning measures the overhead of the split calculation logic.
func BenchmarkPlanning(b *testing.B) {
	body := []byte("Part1{{SYNC}}Part2{{SYNC}}Part3")
	req := &models.CapturedRequest{
		Method: "POST",
		URL:    "http://bench.com",
		Body:   body,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.PlanH1Attack(req)
	}
}

// BenchmarkRaceOrchestration measures the Engine overhead using real factory instantiation.
func BenchmarkRaceOrchestrator(b *testing.B) {
	// Using RealClientFactory with invalid URL to measure init overhead
	racer := engine.NewRacer(&engine.RealClientFactory{}, zap.NewNop())
	req := &models.CapturedRequest{URL: "http://127.0.0.1:0", Body: []byte("A")}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		racer.RunH1Race(context.Background(), req, 1)
	}
}
