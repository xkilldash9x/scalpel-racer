// FILENAME: internal/engine/e2e_test.go
package engine_test

import (
	"context"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

func TestE2E_Workflow(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&engine.RealClientFactory{}, logger)
	req := &models.CapturedRequest{URL: "http://localhost"}

	ch := make(chan models.ScanResult, 5)
	go racer.RunH1Race(context.Background(), req, 5, ch)

	count := 0
	for range ch {
		count++
	}
	// Test passes if it compiles and runs without panic
}
