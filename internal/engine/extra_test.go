// FILENAME: internal/engine/extra_test.go
package engine_test

import (
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/ui"
	"go.uber.org/zap"
)

func TestModelFiltering(t *testing.T) {
	m := ui.NewModel(zap.NewNop(), &engine.Racer{})
	// Correctly access sub-model
	m.Results.Filter = ui.FilterOutliers
	if m.Results.Filter != ui.FilterOutliers {
		t.Error("Filter not set")
	}
}
