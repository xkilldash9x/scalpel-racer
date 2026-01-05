package engine_test

import (
	"bytes"
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// FuzzPlanH1Attack verifies the splitter invariants using Go native fuzzing.
// It exercises the synchronization marker logic without requiring a network stack.
func FuzzPlanH1Attack(f *testing.F) {
	// Seed Corpus
	f.Add([]byte("StandardBody"), "POST")
	f.Add([]byte("Part1{{SYNC}}Part2"), "POST")
	f.Add([]byte("{{SYNC}}Start"), "PUT")
	f.Add([]byte("End{{SYNC}}"), "POST")

	f.Fuzz(func(t *testing.T, body []byte, method string) {
		req := &models.CapturedRequest{
			Method: method,
			URL:    "http://localhost",
			Body:   body,
			Headers: map[string]string{
				"Host": "localhost",
			},
		}

		plan, err := engine.PlanH1Attack(req)
		if err != nil {
			return // Expected errors on malformed serialization are OK
		}

		if len(plan.WireStages) == 0 {
			t.Error("Plan returned empty stages")
		}

		totalLen := 0
		for _, s := range plan.WireStages {
			totalLen += len(s)
		}

		// Content check: Ensure we didn't drop the payload
		marker := []byte("{{SYNC}}")
		cleanBody := bytes.ReplaceAll(body, marker, []byte{})

		// Note: WireStages include headers in stage 0.
		// So totalLen must be >= len(cleanBody)
		if totalLen < len(cleanBody) {
			t.Errorf("Data loss detected: Wire (%d) < CleanBody (%d)", totalLen, len(cleanBody))
		}
	})
}
