// FILENAME: internal/ui/fuzz_test.go
package ui

import (
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// FuzzTextToRequest verifies that the manual text parser handles malformed input gracefully.
func FuzzTextToRequest(f *testing.F) {
	// 1. Seed Corpus
	f.Add("GET http://example.com HTTP/1.1\nHost: example.com\n\nBody")
	f.Add("POST / HTTP/2\nContent-Length: 5\n\n12345")
	f.Add("INVALID_LINE")
	f.Add("\n\n\n")

	f.Fuzz(func(t *testing.T, text string) {
		// Mock original request for host fallback logic
		original := &models.CapturedRequest{
			Headers: map[string]string{"Host": "fallback.com"},
		}

		// Execution
		_, err := textToRequest(text, original)

		// We accept errors (invalid input is expected), but we DO NOT accept panics.
		if err != nil {
			return
		}
	})
}
