// FILENAME: internal/engine/fuzz_test.go
package engine_test

import (
	"testing"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/ui"
)

func FuzzRequestParsing(f *testing.F) {
	f.Add("GET / HTTP/1.1\nHost: example.com\n\n")
	f.Fuzz(func(t *testing.T, data string) {
		req := &models.CapturedRequest{Headers: map[string]string{}}
		// Use exported helpers
		_, _ = ui.TextToRequest(data, req)
	})
}
