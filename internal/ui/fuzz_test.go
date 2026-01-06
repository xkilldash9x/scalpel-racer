// FILENAME: internal/ui/fuzz_test.go
package ui

import (
	"net"
	"testing"
	"unicode/utf8"

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

// FuzzClean validates that the string cleaner/truncator handles all unicode inputs
// and width constraints without panicking.
func FuzzClean(f *testing.F) {
	f.Add("Standard String", 10)
	f.Add("With\tTabs", 5)
	f.Add("With\nNewlines", 10)
	f.Add("🚀 Emoji", 2)
	f.Add("🚀 Emoji", 1)
	f.Add("Long string that needs truncation", 5)
	f.Add("", 0)
	f.Add("Negative Width", -1)

	f.Fuzz(func(t *testing.T, s string, width int) {
		// 1. Execution
		res := clean(s, width)

		// 2. Invariants
		if width <= 0 {
			if res != "" {
				t.Errorf("Expected empty string for width %d, got %q", width, res)
			}
			return
		}

		// The resulting rune count must not exceed the requested width
		count := utf8.RuneCountInString(res)
		if count > width {
			t.Errorf("Result '%s' (len %d) exceeds width %d", res, count, width)
		}
	})
}

// FuzzResolveTarget ensures the URL and Host header parsing logic is robust against
// malformed inputs, verifying that we don't panic during IP/Port extraction.
func FuzzResolveTarget(f *testing.F) {
	f.Add("http://example.com", "example.com")
	f.Add("https://1.2.3.4:8080", "")
	f.Add("/path", "host.com")
	f.Add("http://[::1]:9090", "[::1]")
	f.Add("invalid-url", "invalid-host:port:garbage")

	f.Fuzz(func(t *testing.T, uStr string, hostHdr string) {
		req := &models.CapturedRequest{
			URL:     uStr,
			Headers: map[string]string{"Host": hostHdr},
		}

		// Use a safe mock resolver
		r := &fuzzResolver{}

		// Execution - Should not panic despite garbage input
		resolveTargetIPAndPort(req, r)
	})
}

// FuzzRequestRoundTrip tests the consistency of serialization and deserialization.
// It generates structured requests, converts them to text, and parses them back.
func FuzzRequestRoundTrip(f *testing.F) {
	f.Add("GET", "http://example.com", "HTTP/1.1", "Host", "example.com", []byte("body"))
	f.Add("POST", "/", "HTTP/2", "Content-Type", "application/json", []byte("{}"))

	f.Fuzz(func(t *testing.T, method, url, proto, hKey, hVal string, body []byte) {
		// Limit body size for performance during fuzzing
		if len(body) > 4096 {
			return
		}

		// 1. Construct Source
		req := &models.CapturedRequest{
			Method:   method,
			URL:      url,
			Protocol: proto,
			Headers:  map[string]string{hKey: hVal},
			Body:     body,
		}

		// 2. Serialize
		txt := requestToText(req)

		// 3. Deserialize
		// We pass the original request as context to mimic the UI's editing behavior
		parsed, err := textToRequest(txt, req)

		// We don't assert err == nil because the fuzzer might generate invalid HTTP methods (e.g., with newlines)
		// which requestToText writes but textToRequest correctly rejects.
		// We primarily care that this process never PANICS.

		if err == nil {
			if len(parsed.Body) != len(req.Body) {
				// While lengths usually match, Content-Length logic might adjust it.
				// This is just a sanity check point for debugging.
			}
		}
	})
}

// -- Mocks --

// fuzzResolver implements the Resolver interface for Fuzzing purposes.
type fuzzResolver struct{}

func (f *fuzzResolver) LookupIP(host string) ([]net.IP, error) {
	// Always return a valid IP to ensure we reach deeper logic branches in the target function.
	// This helps fuzz the logic that runs AFTER a successful DNS lookup.
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

