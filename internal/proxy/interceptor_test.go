package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"
)

// TestInterceptor_GoroutineLeak ensures that the Interceptor cleans up
// all resources upon Close(). A proxy that leaks goroutines is a ticking time bomb.
func TestInterceptor_GoroutineLeak(t *testing.T) {
	// 1. Baseline
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	// 2. Upstream Setup
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// 3. Proxy Lifecycle
	logger := zap.NewNop()
	// Use port 0 for random available port
	p, err := NewInterceptor(0, logger)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Disable logging to stdout during test
	p.Logger = zap.NewNop()

	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	// 4. Activity Simulation
	// Fire off requests to force goroutine spawns
	proxyUrl := fmt.Sprintf("127.0.0.1:%d", p.Port)
	conn, err := net.DialTimeout("tcp", proxyUrl, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send a request and read response to ensure full cycle
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", ts.URL, ts.Listener.Addr().String())
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	conn.Read(buf) // wait for response
	conn.Close()

	// 5. Shutdown
	p.Close()

	// 6. Verification
	// Allow scheduler time to park and GC to sweep
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()

	// We allow a small delta for runtime internal routines, but a leak of
	// request-handling routines (1 read + 1 write per conn) would be obvious.
	delta := finalGoroutines - initialGoroutines
	if delta > 2 {
		t.Errorf("Goroutine leak detected. \nStart: %d\nEnd:   %d\nDelta: %d",
			initialGoroutines, finalGoroutines, delta)
	}
}

// TestSanitization_StrictRFC9113 validates the removal of Hop-by-Hop headers
// as defined in RFC 7230/9113, specifically ensuring that headers listed
// within the 'Connection' header are stripped.
func TestSanitization_StrictRFC9113(t *testing.T) {
	headers := http.Header{}

	// Setup standard headers
	headers.Set("Keep-Alive", "timeout=5")
	headers.Set("Transfer-Encoding", "chunked")

	// Setup custom hop-by-hop headers
	// RFC says: "The Connection header field lists other header fields that
	// are regarded as hop-by-hop"
	headers.Set("Connection", "Keep-Alive, X-Custom-Token, Upgrade")
	headers.Set("X-Custom-Token", "secret-value")
	headers.Set("Upgrade", "websocket")
	headers.Set("X-Keep-This", "safe")

	SanitizeHeadersRFC9113(headers)

	forbidden := []string{
		"Keep-Alive",
		"Transfer-Encoding",
		"X-Custom-Token",
		"Upgrade",
		"Connection", // The connection header itself should be gone or empty
	}

	for _, k := range forbidden {
		if val := headers.Get(k); val != "" {
			t.Errorf("RFC Violation: Header '%s' should be stripped, found: '%s'", k, val)
		}
	}

	if headers.Get("X-Keep-This") != "safe" {
		t.Error("Over-sanitization: 'X-Keep-This' was incorrectly removed")
	}
}

// TestInterceptor_CaptureChannelBlocking verifies that a slow consumer on the
// capture channel does not deadlock the proxy core.
func TestInterceptor_CaptureChannelBlocking(t *testing.T) {
	logger := zap.NewNop()
	p, _ := NewInterceptor(0, logger)

	// Fill the capture channel to capacity
	capSize := cap(p.CaptureChan)
	for i := 0; i < capSize; i++ {
		p.CaptureChan <- nil
	}

	// This call should NOT block even though channel is full.
	// It relies on the 'select case default:' in persistCapture
	done := make(chan bool)
	go func() {
		// Mock a request capture
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		p.persistCapture(req, []byte("data"))
		close(done)
	}()

	select {
	case <-done:
		// Success: Non-blocking write
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Deadlock: persistCapture blocked on full channel")
	}
}
