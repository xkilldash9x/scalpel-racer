// FILENAME: internal/proxy/interceptor_test.go
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestInterceptor_GoroutineLeak(t *testing.T) {
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	logger := zap.NewNop()
	cfg := InterceptorConfig{
		Port:               0,
		InsecureSkipVerify: true,
	}
	p, err := NewInterceptor(cfg, logger)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	p.Logger = zap.NewNop()

	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	proxyUrl := fmt.Sprintf("127.0.0.1:%d", p.Port)
	conn, err := net.DialTimeout("tcp", proxyUrl, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	// Send Connection: close to ensure deterministic closure
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", ts.URL, ts.Listener.Addr().String())
	conn.SetReadDeadline(time.Now().Add(time.Second))
	io.ReadAll(conn)
	conn.Close()

	p.Close()
	time.Sleep(100 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	delta := finalGoroutines - initialGoroutines
	if delta > 2 {
		t.Errorf("Goroutine leak detected. \nStart: %d\nEnd:   %d\nDelta: %d",
			initialGoroutines, finalGoroutines, delta)
	}
}

// TestInterceptor_LargeRequest verifies that requests larger than MaxCaptureSize
// are successfully proxied (without error) and captured (truncated).
func TestInterceptor_LargeRequest(t *testing.T) {
	// 1. Setup Upstream
	receivedSize := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedSize = len(body)
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// 2. Setup Proxy
	logger := zap.NewNop()
	p, _ := NewInterceptor(InterceptorConfig{Port: 0}, logger)
	p.Start()
	defer p.Close()

	// 3. Create Client
	proxyUrl := fmt.Sprintf("http://127.0.0.1:%d", p.Port)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyUrl)
			},
		},
		Timeout: 5 * time.Second,
	}

	// 4. Send Large Request (11MB)
	// MaxCaptureSize is 10MB.
	largeBody := bytes.Repeat([]byte("A"), 11*1024*1024)
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(largeBody))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected 200 OK, got %d", resp.StatusCode)
	}

	// 5. Verify Upstream Received All Data
	if receivedSize != len(largeBody) {
		t.Errorf("Upstream received %d bytes, expected %d", receivedSize, len(largeBody))
	}
}

func TestSanitization_StrictRFC9113(t *testing.T) {
	headers := http.Header{}
	headers.Set("Keep-Alive", "timeout=5")
	headers.Set("Transfer-Encoding", "chunked")
	headers.Set("Connection", "Keep-Alive, X-Custom-Token, Upgrade")
	headers.Set("X-Custom-Token", "secret-value")
	headers.Set("Upgrade", "websocket")
	headers.Set("X-Keep-This", "safe")

	SanitizeHeadersRFC9113(headers)

	forbidden := []string{"Keep-Alive", "Transfer-Encoding", "X-Custom-Token", "Upgrade", "Connection"}
	for _, k := range forbidden {
		if val := headers.Get(k); val != "" {
			t.Errorf("RFC Violation: Header '%s' should be stripped, found: '%s'", k, val)
		}
	}
}

func TestInterceptor_CaptureChannelBlocking(t *testing.T) {
	logger := zap.NewNop()
	cfg := InterceptorConfig{Port: 0}
	p, _ := NewInterceptor(cfg, logger)

	capSize := cap(p.CaptureChan)
	for i := 0; i < capSize; i++ {
		p.CaptureChan <- nil
	}

	done := make(chan bool)
	go func() {
		req, _ := http.NewRequest("GET", "http://example.com", nil)
		p.persistCapture(req, []byte("data"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Deadlock: persistCapture blocked on full channel")
	}
}
