package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/proxy"
	"go.uber.org/zap"
)

func TestCertGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "test_ca.pem")
	keyFile := filepath.Join(tmpDir, "test_ca.key")

	// First, create the CA
	ca, err := proxy.LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Then, load it
	loadedCa, err := proxy.LoadOrCreateCA(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load CA: %v", err)
	}

	if !bytes.Equal(ca.Certificate[0], loadedCa.Certificate[0]) {
		t.Error("Loaded certificate does not match created certificate")
	}

	serverKey, err := proxy.GenerateSharedKey()
	if err != nil {
		t.Fatalf("Failed to generate shared key: %v", err)
	}
	leaf, err := proxy.GenerateLeafCert(ca, ca.Leaf, serverKey, "example.com")
	if err != nil {
		t.Fatalf("Failed to generate leaf: %v", err)
	}
	if len(leaf.Certificate) == 0 {
		t.Error("Leaf certificate empty")
	}

	t.Run("Corrupted CA file", func(t *testing.T) {
		tmpDirCorrupted := t.TempDir()
		certFileCorrupted := filepath.Join(tmpDirCorrupted, "test_ca.pem")
		keyFileCorrupted := filepath.Join(tmpDirCorrupted, "test_ca.key")
		// create dummy files
		err := os.WriteFile(certFileCorrupted, []byte("corrupted"), 0644)
		if err != nil {
			t.Fatalf("Failed to write corrupted cert file: %v", err)
		}
		err = os.WriteFile(keyFileCorrupted, []byte("corrupted"), 0600)
		if err != nil {
			t.Fatalf("Failed to write corrupted key file: %v", err)
		}

		_, err = proxy.LoadOrCreateCA(certFileCorrupted, keyFileCorrupted)
		if err == nil {
			t.Fatal("Expected error when loading corrupted CA, but got nil")
		}
	})
}

func TestInterceptor_Integration(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Target", "Hit")
		w.WriteHeader(200)
		w.Write([]byte("TargetReached"))
	}))
	defer target.Close()

	logger := zap.NewNop()
	p, err := proxy.NewInterceptor(0, logger)
	if err != nil {
		t.Fatalf("Failed to create interceptor: %v", err)
	}
	if err := p.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer p.Close()

	proxyUrl, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.Port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	t.Run("Plain HTTP", func(t *testing.T) {
		req, _ := http.NewRequest("POST", target.URL+"/test", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if body, _ := io.ReadAll(resp.Body); string(body) != "TargetReached" {
			t.Error("Body mismatch")
		}
	})

	t.Run("HTTPS Connect", func(t *testing.T) {
		secureTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("SecureData"))
		}))
		defer secureTarget.Close()

		req, _ := http.NewRequest("GET", secureTarget.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Secure request failed: %v", err)
		}
		defer resp.Body.Close()

		if body, _ := io.ReadAll(resp.Body); string(body) != "SecureData" {
			t.Error("Secure body mismatch")
		}
	})
}

// TestInterceptor_Stability verifies the proxy handles "chaos" without crashing.
func TestInterceptor_Stability(t *testing.T) {
	logger := zap.NewNop()
	p, _ := proxy.NewInterceptor(0, logger)
	p.Start()
	defer p.Close()

	address := fmt.Sprintf("127.0.0.1:%d", p.Port)

	t.Run("Junk Connection", func(t *testing.T) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("\xDE\xAD\xBE\xEF\x00\x01\x02"))
		// Expectation: Proxy closes connection, no panic.
		// We read until EOF to ensure server closed it.
		io.ReadAll(conn)
	})

	t.Run("Invalid HTTP Request", func(t *testing.T) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
		io.ReadAll(conn)
	})

	t.Run("Junk After HTTPS Connect", func(t *testing.T) {
		secureTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("SecureData"))
		}))
		defer secureTarget.Close()

		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		req, _ := http.NewRequest("CONNECT", secureTarget.URL, nil)
		req.Write(conn)

		// Read the "200 Connection established" response
		br := bufio.NewReader(conn)
		br.ReadString('\n')

		// Send junk instead of a valid TLS handshake
		conn.Write([]byte("this is not a valid tls handshake"))
		io.ReadAll(conn)
	})

	t.Run("Client Disconnect During Body", func(t *testing.T) {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n")
		conn.Write([]byte("StartOfBody"))
		conn.Close() // Abrupt close
		// Expectation: Logs an error, but does not hang routine
	})
}

// FIX: Moved to standalone test to avoid race condition on p.Transport
func TestInterceptor_UpstreamFailure(t *testing.T) {
	logger := zap.NewNop()
	p, _ := proxy.NewInterceptor(0, logger)

	// Inject Transport BEFORE starting the proxy
	p.UpstreamClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("connection refused simulation")
		},
	}

	p.Start()
	defer p.Close()

	proxyUrl, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", p.Port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyUrl)},
	}

	resp, err := client.Get("http://will-fail.com")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("Expected 502, got %d", resp.StatusCode)
		}
	}
}

func TestSanitizeHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "upgrade, keep-alive")
	h.Set("Upgrade", "websocket")
	proxy.SanitizeHeadersRFC9113(h)
	if h.Get("Upgrade") != "" {
		t.Error("Failed to strip Upgrade header")
	}
}

func TestSanitizeHeadersForLog(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer 12345",
		"Cookie":        "secret-cookie",
		"X-Test":        "test-value",
	}

	proxy.SanitizeHeadersForLog(headers)

	if headers["Authorization"] != "[REDACTED]" {
		t.Error("Authorization header not redacted")
	}
	if headers["Cookie"] != "[REDACTED]" {
		t.Error("Cookie header not redacted")
	}
	if headers["X-Test"] != "test-value" {
		t.Error("Non-sensitive header was redacted")
	}
}

func TestLimitWriter(t *testing.T) {
	t.Run("Successful write", func(t *testing.T) {
		var buf bytes.Buffer
		lw := proxy.LimitWriter(&buf, 5)

		n, err := lw.Write([]byte("hello"))
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != 5 {
			t.Errorf("Write returned wrong number of bytes: got %d, want %d", n, 5)
		}

		n, err = lw.Write([]byte(" world"))
		if err != io.ErrShortWrite {
			t.Errorf("Write did not return ErrShortWrite: got %v", err)
		}
		if n != 0 {
			t.Errorf("Write returned non-zero bytes on short write: got %d", n)
		}
	})

	t.Run("Write with error", func(t *testing.T) {
		errWriter := &errorWriter{err: errors.New("write error")}
		lw := proxy.LimitWriter(errWriter, 5)

		_, err := lw.Write([]byte("hello"))
		if err == nil {
			t.Fatal("Write did not return an error")
		}
	})
}

// errorWriter is a writer that always returns an error
type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}

// Test coverage for captureAndForwardStandard
func TestInterceptor_captureAndForwardStandard(t *testing.T) {
	logger := zap.NewNop()
	p, _ := proxy.NewInterceptor(0, logger)

	t.Run("Successful forward", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Target", "Hit")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("TargetReached"))
		}))
		defer target.Close()

		p.UpstreamClient.Transport = http.DefaultTransport

		req := httptest.NewRequest("GET", target.URL, nil)
		rr := httptest.NewRecorder()

		p.CaptureAndForwardStandard(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rr.Code)
		}
		if rr.Header().Get("X-Target") != "Hit" {
			t.Error("Header mismatch")
		}
		if rr.Body.String() != "TargetReached" {
			t.Error("Body mismatch")
		}
	})

	t.Run("Upstream failure", func(t *testing.T) {
		p.UpstreamClient.Transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return nil, errors.New("connection refused simulation")
			},
		}

		req := httptest.NewRequest("GET", "http://will-fail.com", nil)
		rr := httptest.NewRecorder()

		p.CaptureAndForwardStandard(rr, req)

		if rr.Code != http.StatusBadGateway {
			t.Errorf("Expected 502, got %d", rr.Code)
		}
	})
}
