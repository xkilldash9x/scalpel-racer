// FILENAME: internal/proxy/pipeline.go
package proxy

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// IngestionPipeline handles the processing, sanitization, and storage of captured requests.
// REF-003: Interceptor Decomposition
type IngestionPipeline struct {
	CaptureChan chan *models.CapturedRequest
	Logger      *zap.Logger
	mu          sync.RWMutex
	closed      bool
}

func NewIngestionPipeline(logger *zap.Logger) *IngestionPipeline {
	return &IngestionPipeline{
		CaptureChan: make(chan *models.CapturedRequest, 100),
		Logger:      logger,
	}
}

// PersistCapture processes a raw capture and sends it to the UI channel.
func (p *IngestionPipeline) PersistCapture(req *http.Request, body []byte) {
	// SECURITY: Redact sensitive query params in logs
	logURL := *req.URL
	if logURL.RawQuery != "" {
		logURL.RawQuery = "REDACTED"
	}

	p.mu.RLock()
	if p.closed {
		p.mu.RUnlock()
		return
	}
	p.mu.RUnlock()

	// Offload logic
	var offloadPath string
	if len(body) > config.BodyOffloadThreshold {
		if f, err := os.CreateTemp("", "scalpel-body-*"); err == nil {
			f.Write(body)
			f.Close()
			offloadPath = f.Name()
			body = nil // Free RAM
		}
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, "; ")
	}

	captured := &models.CapturedRequest{
		Method:      req.Method,
		URL:         req.URL.String(),
		Headers:     headers,
		Body:        body,
		Protocol:    req.Proto,
		OffloadPath: offloadPath,
	}

	// Non-blocking send
	select {
	case p.CaptureChan <- captured:
		p.Logger.Info("Captured request", zap.String("url", logURL.String()))
	default:
		p.Logger.Warn("Capture channel full, dropping request")
	}
}

func (p *IngestionPipeline) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.CaptureChan)
	}
}

// SpongeLimitWriter assists in capturing bodies without breaking io.TeeReader
type SpongeLimitWriter struct {
	W io.Writer
	N int64
}

func (l *SpongeLimitWriter) Write(p []byte) (n int, err error) {
	if l.N <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > l.N {
		n, err = l.W.Write(p[:l.N])
		l.N = 0
		if err != nil {
			return n, err
		}
		return len(p), nil
	}
	n, err = l.W.Write(p)
	l.N -= int64(n)
	return n, err
}

func LimitWriter(w io.Writer, n int64) io.Writer {
	return &SpongeLimitWriter{W: w, N: n}
}

type StartTeeReadCloser struct {
	io.Reader
	io.Closer
}

// CaptureWrap creates a TeeReader to capture the body while streaming upstream
func CaptureWrap(req *http.Request) (*bytes.Buffer, *http.Request) {
	var captureBuf bytes.Buffer
	limitWriter := LimitWriter(&captureBuf, config.MaxCaptureSize)
	proxyBody := &StartTeeReadCloser{
		Reader: io.TeeReader(req.Body, limitWriter),
		Closer: req.Body,
	}
	req.Body = proxyBody
	return &captureBuf, req
}

// PrepareProxyRequest clones and sanitizes a request for upstream forwarding
func PrepareProxyRequest(req *http.Request) *http.Request {
	proxyReq, _ := http.NewRequest(req.Method, req.URL.String(), http.NoBody)
	proxyReq.Header = req.Header.Clone()
	SanitizeHeadersRFC9113(proxyReq.Header)
	return proxyReq
}
