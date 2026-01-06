// FILENAME: internal/proxy/interceptor.go
package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

const (
	MaxCaptureSize = 10 * 1024 * 1024 // 10MB Limit
)

// InterceptorConfig holds configuration for the proxy interceptor.
type InterceptorConfig struct {
	// Port is the TCP/UDP port to listen on.
	Port int
	// InsecureSkipVerify controls whether the proxy validates upstream TLS certificates.
	InsecureSkipVerify bool
	// CertDir allows overriding the default certificate storage location.
	CertDir string
	// MaxIdleConns controls the connection pool size for upstream requests. Defaults to 100.
	MaxIdleConns int
	// IdleConnTimeout controls how long idle connections are kept alive. Defaults to 90s.
	IdleConnTimeout time.Duration
}

type Interceptor struct {
	Port           int
	CaptureChan    chan *models.CapturedRequest
	Logger         *zap.Logger
	certManager    *CertManager
	listener       net.Listener
	udpConn        *net.UDPConn
	quicServer     *http3.Server
	UpstreamClient *http.Client

	mu           sync.RWMutex
	closed       bool
	shutdownOnce sync.Once
	// used to signal background routines to stop
	stopChan chan struct{}
}

func NewInterceptor(cfg InterceptorConfig, logger *zap.Logger) (*Interceptor, error) {
	// Set defaults for optional config fields
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 100
	}
	if cfg.IdleConnTimeout == 0 {
		cfg.IdleConnTimeout = 90 * time.Second
	}

	cm, err := NewCertManager(cfg.CertDir, logger)
	if err != nil {
		return nil, err
	}

	// Robust Transport Configuration
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          cfg.MaxIdleConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			// Allow re-negotiation if absolutely necessary, though risky
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}

	return &Interceptor{
		Port:        cfg.Port,
		CaptureChan: make(chan *models.CapturedRequest, 100),
		Logger:      logger,
		certManager: cm,
		stopChan:    make(chan struct{}),
		UpstreamClient: &http.Client{
			Transport:     transport,
			Timeout:       30 * time.Second, // General timeout cap
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (i *Interceptor) Start() error {
	var err error
	i.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", i.Port))
	if err != nil {
		return fmt.Errorf("failed to start TCP proxy: %w", err)
	}
	// Update port if 0 was passed
	i.Port = i.listener.Addr().(*net.TCPAddr).Port

	// RESTORED: QUIC/HTTP3 Server Setup
	i.quicServer = &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{i.certManager.GetCA()},
			NextProtos:   []string{"h3"},
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.URL.Scheme = "https"
			if r.URL.Host == "" {
				r.URL.Host = r.Host
			}
			i.CaptureAndForwardStandard(w, r)
		}),
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 10 * time.Second,
		},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", i.Port))
	if err != nil {
		i.Logger.Error("failed to resolve UDP address", zap.Error(err))
	} else {
		i.udpConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			i.Logger.Error("failed to listen on UDP", zap.Error(err))
		} else {
			const targetBuffer = 2 * 1024 * 1024
			_ = i.udpConn.SetReadBuffer(targetBuffer)
			go i.serveQUIC()
		}
	}

	i.Logger.Info("Proxy listening (TCP/UDP)", zap.Int("port", i.Port))

	go func() {
		for {
			conn, err := i.listener.Accept()
			if err != nil {
				// Check if we are shutting down
				select {
				case <-i.stopChan:
					return
				default:
				}
				i.Logger.Error("Accept error", zap.Error(err))
				return
			}
			go i.handleConnection(conn)
		}
	}()

	return nil
}

func (i *Interceptor) serveQUIC() {
	if i.udpConn == nil {
		return
	}
	if err := i.quicServer.Serve(i.udpConn); err != nil {
		select {
		case <-i.stopChan:
			// Expected error during shutdown
			return
		default:
			i.Logger.Debug("QUIC server stopped", zap.Error(err))
		}
	}
}

func (i *Interceptor) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Wrap in a buffered conn to peek at headers/protocol
	br := bufio.NewReader(clientConn)
	proxyConn := NewBufferedConn(clientConn, br)

	// Keep-Alive Loop for standard HTTP
	for {
		// Set idle timeout for reading the request line
		if err := clientConn.SetReadDeadline(time.Now().Add(i.UpstreamClient.Transport.(*http.Transport).IdleConnTimeout)); err != nil {
			return
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			// Normal connection close or timeout (keep-alive idle)
			return
		}

		// Reset deadline strictly for request processing
		_ = clientConn.SetReadDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			i.handleHTTPS(proxyConn, req)
			// HTTPS tunnel takes over the connection, we are done
			return
		}

		// Handle HTTP
		keepAlive := i.handleHTTP(proxyConn, req)
		if !keepAlive {
			return
		}
	}
}

func (i *Interceptor) handleHTTPS(clientConn net.Conn, req *http.Request) {
	host := req.URL.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	leaf, err := i.certManager.GetOrCreate(host)
	if err != nil {
		i.Logger.Error("cert gen fail", zap.Error(err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"}, // Enforce HTTP/1.1
	}
	tlsConn := tls.Server(clientConn, tlsConfig)

	if err := tlsConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	tlsReader := bufio.NewReader(tlsConn)

	for {
		// Idle timeout for keep-alive inside tunnel
		if err := tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return
		}

		secureReq, err := http.ReadRequest(tlsReader)
		if err != nil {
			return
		}

		_ = tlsConn.SetReadDeadline(time.Time{})

		secureReq.URL.Scheme = "https"
		secureReq.URL.Host = req.URL.Host

		keepAlive := i.captureAndForwardRaw(tlsConn, secureReq)
		if !keepAlive {
			return
		}
	}
}

func (i *Interceptor) handleHTTP(clientConn net.Conn, req *http.Request) bool {
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	return i.captureAndForwardRaw(clientConn, req)
}

type startTeeReadCloser struct {
	io.Reader
	io.Closer
}

// captureAndForwardRaw returns true if the connection should be kept alive
func (i *Interceptor) captureAndForwardRaw(clientConn net.Conn, req *http.Request) bool {
	// Handle Expect: 100-continue (Deadlock fix)
	if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		_, err := fmt.Fprintf(clientConn, "HTTP/1.1 100 Continue\r\n\r\n")
		if err != nil {
			return false
		}
		req.Header.Del("Expect")
	}

	var captureBuf bytes.Buffer
	// Use SpongeLimitWriter to prevent aborting large requests
	limitWriter := LimitWriter(&captureBuf, MaxCaptureSize)

	proxyBody := &startTeeReadCloser{
		Reader: io.TeeReader(req.Body, limitWriter),
		Closer: req.Body,
	}

	proxyReq := i.prepareProxyRequest(req)
	proxyReq.Body = proxyBody
	proxyReq.ContentLength = req.ContentLength

	resp, err := i.UpstreamClient.Do(proxyReq)

	i.persistCapture(req, captureBuf.Bytes())

	if err != nil {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return false
	}
	defer resp.Body.Close()

	SanitizeHeadersRFC9113(resp.Header)

	if err := resp.Write(clientConn); err != nil {
		i.Logger.Debug("response write fail", zap.Error(err))
		return false
	}

	return !resp.Close && !req.Close
}

func (i *Interceptor) CaptureAndForwardStandard(w http.ResponseWriter, req *http.Request) {
	var captureBuf bytes.Buffer
	limitWriter := LimitWriter(&captureBuf, MaxCaptureSize)

	proxyBody := &startTeeReadCloser{
		Reader: io.TeeReader(req.Body, limitWriter),
		Closer: req.Body,
	}

	proxyReq := i.prepareProxyRequest(req)
	proxyReq.Body = proxyBody
	proxyReq.ContentLength = req.ContentLength

	resp, err := i.UpstreamClient.Do(proxyReq)

	i.persistCapture(req, captureBuf.Bytes())

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	SanitizeHeadersRFC9113(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (i *Interceptor) persistCapture(req *http.Request, body []byte) {
	// SECURITY FIX: Sanitize URL query parameters before logging
	// We clone the URL to avoid modifying the original request reference
	logURL := *req.URL
	if logURL.RawQuery != "" {
		logURL.RawQuery = "REDACTED"
	}

	// Lock-free check first for performance
	select {
	case <-i.stopChan:
		return
	default:
	}

	headers := make(map[string]string)
	for k, v := range req.Header {
		headers[k] = strings.Join(v, "; ")
	}

	captured := &models.CapturedRequest{
		Method:   req.Method,
		URL:      req.URL.String(),
		Headers:  headers,
		Body:     body,
		Protocol: req.Proto,
	}

	select {
	case i.CaptureChan <- captured:
	case <-i.stopChan:
		return
	default:
		i.Logger.Warn("capture channel full, dropping request")
	}

	i.Logger.Info("Captured", zap.String("url", logURL.String()))
}

func (i *Interceptor) prepareProxyRequest(req *http.Request) *http.Request {
	proxyReq, _ := http.NewRequest(req.Method, req.URL.String(), http.NoBody)
	proxyReq.Header = req.Header.Clone()
	SanitizeHeadersRFC9113(proxyReq.Header)
	return proxyReq
}

func (i *Interceptor) Close() {
	i.shutdownOnce.Do(func() {
		close(i.stopChan) // Signal all goroutines to stop

		i.mu.Lock()
		i.closed = true
		i.mu.Unlock()

		if i.listener != nil {
			i.listener.Close()
		}
		// FIX: Explicitly close the UDP connection to prevent resource leaks
		if i.udpConn != nil {
			i.udpConn.Close()
		}
		if i.quicServer != nil {
			i.quicServer.Close()
		}
		if i.UpstreamClient != nil {
			i.UpstreamClient.CloseIdleConnections()
		}
	})
}

// -----------------------------------------------------------------------------
// Utilities & Helper Functions
// -----------------------------------------------------------------------------

// SpongeLimitWriter writes to W until N bytes are written.
// After N bytes, it silently discards data but returns success.
// This prevents io.TeeReader from failing when the capture buffer is full.
type SpongeLimitWriter struct {
	W io.Writer
	N int64
}

func NewSpongeLimitWriter(w io.Writer, n int64) *SpongeLimitWriter {
	return &SpongeLimitWriter{W: w, N: n}
}

func (l *SpongeLimitWriter) Write(p []byte) (n int, err error) {
	if l.N <= 0 {
		return len(p), nil
	}

	if int64(len(p)) > l.N {
		// Partial write to buffer
		n, err = l.W.Write(p[:l.N])
		l.N = 0
		if err != nil {
			return n, err
		}
		// Return len(p) so caller thinks we consumed it all
		return len(p), nil
	}

	n, err = l.W.Write(p)
	l.N -= int64(n)
	return n, err
}

func LimitWriter(w io.Writer, n int64) io.Writer {
	return NewSpongeLimitWriter(w, n)
}
