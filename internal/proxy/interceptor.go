// FILENAME: internal/proxy/interceptor.go
package proxy

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
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
	// Set to true for capturing traffic from targets with self-signed certs.
	InsecureSkipVerify bool
	// CertDir allows overriding the default certificate storage location (~/.scalpel-racer/certs).
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
	ca             tls.Certificate
	caParsed       *x509.Certificate
	serverKey      *ecdsa.PrivateKey
	listener       net.Listener
	udpConn        *net.UDPConn
	quicServer     *http3.Server
	UpstreamClient *http.Client

	certCache    map[string]*tls.Certificate
	certCacheMu  sync.RWMutex
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

	// Resolve certificate directory (Config override > Safe Default)
	var certDir string
	var err error
	if cfg.CertDir != "" {
		certDir = cfg.CertDir
	} else {
		certDir, err = resolveSafeCertDir(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve safe cert directory: %w", err)
		}
	}

	// Ensure the directory exists with strict 0700 permissions
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create cert dir: %w", err)
	}

	certPath := filepath.Join(certDir, "ca.pem")
	keyPath := filepath.Join(certDir, "ca.key")

	logger.Info("Loading CA identity", zap.String("path", certDir))

	ca, err := LoadOrCreateCA(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	caParsed, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate a shared key for leaf certificates to avoid expensive key gen per request
	serverKey, err := GenerateSharedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
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
		ca:          ca,
		caParsed:    caParsed,
		serverKey:   serverKey,
		certCache:   make(map[string]*tls.Certificate),
		stopChan:    make(chan struct{}),
		UpstreamClient: &http.Client{
			Transport:     transport,
			Timeout:       30 * time.Second, // General timeout cap
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// resolveSafeCertDir resolves the directory with strict validation to prevent
// path traversal or arbitrary file overwrite attacks when using defaults.
func resolveSafeCertDir(logger *zap.Logger) (string, error) {
	// 1. Determine the effective home directory
	var homeDir string

	// Prefer the user attempting to run sudo, but ONLY if we are actually root.
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" && os.Geteuid() == 0 {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			homeDir = u.HomeDir
			logger.Debug("Using SUDO_USER home for cert storage", zap.String("user", sudoUser))
		}
	}

	if homeDir == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		homeDir = h
	}

	// 2. Hardcode the subdirectory. Do NOT allow env var overrides for the base path
	// when running as root/sudo, as this allows attackers to target /etc or /bin.
	targetDir := filepath.Join(homeDir, ".scalpel-racer", "certs")

	// 3. Clean the path to resolve any ".."
	return filepath.Clean(targetDir), nil
}

func (i *Interceptor) Start() error {
	var err error
	i.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", i.Port))
	if err != nil {
		return fmt.Errorf("failed to start TCP proxy: %w", err)
	}
	// Update port if 0 was passed
	i.Port = i.listener.Addr().(*net.TCPAddr).Port

	i.quicServer = &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{i.ca},
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

	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return
	}

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)

	// Reset deadline strictly
	_ = clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		return
	}

	// Use BufferedConn to allow reading the already-buffered bytes from bufio
	proxyConn := NewBufferedConn(clientConn, br)

	if req.Method == http.MethodConnect {
		i.handleHTTPS(proxyConn, req)
	} else {
		i.handleHTTP(proxyConn, req)
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

	i.certCacheMu.RLock()
	leaf, hit := i.certCache[host]
	i.certCacheMu.RUnlock()

	if !hit {
		leaf, err = GenerateLeafCert(i.ca, i.caParsed, i.serverKey, host)
		if err != nil {
			i.Logger.Error("cert gen fail", zap.Error(err))
			return
		}
		i.certCacheMu.Lock()
		if len(i.certCache) > 1000 {
			i.certCache = make(map[string]*tls.Certificate)
		}
		i.certCache[host] = leaf
		i.certCacheMu.Unlock()
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*leaf}}
	tlsConn := tls.Server(clientConn, tlsConfig)

	if err := tlsConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	defer tlsConn.Close()

	tlsReader := bufio.NewReader(tlsConn)
	secureReq, err := http.ReadRequest(tlsReader)
	if err != nil {
		return
	}

	secureReq.URL.Scheme = "https"
	secureReq.URL.Host = req.URL.Host
	i.captureAndForwardRaw(tlsConn, secureReq)
}

func (i *Interceptor) handleHTTP(clientConn net.Conn, req *http.Request) {
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	i.captureAndForwardRaw(clientConn, req)
}

type startTeeReadCloser struct {
	io.Reader
	io.Closer
}

func (i *Interceptor) captureAndForwardRaw(clientConn net.Conn, req *http.Request) {
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
		// Use fmt.Fprintf carefully, ignoring errors as client might be gone
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()

	SanitizeHeadersRFC9113(resp.Header)

	if err := resp.Write(clientConn); err != nil {
		i.Logger.Debug("response write fail", zap.Error(err))
	}
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
		URL:      req.URL.String(), // Full URL kept for internal capture logic
		Headers:  headers,
		Body:     body,
		Protocol: req.Proto,
	}

	select {
	case i.CaptureChan <- captured:
	case <-i.stopChan:
		// Do not write if we are stopping
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

// limitWriter is a writer that writes to w but stops with an ErrShortWrite after n bytes.
type limitWriter struct {
	W io.Writer // underlying writer
	N int64     // max bytes remaining
}

func (l *limitWriter) Write(p []byte) (n int, err error) {
	if l.N <= 0 {
		return 0, io.ErrShortWrite
	}
	if int64(len(p)) > l.N {
		p = p[0:l.N]
		err = io.ErrShortWrite
	}
	n, writeErr := l.W.Write(p)
	if writeErr != nil {
		err = writeErr
	}
	l.N -= int64(n)
	return
}

func LimitWriter(w io.Writer, n int64) io.Writer {
	return &limitWriter{W: w, N: n}
}
