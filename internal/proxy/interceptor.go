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
	IdleTimeout    = 60 * time.Second
)

type Interceptor struct {
	Port           int
	CaptureChan    chan *models.CapturedRequest
	Logger         *zap.Logger
	ca             tls.Certificate
	caParsed       *x509.Certificate
	serverKey      *ecdsa.PrivateKey // Shared key optimization
	listener       net.Listener
	udpConn        *net.UDPConn
	quicServer     *http3.Server
	UpstreamClient *http.Client

	certCache    map[string]*tls.Certificate
	certCacheMu  sync.RWMutex
	mu           sync.RWMutex
	closed       bool
	shutdownOnce sync.Once
}

func NewInterceptor(port int, logger *zap.Logger) (*Interceptor, error) {
	// FIX: Establish a stable, absolute path for identity files.
	// This prevents "directory drift" where certs are scattered across the repo.
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to determine user home: %w", err)
	}

	certDir := filepath.Join(home, ".scalpel-racer", "certs")
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

	// Performance optimization: Parse CA once
	caParsed, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate shared key once at startup to avoid DoS during high concurrency
	serverKey, err := GenerateSharedKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate shared key: %w", err)
	}

	// Configure robust transport for high-concurrency reuse
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyFromEnvironment,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	return &Interceptor{
		Port:        port,
		CaptureChan: make(chan *models.CapturedRequest, 100),
		Logger:      logger,
		ca:          ca,
		caParsed:    caParsed,
		serverKey:   serverKey,
		certCache:   make(map[string]*tls.Certificate),
		UpstreamClient: &http.Client{
			Transport:     transport,
			Timeout:       10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (i *Interceptor) Start() error {
	var err error
	// 1. TCP Listener
	i.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", i.Port))
	if err != nil {
		return fmt.Errorf("failed to start TCP proxy: %w", err)
	}
	i.Port = i.listener.Addr().(*net.TCPAddr).Port

	// 2. Initialize QUIC Server
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

	// 3. UDP Listener (QUIC)
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", i.Port))
	if err != nil {
		i.Logger.Error("failed to resolve UDP address", zap.Error(err))
	} else {
		i.udpConn, err = net.ListenUDP("udp", udpAddr)
		if err != nil {
			i.Logger.Error("failed to listen on UDP", zap.Error(err))
		} else {
			// Tuning for High Throughput
			const targetBuffer = 2 * 1024 * 1024
			_ = i.udpConn.SetReadBuffer(targetBuffer)
			go i.serveQUIC()
		}
	}

	i.Logger.Info("Proxy listening (TCP/UDP)", zap.Int("port", i.Port))

	// 4. Accept Loop
	go func() {
		for {
			conn, err := i.listener.Accept()
			if err != nil {
				i.mu.RLock()
				isClosed := i.closed
				i.mu.RUnlock()
				if isClosed || strings.Contains(err.Error(), "closed") {
					return
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
	// Serve blocks until closed
	if err := i.quicServer.Serve(i.udpConn); err != nil {
		if !strings.Contains(err.Error(), "closed") {
			i.Logger.Debug("QUIC server stopped", zap.Error(err))
		}
	}
}

func (i *Interceptor) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Hardening: Read Deadline for initial sniff
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)

	clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		return
	}

	// BUG FIX: Use BufferedConn to prevent data loss of bytes already in 'br'
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

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Check cache first
	i.certCacheMu.RLock()
	leaf, hit := i.certCache[host]
	i.certCacheMu.RUnlock()

	if !hit {
		var err error
		// Optimized cert generation
		leaf, err = GenerateLeafCert(i.ca, i.caParsed, i.serverKey, host)
		if err != nil {
			i.Logger.Error("cert gen fail", zap.Error(err))
			return
		}
		// Cache the generated certificate
		i.certCacheMu.Lock()
		// Simple eviction to prevent memory leaks
		if len(i.certCache) > 1000 {
			i.certCache = make(map[string]*tls.Certificate)
		}
		i.certCache[host] = leaf
		i.certCacheMu.Unlock()
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*leaf}}

	// CRITICAL FIX: Use proxyConn (BufferedConn) to handle handshake bytes already peeked.
	// clientConn here is the BufferedConn wrapper passed from handleConnection.
	tlsConn := tls.Server(clientConn, tlsConfig)

	// Enforce handshake deadline
	clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	clientConn.SetDeadline(time.Time{}) // Reset
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

// startTeeReadCloser is a helper to tee the body read while keeping it closeable
type startTeeReadCloser struct {
	io.Reader
	io.Closer
}

func (i *Interceptor) captureAndForwardRaw(clientConn net.Conn, req *http.Request) {
	var captureBuf bytes.Buffer
	// TeeReader allows streaming while capturing prefix to avoid OOM
	limitWriter := LimitWriter(&captureBuf, MaxCaptureSize)

	proxyBody := &startTeeReadCloser{
		Reader: io.TeeReader(req.Body, limitWriter),
		Closer: req.Body,
	}

	proxyReq := i.prepareProxyRequest(req)
	proxyReq.Body = proxyBody
	proxyReq.ContentLength = req.ContentLength

	resp, err := i.UpstreamClient.Do(proxyReq)

	// Persist after reading headers to ensure we captured what was sent
	i.persistCapture(req, captureBuf.Bytes())

	if err != nil {
		fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer resp.Body.Close()

	SanitizeHeadersRFC9113(resp.Header)

	// BUG FIX: Use resp.Write instead of DumpResponse to stream output and avoid OOM.
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
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.closed {
		return
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
	default:
		i.Logger.Warn("capture channel full, dropping request")
	}

	logHeaders := make(map[string]string)
	for k, v := range headers {
		logHeaders[k] = v
	}
	SanitizeHeadersForLog(logHeaders)
	i.Logger.Info("Captured", zap.String("url", req.URL.String()))
}

func (i *Interceptor) prepareProxyRequest(req *http.Request) *http.Request {
	// Create new request with NoBody initially, body is assigned by caller
	proxyReq, _ := http.NewRequest(req.Method, req.URL.String(), http.NoBody)
	proxyReq.Header = req.Header.Clone()
	SanitizeHeadersRFC9113(proxyReq.Header)
	return proxyReq
}

func (i *Interceptor) Close() {
	i.shutdownOnce.Do(func() {
		i.mu.Lock()
		i.closed = true
		i.mu.Unlock()

		if i.listener != nil {
			i.listener.Close()
		}
		if i.quicServer != nil {
			i.quicServer.Close()
		}
		// Explicit close of udpConn causes double-close panic with quic-go/http3
		// allowing http3 server close to handle it.

		if i.UpstreamClient != nil {
			i.UpstreamClient.CloseIdleConnections()
		}
		// NOTE: We do NOT close i.CaptureChan here.
		// Doing so causes a panic if a pending goroutine tries to write to it.
		// We let the GC handle the channel once all references are gone.
	})
}

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

// LimitWriter returns a Writer that writes to w but stops with an ErrShortWrite after n bytes.
func LimitWriter(w io.Writer, n int64) io.Writer {
	return &limitWriter{W: w, N: n}
}
