// FILENAME: internal/proxy/tcp_listener.go
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// TcpListener handles HTTP/1.1, HTTP/2 (h2c/TLS), and HTTPS Connect tunnels.
type TcpListener struct {
	Port           int
	Listener       net.Listener
	Pipeline       *IngestionPipeline
	CertManager    *CertManager
	UpstreamClient *http.Client
	Logger         *zap.Logger
}

func NewTcpListener(port int, pipeline *IngestionPipeline, cm *CertManager, client *http.Client, logger *zap.Logger) *TcpListener {
	return &TcpListener{
		Port:           port,
		Pipeline:       pipeline,
		CertManager:    cm,
		UpstreamClient: client,
		Logger:         logger,
	}
}

func (t *TcpListener) Start() error {
	var err error
	t.Listener, err = net.Listen("tcp", fmt.Sprintf(":%d", t.Port))
	if err != nil {
		return err
	}
	t.Port = t.Listener.Addr().(*net.TCPAddr).Port // Update actual port

	go t.acceptLoop()
	return nil
}

func (t *TcpListener) acceptLoop() {
	for {
		conn, err := t.Listener.Accept()
		if err != nil {
			// Assume closed
			return
		}
		go t.handleConnection(conn)
	}
}

func (t *TcpListener) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	br := bufio.NewReader(clientConn)
	proxyConn := NewBufferedConn(clientConn, br)

	for {
		if err := clientConn.SetReadDeadline(time.Now().Add(t.UpstreamClient.Transport.(*http.Transport).IdleConnTimeout)); err != nil {
			return
		}

		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}

		_ = clientConn.SetReadDeadline(time.Time{})

		if req.Method == http.MethodConnect {
			t.handleHTTPS(proxyConn, req)
			return
		}

		if !t.handleHTTP(proxyConn, req) {
			return
		}
	}
}

func (t *TcpListener) handleHTTPS(clientConn net.Conn, req *http.Request) {
	host := req.URL.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	leaf, err := t.CertManager.GetOrCreate(host)
	if err != nil {
		t.Logger.Error("Cert gen failed", zap.Error(err))
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"http/1.1"},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)

	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	tlsReader := bufio.NewReader(tlsConn)

	for {
		_ = tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		secureReq, err := http.ReadRequest(tlsReader)
		if err != nil {
			return
		}
		_ = tlsConn.SetReadDeadline(time.Time{})

		secureReq.URL.Scheme = "https"
		secureReq.URL.Host = req.URL.Host

		if !t.forwardRequest(tlsConn, secureReq) {
			return
		}
	}
}

func (t *TcpListener) handleHTTP(clientConn net.Conn, req *http.Request) bool {
	req.URL.Scheme = "http"
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	return t.forwardRequest(clientConn, req)
}

func (t *TcpListener) forwardRequest(clientConn net.Conn, req *http.Request) bool {
	if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 100 Continue\r\n\r\n")
		req.Header.Del("Expect")
	}

	captureBuf, proxyReq := CaptureWrap(req)
	proxyReq.ContentLength = req.ContentLength // Restore length
	proxyReq2 := PrepareProxyRequest(proxyReq)
	proxyReq2.Body = proxyReq.Body // Link TeeReader

	resp, err := t.UpstreamClient.Do(proxyReq2)

	t.Pipeline.PersistCapture(req, captureBuf.Bytes())

	if err != nil {
		_, _ = fmt.Fprintf(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return false
	}
	defer resp.Body.Close()

	SanitizeHeadersRFC9113(resp.Header)
	if err := resp.Write(clientConn); err != nil {
		return false
	}
	return !resp.Close && !req.Close
}

func (t *TcpListener) Close() {
	if t.Listener != nil {
		t.Listener.Close()
	}
}
