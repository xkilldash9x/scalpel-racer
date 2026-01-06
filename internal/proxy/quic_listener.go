// FILENAME: internal/proxy/quic_listener.go
package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"go.uber.org/zap"
)

type QuicListener struct {
	Port           int
	Pipeline       *IngestionPipeline
	CertManager    *CertManager
	UpstreamClient *http.Client
	Logger         *zap.Logger
	Server         *http3.Server
	UDPConn        *net.UDPConn
}

func NewQuicListener(port int, pipeline *IngestionPipeline, cm *CertManager, client *http.Client, logger *zap.Logger) *QuicListener {
	return &QuicListener{
		Port:           port,
		Pipeline:       pipeline,
		CertManager:    cm,
		UpstreamClient: client,
		Logger:         logger,
	}
}

func (q *QuicListener) Start() error {
	q.Server = &http3.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{q.CertManager.GetCA()},
			NextProtos:   []string{"h3"},
		},
		Handler: http.HandlerFunc(q.handle),
		QUICConfig: &quic.Config{
			KeepAlivePeriod: 10 * time.Second,
		},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", q.Port))
	if err != nil {
		return err
	}

	q.UDPConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// High buffer for QUIC
	_ = q.UDPConn.SetReadBuffer(2 * 1024 * 1024)

	go func() {
		if err := q.Server.Serve(q.UDPConn); err != nil {
			q.Logger.Debug("QUIC serve stopped", zap.Error(err))
		}
	}()

	return nil
}

func (q *QuicListener) handle(w http.ResponseWriter, r *http.Request) {
	r.URL.Scheme = "https"
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}

	captureBuf, proxyReq := CaptureWrap(r)
	proxyReq2 := PrepareProxyRequest(proxyReq)
	proxyReq2.Body = proxyReq.Body

	resp, err := q.UpstreamClient.Do(proxyReq2)

	q.Pipeline.PersistCapture(r, captureBuf.Bytes())

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

func (q *QuicListener) Close() {
	if q.UDPConn != nil {
		q.UDPConn.Close()
	}
	if q.Server != nil {
		q.Server.Close()
	}
}
