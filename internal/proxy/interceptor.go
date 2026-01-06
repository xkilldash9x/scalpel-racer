// FILENAME: internal/proxy/interceptor.go
package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

type InterceptorConfig struct {
	Port               int
	InsecureSkipVerify bool
	CertDir            string
}

// Interceptor is a Facade that manages the TCP and QUIC listeners and the ingestion pipeline.
type Interceptor struct {
	Pipeline *IngestionPipeline
	Tcp      *TcpListener
	Quic     *QuicListener
	Client   *http.Client
	Logger   *zap.Logger

	stopOnce sync.Once
}

func NewInterceptor(cfg InterceptorConfig, logger *zap.Logger) (*Interceptor, error) {
	cm, err := NewCertManager(cfg.CertDir, logger)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   config.ProxyTimeout,
		KeepAlive: config.ProxyKeepAlive,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          config.MaxIdleConns,
		IdleConnTimeout:       config.IdleConnTimeout,
		TLSHandshakeTimeout:   config.ProxyHandshakeTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
	}

	client := &http.Client{
		Transport:     transport,
		Timeout:       config.ProxyTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}

	pipeline := NewIngestionPipeline(logger)
	tcp := NewTcpListener(cfg.Port, pipeline, cm, client, logger)
	// Note: Quic listener needs same port, but TCP listener must bind first to determine ephemeral port if 0
	quic := NewQuicListener(cfg.Port, pipeline, cm, client, logger)

	return &Interceptor{
		Pipeline: pipeline,
		Tcp:      tcp,
		Quic:     quic,
		Client:   client,
		Logger:   logger,
	}, nil
}

func (i *Interceptor) Start() error {
	if err := i.Tcp.Start(); err != nil {
		return err
	}
	i.Logger.Info("TCP Proxy started", zap.Int("port", i.Tcp.Port))

	// Sync port for QUIC
	i.Quic.Port = i.Tcp.Port
	if err := i.Quic.Start(); err != nil {
		i.Logger.Warn("QUIC Proxy failed to start", zap.Error(err))
	} else {
		i.Logger.Info("QUIC Proxy started", zap.Int("port", i.Quic.Port))
	}

	return nil
}

// CaptureChan exposes the channel for the UI to consume
func (i *Interceptor) CaptureChan() <-chan *models.CapturedRequest {
	return i.Pipeline.CaptureChan
}

func (i *Interceptor) Close() {
	i.stopOnce.Do(func() {
		i.Tcp.Close()
		i.Quic.Close()
		i.Pipeline.Close()
		i.Client.CloseIdleConnections()
	})
}

// CaptureAndForwardStandard allows using the interceptor logic with standard HTTP handlers (used in tests)
func (i *Interceptor) CaptureAndForwardStandard(w http.ResponseWriter, req *http.Request) {
	captureBuf, proxyReq := CaptureWrap(req)
	proxyReq.ContentLength = req.ContentLength
	proxyReq2 := PrepareProxyRequest(proxyReq)

	// Use the shared client
	resp, err := i.Client.Do(proxyReq2)

	i.Pipeline.PersistCapture(req, captureBuf.Bytes())

	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
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
