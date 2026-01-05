// FILENAME: internal/engine/h3_client.go
package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"go.uber.org/zap"
)

type h3ClientImpl struct {
	transport *http3.Transport
	client    *http.Client
	logger    *zap.Logger
}

func NewH3Client(targetURL *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H3Client, error) {
	if targetURL.Scheme != "https" {
		return nil, fmt.Errorf("H3 requires https scheme")
	}

	var tlsConfig *tls.Config
	if conf.DialerConfig != nil && conf.DialerConfig.TLSConfig != nil {
		tlsConfig = conf.DialerConfig.TLSConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.InsecureSkipVerify = conf.InsecureSkipVerify
	tlsConfig.NextProtos = []string{"h3"}

	qConf := &quic.Config{
		KeepAlivePeriod: conf.H3Config.KeepAlivePeriod,
		MaxIdleTimeout:  conf.IdleConnTimeout,
		// EnableDatagrams can be set if needed, but off by default reduces handshake overhead
		EnableDatagrams: false,
	}

	// Create a dedicated Transport for isolation
	tr := &http3.Transport{
		TLSClientConfig: tlsConfig,
		QUICConfig:      qConf,
		// Disable compression to reduce CPU overhead and ensure byte-accurate control
		DisableCompression: true,
	}

	return &h3ClientImpl{
		transport: tr,
		client: &http.Client{
			Transport: tr,
			Timeout:   0, // Timeouts handled by race context
		},
		logger: logger,
	}, nil
}

func (c *h3ClientImpl) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return c.client.Do(req)
}

func (c *h3ClientImpl) Close() error {
	c.transport.CloseIdleConnections()
	return nil
}
