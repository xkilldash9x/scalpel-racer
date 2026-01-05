// FILENAME: internal/engine/interfaces.go
package engine

import (
	"context"
	"net/http"
	"net/url"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"go.uber.org/zap"
)

// H3Client defines the contract for an HTTP/3 client.
type H3Client interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
	Close() error
}

// H2Client defines the contract for an HTTP/2 Single Packet Attack client.
type H2Client interface {
	Connect(ctx context.Context) error
	PrepareRequest(ctx context.Context, req *http.Request) (*customhttp.H2StreamHandle, error)
	ReleaseBody(handle *customhttp.H2StreamHandle) error
	WaitResponse(ctx context.Context, handle *customhttp.H2StreamHandle) (*http.Response, error)
	Close() error
}

// H1Client defines the contract for an HTTP/1.1 Pipelining client.
type H1Client interface {
	Connect(ctx context.Context) error
	SendRaw(ctx context.Context, payload []byte) error
	ReadPipelinedResponses(ctx context.Context, expectedCount int) ([]*http.Response, error)
	Close() error
}

// ClientFactory defines the interface for creating protocol-specific clients.
type ClientFactory interface {
	NewH3Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H3Client, error)
	NewH2Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H2Client, error)
	NewH1Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H1Client, error)
}

// RealClientFactory implements ClientFactory using the actual customhttp package.
type RealClientFactory struct{}

func (f *RealClientFactory) NewH3Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H3Client, error) {
	return NewH3Client(u, conf, logger)
}

func (f *RealClientFactory) NewH2Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H2Client, error) {
	return customhttp.NewH2Client(u, conf, logger)
}

func (f *RealClientFactory) NewH1Client(u *url.URL, conf *customhttp.ClientConfig, logger *zap.Logger) (H1Client, error) {
	return customhttp.NewH1Client(u, conf, logger)
}
