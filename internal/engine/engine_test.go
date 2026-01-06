// FILENAME: internal/engine/engine_test.go
package engine_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// -- Mocks --

type MockClientFactory struct {
	H1 *MockH1Client
	H2 *MockH2Client
	H3 *MockH3Client
}

func (f *MockClientFactory) NewH1Client(u *url.URL, conf *customhttp.ClientConfig, l *zap.Logger) (engine.H1Client, error) {
	if f.H1 != nil {
		return f.H1, nil
	}
	return nil, errors.New("mock h1 factory fail")
}

func (f *MockClientFactory) NewH2Client(u *url.URL, conf *customhttp.ClientConfig, l *zap.Logger) (engine.H2Client, error) {
	if f.H2 != nil {
		return f.H2, nil
	}
	return nil, errors.New("mock h2 factory fail")
}

func (f *MockClientFactory) NewH3Client(u *url.URL, conf *customhttp.ClientConfig, l *zap.Logger) (engine.H3Client, error) {
	if f.H3 != nil {
		return f.H3, nil
	}
	return nil, errors.New("mock h3 factory fail")
}

type MockH1Client struct {
	mu                 sync.Mutex
	SentData           [][]byte
	ConnectError       error
	SendError          error
	ResponseStatusCode int
	ResponseBody       []byte
	ResponseError      error
}

func (m *MockH1Client) Connect(ctx context.Context) error { return m.ConnectError }
func (m *MockH1Client) Close() error                      { return nil }
func (m *MockH1Client) SendRaw(ctx context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SentData = append(m.SentData, data)
	return m.SendError
}
func (m *MockH1Client) ReadPipelinedResponses(ctx context.Context, n int) ([]*http.Response, error) {
	if m.ResponseError != nil {
		return nil, m.ResponseError
	}
	res := make([]*http.Response, n)
	for i := 0; i < n; i++ {
		res[i] = &http.Response{
			StatusCode: m.ResponseStatusCode,
			Body:       io.NopCloser(bytes.NewReader(m.ResponseBody)),
		}
	}
	return res, nil
}

type MockH2Client struct {
	ConnectError       error
	PreparedHandle     *customhttp.H2StreamHandle
	PrepareError       error
	ReleaseError       error
	ResponseStatusCode int
	ResponseBody       []byte
	WaitError          error
}

func (m *MockH2Client) Connect(ctx context.Context) error { return m.ConnectError }
func (m *MockH2Client) Close() error                      { return nil }
func (m *MockH2Client) PrepareRequest(ctx context.Context, req *http.Request) (*customhttp.H2StreamHandle, error) {
	if m.PrepareError == nil && m.PreparedHandle == nil {
		return &customhttp.H2StreamHandle{}, nil
	}
	return m.PreparedHandle, m.PrepareError
}
func (m *MockH2Client) ReleaseBody(handle *customhttp.H2StreamHandle) error { return m.ReleaseError }
func (m *MockH2Client) WaitResponse(ctx context.Context, h *customhttp.H2StreamHandle) (*http.Response, error) {
	if m.WaitError != nil {
		return nil, m.WaitError
	}
	return &http.Response{
		StatusCode: m.ResponseStatusCode,
		Body:       io.NopCloser(bytes.NewReader(m.ResponseBody)),
	}, nil
}

type MockH3Client struct {
	DoError            error
	ResponseStatusCode int
	ResponseBody       []byte
}

func (m *MockH3Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if m.DoError != nil {
		return nil, m.DoError
	}
	return &http.Response{
		StatusCode: m.ResponseStatusCode,
		Body:       io.NopCloser(bytes.NewReader(m.ResponseBody)),
	}, nil
}

func (m *MockH3Client) Close() error { return nil }

func drainResults(ch <-chan models.ScanResult) []models.ScanResult {
	var results []models.ScanResult
	for r := range ch {
		results = append(results, r)
	}
	return results
}

// -- Tests --

func TestH1Race_Flow(t *testing.T) {
	mockH1 := &MockH1Client{ResponseStatusCode: 200, ResponseBody: []byte("OK")}
	racer := engine.NewRacer(&MockClientFactory{H1: mockH1}, zap.NewNop())
	req := &models.CapturedRequest{URL: "http://e.com", Body: []byte("A{{SYNC}}B")}

	concurrency := 1
	resultsCh := make(chan models.ScanResult, concurrency)

	// RunH1Race closes resultsCh upon completion/return, so we should NOT close it here again
	err := racer.RunH1Race(context.Background(), req, concurrency, resultsCh)
	if err != nil {
		t.Fatalf("Race failed: %v", err)
	}

	results := drainResults(resultsCh)

	if len(results) != 1 {
		t.Error("Expected 1 result")
	}
}

// TestH1Race_SystematicErrorPaths validates all error branches in H1 engine.
func TestH1Race_SystematicErrorPaths(t *testing.T) {
	logger := zap.NewNop()

	t.Run("InvalidURL", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{}, logger)
		// Control character in URL
		err := r.RunH1Race(context.Background(), &models.CapturedRequest{URL: "http://e.com\x7f"}, 1, make(chan models.ScanResult, 1))
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})

	t.Run("PlanFailure", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{}, logger)
		req := &models.CapturedRequest{
			URL:     "http://e.com",
			Headers: map[string]string{"Content-Length": "invalid"}, // Breaks serialization
		}
		err := r.RunH1Race(context.Background(), req, 1, make(chan models.ScanResult, 1))
		if err == nil {
			t.Error("Expected planning error due to bad headers")
		}
	})

	t.Run("ClientInitFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H1: nil}, logger)
		resultsCh := make(chan models.ScanResult, 1)
		// RunH1Race closes resultsCh
		_ = r.RunH1Race(context.Background(), &models.CapturedRequest{URL: "http://e.com"}, 1, resultsCh)
		res := drainResults(resultsCh)
		if len(res) > 0 && res[0].Error == nil {
			t.Error("Expected factory error propagation")
		}
	})

	t.Run("ConnectFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H1: &MockH1Client{ConnectError: errors.New("net fail")}}, logger)
		resultsCh := make(chan models.ScanResult, 1)
		// RunH1Race closes resultsCh
		_ = r.RunH1Race(context.Background(), &models.CapturedRequest{URL: "http://e.com"}, 1, resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected connect error")
		}
	})

	t.Run("SendFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H1: &MockH1Client{SendError: errors.New("broken pipe")}}, logger)
		resultsCh := make(chan models.ScanResult, 1)
		// RunH1Race closes resultsCh
		_ = r.RunH1Race(context.Background(), &models.CapturedRequest{URL: "http://e.com"}, 1, resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected send error")
		}
	})

	t.Run("ReadFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H1: &MockH1Client{ResponseError: errors.New("timeout")}}, logger)
		resultsCh := make(chan models.ScanResult, 1)
		// RunH1Race closes resultsCh
		_ = r.RunH1Race(context.Background(), &models.CapturedRequest{URL: "http://e.com"}, 1, resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected read error")
		}
	})
}

func TestH2Race_Flow(t *testing.T) {
	mockH2 := &MockH2Client{
		PreparedHandle:     &customhttp.H2StreamHandle{},
		ResponseStatusCode: 202,
	}
	racer := engine.NewRacer(&MockClientFactory{H2: mockH2}, zap.NewNop())
	req := &models.CapturedRequest{URL: "https://e.com", Body: []byte("test")}

	concurrency := 5
	resultsCh := make(chan models.ScanResult, concurrency)

	// Note: engine implementation for H2 likely handles closing too, but checking H1 specifically for now based on logs.
	// If H2 follows same pattern, we assume correct behavior or fix if needed.
	// Based on H1 fix, we should likely trust the engine to close or check H2 implementation.
	// Provided logs only showed panic in TestH1Race_Flow.
	err := racer.RunH2Race(context.Background(), req, concurrency, resultsCh)
	if err != nil {
		t.Fatalf("H2 race failed: %v", err)
	}
	// Warning: If RunH2Race also defers close, this is a bug.
	// Assuming symmetry with H1, we should remove this close as well to be safe,
	// though the log didn't explicitly trigger here yet.
	// However, looking at the code provided for H1, it closes. I don't have H2 code but safer to assume symmetry.
	// I will comment it out to be consistent with the fix pattern.
	// close(resultsCh)

	results := drainResults(resultsCh)
	if len(results) != 5 {
		t.Errorf("Expected 5 results, got %d", len(results))
	}
}

func TestH2Race_SystematicErrors(t *testing.T) {
	logger := zap.NewNop()
	req := &models.CapturedRequest{URL: "https://e.com"}

	t.Run("InvalidURL", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{}, logger)
		err := r.RunH2Race(context.Background(), &models.CapturedRequest{URL: "::invalid"}, 1, make(chan models.ScanResult, 1))
		if err == nil {
			t.Error("Expected error for invalid URL")
		}
	})

	t.Run("ClientInitFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H2: nil}, logger)
		err := r.RunH2Race(context.Background(), req, 1, make(chan models.ScanResult, 1))
		if err == nil {
			t.Error("Expected client init error")
		}
	})

	t.Run("ConnectFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H2: &MockH2Client{ConnectError: errors.New("fail")}}, logger)
		err := r.RunH2Race(context.Background(), req, 1, make(chan models.ScanResult, 1))
		if err == nil {
			t.Error("Expected global connect error")
		}
	})

	t.Run("PrepareFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H2: &MockH2Client{PrepareError: errors.New("fail")}}, logger)
		resultsCh := make(chan models.ScanResult, 1)
		_ = r.RunH2Race(context.Background(), req, 1, resultsCh)
		// Removed close(resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected prepare error")
		}
	})

	t.Run("ReleaseFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H2: &MockH2Client{
			PreparedHandle: &customhttp.H2StreamHandle{},
			ReleaseError:   errors.New("fail"),
		}}, logger)

		resultsCh := make(chan models.ScanResult, 1)
		_ = r.RunH2Race(context.Background(), req, 1, resultsCh)
		// Removed close(resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected release error")
		}
	})

	t.Run("WaitFail", func(t *testing.T) {
		r := engine.NewRacer(&MockClientFactory{H2: &MockH2Client{
			PreparedHandle: &customhttp.H2StreamHandle{},
			WaitError:      errors.New("timeout"),
		}}, logger)

		resultsCh := make(chan models.ScanResult, 1)
		_ = r.RunH2Race(context.Background(), req, 1, resultsCh)
		// Removed close(resultsCh)
		res := drainResults(resultsCh)
		if res[0].Error == nil {
			t.Error("Expected wait response error")
		}
	})
}
