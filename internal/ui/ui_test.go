// FILENAME: internal/ui/ui_test.go
package ui

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-cli/pkg/customhttp"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

// -- Mocks --

type MockFactory struct{}

func (f *MockFactory) NewH1Client(u *url.URL, c *customhttp.ClientConfig, l *zap.Logger) (engine.H1Client, error) {
	return nil, nil
}
func (f *MockFactory) NewH2Client(u *url.URL, c *customhttp.ClientConfig, l *zap.Logger) (engine.H2Client, error) {
	return &MockH2{}, nil
}
func (f *MockFactory) NewH3Client(u *url.URL, c *customhttp.ClientConfig, l *zap.Logger) (engine.H3Client, error) {
	return nil, nil
}

type MockH2 struct{}

func (m *MockH2) Connect(ctx context.Context) error { return nil }
func (m *MockH2) PrepareRequest(ctx context.Context, req *http.Request) (*customhttp.H2StreamHandle, error) {
	return &customhttp.H2StreamHandle{}, nil
}
func (m *MockH2) ReleaseBody(handle *customhttp.H2StreamHandle) error { return nil }
func (m *MockH2) WaitResponse(ctx context.Context, h *customhttp.H2StreamHandle) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}
func (m *MockH2) Close() error { return nil }

// -- Helpers --

func update(m Model, msg tea.Msg) (Model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(Model), cmd
}

// -- Tests --

func TestUI_Workflow(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)
	m := NewModel(logger, racer)

	// 1. Initial State
	if !strings.Contains(m.View(), "CAPTURE") {
		t.Error("Initial view missing status")
	}

	// 2. Capture Request
	req := &models.CapturedRequest{
		Method:   "GET",
		URL:      "http://test.com",
		Headers:  map[string]string{"Host": "test.com"},
		Protocol: "HTTP/1.1",
		Body:     []byte("small body"),
	}
	m, _ = update(m, CaptureMsg(req))

	if len(m.History.List()) != 1 {
		t.Error("Request not added to history")
	}

	// 3. Toggle Strategy
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.Strategy != "h1" {
		t.Error("Strategy not toggled to h1")
	}

	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.Strategy != "h3" {
		t.Error("Strategy not toggled to h3")
	}

	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab})
	if m.Strategy != "h2" {
		t.Error("Strategy not toggled back to h2")
	}

	// 4. Edit Mode
	// Pressing Enter triggers a Command to load the body. We must execute it.
	m, cmd := update(m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		// Execute the command (loading body)
		msg := cmd()
		// Feed the result back (BodyLoadedMsg) which triggers transition to StateEditing
		m, _ = update(m, msg)
	}

	if m.State != StateEditing {
		t.Error("Did not enter edit mode")
	}

	if !strings.Contains(m.Editor.Value(), "small body") {
		t.Error("Editor did not load request body")
	}

	// 5. Run Race (Mock)
	m, cmd = update(m, tea.KeyMsg{Type: tea.KeyCtrlS})
	if m.State != StateRunning {
		t.Error("Did not enter running state")
	}

	if cmd == nil {
		t.Fatal("Expected a command to run the race")
	}

	// Unpack the batch to find StreamResultMsg
	foundResult := false
	var processCmd func(tea.Cmd)
	processCmd = func(c tea.Cmd) {
		if c == nil {
			return
		}
		msg := c()
		if msg == nil {
			return
		}
		switch val := msg.(type) {
		case tea.BatchMsg:
			for _, sub := range val {
				processCmd(sub)
			}
		case StreamResultMsg:
			foundResult = true
			m, _ = update(m, val)
		}
	}

	processCmd(cmd)

	if !foundResult {
		t.Fatal("Expected to receive a StreamResultMsg (Mock racer execution)")
	}

	// 6. View Results
	// The racer finishes automatically when channel closes
	m, _ = update(m, RaceFinishedMsg{})

	if m.State != StateResults {
		t.Error("Did not enter results state")
	}
	if !strings.Contains(m.View(), "RESULTS") {
		t.Error("Results view mismatch")
	}

	// 7. Reset
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.State != StateIntercepting {
		t.Error("Did not return to intercept")
	}
}
func TestHistory_RAM(t *testing.T) {
	h := NewRequestHistory(10, zap.NewNop())
	req := &models.CapturedRequest{Body: []byte("tiny")}
	h.Add(req)
	meta := h.GetMeta(0)
	if meta == nil {
		t.Fatal("Failed to get request metadata")
	}
	retrieved := meta.Req
	if string(retrieved.Body) != "tiny" {
		t.Errorf("Body mismatch: %s", string(retrieved.Body))
	}
}

func TestHistory_DiskOffload(t *testing.T) {
	h := NewRequestHistory(10, zap.NewNop())
	defer h.Close()

	largeBody := make([]byte, 1024*15)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	req := &models.CapturedRequest{Body: largeBody}
	h.Add(req)

	meta := h.GetMeta(0)
	if meta == nil {
		t.Fatal("Failed to get request metadata")
	}

	if !meta.OnDisk {
		t.Error("Large body should be offloaded to disk")
	}
	if meta.Req.OffloadPath == "" {
		t.Error("OffloadPath should be set")
	}
	if _, err := os.Stat(meta.Req.OffloadPath); os.IsNotExist(err) {
		t.Error("Temp file was not created")
	}
	content, err := os.ReadFile(meta.Req.OffloadPath)
	if err != nil {
		t.Fatalf("Failed to read offload file: %v", err)
	}

	if len(content) != len(largeBody) {
		t.Errorf("Retrieved body size mismatch. Got %d, want %d", len(content), len(largeBody))
	}
}

func TestHistory_RingBuffer(t *testing.T) {
	limit := 3
	h := NewRequestHistory(limit, zap.NewNop())
	defer h.Close()
	h.Add(&models.CapturedRequest{Method: "1"})
	h.Add(&models.CapturedRequest{Method: "2"})
	h.Add(&models.CapturedRequest{Method: "3"})
	if h.size != 3 {
		t.Errorf("Size should be 3, got %d", h.size)
	}
	h.Add(&models.CapturedRequest{Method: "4"})
	if h.size != 3 {
		t.Errorf("Size should remain 3, got %d", h.size)
	}
	list := h.List()
	if list[0].Method != "2" {
		t.Errorf("Expected first item to be '2', got '%s'", list[0].Method)
	}
}

func TestRequestToText(t *testing.T) {
	req := &models.CapturedRequest{
		Method:   "GET",
		URL:      "http://test.com",
		Headers:  map[string]string{"Host": "test.com"},
		Protocol: "HTTP/1.1",
		Body:     []byte("test body"),
	}
	text := requestToText(req)
	if !strings.Contains(text, "GET http://test.com HTTP/1.1") {
		t.Error("Request line not present in output")
	}
}

func TestTextToRequest(t *testing.T) {
	text := "GET http://test.com HTTP/1.1\nHost: test.com\n\nsome body data"
	req, err := textToRequest(text, nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "GET" {
		t.Errorf("Method mismatch: got %s", req.Method)
	}
	if string(req.Body) != "some body data" {
		t.Errorf("Body mismatch: got %s", string(req.Body))
	}
}
