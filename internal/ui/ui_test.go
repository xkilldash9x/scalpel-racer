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
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyTab}) // Toggle back
	if m.Strategy != "h2" {
		t.Error("Strategy not toggled back to h2")
	}

	// 4. Edit Mode
	m, _ = update(m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.State != StateEditing {
		t.Error("Did not enter edit mode")
	}

	// Verify Editor content
	if !strings.Contains(m.Editor.Value(), "small body") {
		t.Error("Editor did not load request body")
	}

	// 5. Run Race (Mock)
	m, cmd := update(m, tea.KeyMsg{Type: tea.KeyCtrlS})
	if m.State != StateRunning {
		t.Error("Did not enter running state")
	}

	if cmd == nil {
		t.Fatal("Expected a command to run the race")
	}

	// Execute the command(s) and find the RaceResultMsg.
	// The command can be a single command or a batch.
	var resultMsg tea.Msg
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, cmdFunc := range msg {
			res := cmdFunc()
			if _, ok := res.(RaceResultMsg); ok {
				resultMsg = res
				break
			}
		}
	default:
		resultMsg = msg
	}

	if resultMsg == nil {
		t.Fatal("Expected to receive a RaceResultMsg")
	}

	if _, ok := resultMsg.(RaceResultMsg); !ok {
		t.Fatalf("Cmd returned wrong type: %T", resultMsg)
	}

	m, _ = update(m, resultMsg)

	// 6. View Results
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

// Test Standard RAM usage
func TestHistory_RAM(t *testing.T) {
	h := NewRequestHistory(10, zap.NewNop())
	req := &models.CapturedRequest{Body: []byte("tiny")}
	h.Add(req)

	// FIXED: Use GetMeta and manual check to respect non-blocking interface
	meta := h.GetMeta(0)
	if meta == nil {
		t.Fatal("Failed to get request metadata")
	}
	retrieved := meta.Req

	if string(retrieved.Body) != "tiny" {
		t.Errorf("Body mismatch: %s", string(retrieved.Body))
	}

	// Verify internal state (Whitebox testing)
	if meta.OnDisk {
		t.Error("Small body should be in RAM, not disk")
	}
}

// Test Disk Offloading
func TestHistory_DiskOffload(t *testing.T) {
	h := NewRequestHistory(10, zap.NewNop())
	defer h.Close()

	// Create a body larger than BodyOffloadThreshold (10KB)
	largeBody := make([]byte, 1024*15)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	req := &models.CapturedRequest{Body: largeBody}
	h.Add(req)

	// Verify it went to disk
	meta := h.GetMeta(0)
	if meta == nil {
		t.Fatal("Failed to get request metadata")
	}

	if !meta.OnDisk {
		t.Error("Large body should be offloaded to disk")
	}
	// FIXED: Use correct field name Req.OffloadPath
	if meta.Req.OffloadPath == "" {
		t.Error("OffloadPath should be set")
	}
	if _, err := os.Stat(meta.Req.OffloadPath); os.IsNotExist(err) {
		t.Error("Temp file was not created")
	}
	if req.Body != nil {
		t.Error("Original request body in RAM should be nilled out")
	}

	// Simulate Hydration (Manual IO as per Architecture)
	// We do NOT want a Get() method that implicitly blocks on IO.
	content, err := os.ReadFile(meta.Req.OffloadPath)
	if err != nil {
		t.Fatalf("Failed to read offload file: %v", err)
	}

	if len(content) != len(largeBody) {
		t.Errorf("Retrieved body size mismatch. Got %d, want %d", len(content), len(largeBody))
	}
}

// Test Ring Buffer Overwrite Logic
func TestHistory_RingBuffer(t *testing.T) {
	limit := 3
	h := NewRequestHistory(limit, zap.NewNop())
	defer h.Close()

	// Add 3 items (filling the buffer)
	h.Add(&models.CapturedRequest{Method: "1"})
	h.Add(&models.CapturedRequest{Method: "2"})
	h.Add(&models.CapturedRequest{Method: "3"})

	if h.size != 3 {
		t.Errorf("Size should be 3, got %d", h.size)
	}

	// Verify order
	list := h.List()
	if list[0].Method != "1" || list[2].Method != "3" {
		t.Error("Initial list order incorrect")
	}

	// Add 4th item (should overwrite "1")
	h.Add(&models.CapturedRequest{Method: "4"})

	if h.size != 3 {
		t.Errorf("Size should remain 3, got %d", h.size)
	}

	list = h.List()
	// The oldest item ("1") should be gone. The list should shift.
	// Correct logical order should be: 2, 3, 4
	if list[0].Method != "2" {
		t.Errorf("Expected first item to be '2', got '%s'", list[0].Method)
	}
	if list[2].Method != "4" {
		t.Errorf("Expected last item to be '4', got '%s'", list[2].Method)
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
	if !strings.Contains(text, "Host: test.com") {
		t.Error("Host header not present in output")
	}
	if !strings.Contains(text, "test body") {
		t.Error("Body not present in output")
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
	if req.URL != "http://test.com" {
		t.Errorf("URL mismatch: got %s", req.URL)
	}
	if req.Protocol != "HTTP/1.1" {
		t.Errorf("Protocol mismatch: got %s", req.Protocol)
	}
	if val, ok := req.Headers["Host"]; !ok || val != "test.com" {
		t.Errorf("Host header mismatch: got %s", val)
	}
	if string(req.Body) != "some body data" {
		t.Errorf("Body mismatch: got %s", string(req.Body))
	}
}
