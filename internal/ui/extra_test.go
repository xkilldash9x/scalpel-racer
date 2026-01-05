// FILENAME: internal/ui/extra_test.go
package ui

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"go.uber.org/zap"
)

func TestUI_StateTransitions(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)

	t.Run("CancelEdit", func(t *testing.T) {
		m := NewModel(logger, racer)
		m.State = StateEditing
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyEsc})
		if m.State != StateIntercepting {
			t.Error("Did not return to intercepting state")
		}
	})

	t.Run("BackFromResults", func(t *testing.T) {
		m := NewModel(logger, racer)
		m.State = StateResults
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyEsc})
		if m.State != StateIntercepting {
			t.Error("Did not return to intercepting state")
		}
	})

	t.Run("Quit", func(t *testing.T) {
		m := NewModel(logger, racer)
		_, cmd := update(m, tea.KeyMsg{Type: tea.KeyCtrlC})
		if cmd == nil {
			t.Fatal("Expected a quit command")
		}
		if cmd() != tea.Quit() {
			t.Error("Did not return a quit message")
		}
	})
}

func TestUI_ResultsView(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)
	m := NewModel(logger, racer)

	results := []models.ScanResult{
		{Index: 0, StatusCode: 200, Body: []byte("a")},
		{Index: 1, StatusCode: 404, Body: []byte("b")},
		{Index: 2, StatusCode: 200, Body: []byte("a")},
	}
	m, _ = update(m, RaceResultMsg(results))

	t.Run("FilterOutliers", func(t *testing.T) {
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		if m.Filter != FilterOutliers {
			t.Error("Filter not set to Outliers")
		}
		if len(m.FilteredRes) != 1 {
			t.Errorf("Expected 1 outlier, got %d", len(m.FilteredRes))
		}
		// Toggle back
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		if m.Filter != FilterAll {
			t.Error("Filter not set back to All")
		}
		if len(m.FilteredRes) != 3 {
			t.Errorf("Expected 3 results, got %d", len(m.FilteredRes))
		}
	})

	t.Run("SetBaselineAndSuspect", func(t *testing.T) {
		m.ResTable.SetCursor(1)
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
		if m.BaselineRes.Index != 1 {
			t.Error("Baseline not set correctly")
		}

		m.ResTable.SetCursor(2)
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyEnter})
		if m.SuspectRes.Index != 2 {
			t.Error("Suspect not set correctly")
		}
	})
}

func TestUI_ErrorHandling(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)

	t.Run("BodyLoadError", func(t *testing.T) {
		m := NewModel(logger, racer)
		m, _ = update(m, BodyLoadedMsg{Err: errors.New("test error")})
		if m.State != StateIntercepting {
			t.Error("Should return to intercepting state on body load error")
		}
		if !strings.Contains(m.View(), "test error") {
			t.Error("Error message not displayed in view")
		}
	})

	t.Run("RequestParseError", func(t *testing.T) {
		m := NewModel(logger, racer)
		m.State = StateEditing
		m.SelectedReq = &models.CapturedRequest{}
		m.Editor.SetValue("invalid request")
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyCtrlS})
		if m.State != StateEditing {
			t.Error("Should remain in editing state on parse error")
		}
		if !strings.Contains(m.View(), "Parse Error") {
			t.Error("Error message not displayed in view")
		}
	})
}

func TestUI_View(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)
	m := NewModel(logger, racer)

	// To get some dimensions
	m, _ = update(m, tea.WindowSizeMsg{Width: 80, Height: 24})

	testCases := []struct {
		state    State
		contains string
	}{
		{StateIntercepting, "CAPTURE"},
		{StateLoading, "Hydrating"},
		{StateEditing, "Payload Editor"},
		{StateRunning, "ATTACK IN PROGRESS"},
		{StateResults, "RESULTS"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("State%d", tc.state), func(t *testing.T) {
			m.State = tc.state
			if tc.state == StateEditing {
				m.SelectedReq = &models.CapturedRequest{}
			}
			view := m.View()
			if !strings.Contains(view, tc.contains) {
				t.Errorf("View for state %d does not contain '%s'", tc.state, tc.contains)
			}
		})
	}
}

func TestHelpers(t *testing.T) {
	t.Run("isBinary", func(t *testing.T) {
		if !isBinary([]byte{0x00}) {
			t.Error("Null byte should be considered binary")
		}
		if isBinary([]byte("hello world")) {
			t.Error("Plain text should not be considered binary")
		}
	})

	t.Run("clean", func(t *testing.T) {
		if clean("\t\r", 10) != "  " {
			t.Error("Whitespace cleaning failed")
		}
		if !strings.Contains(clean("a\x00b", 10), "·") {
			t.Error("Non-printable characters not replaced")
		}
		if clean("1234567890", 5) != "12..." {
			t.Error("Truncation failed")
		}
		// FIX: Verify fix for panic on small width
		if clean("abc", 2) != "ab" {
			t.Error("Small width truncation failed")
		}
		// FIX: Verify fix for negative width (bug fix verification)
		if clean("abc", -1) != "" {
			t.Error("Negative width should return empty string, not panic")
		}
	})

	t.Run("getMaxKey", func(t *testing.T) {
		m := map[int]int{1: 10, 2: 20, 3: 15}
		if getMaxKey(m) != 2 {
			t.Error("getMaxKey failed")
		}
		// FIX: Deterministic tie-breaking check
		mTie := map[int]int{1: 10, 2: 10}
		if getMaxKey(mTie) != 1 {
			t.Error("getMaxKey nondeterministic on tie")
		}
	})
}

// MockResolver implements the Resolver interface for testing.
type MockResolver struct{}

func (mr *MockResolver) LookupIP(host string) ([]net.IP, error) {
	// Deterministic Mock
	if host == "example.com" {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}
	return nil, fmt.Errorf("not found")
}

func Test_resolveTargetIPAndPort(t *testing.T) {
	testCases := []struct {
		name       string
		req        *models.CapturedRequest
		expectedIP string
		expectedPo int
	}{
		{
			"HTTP",
			&models.CapturedRequest{
				URL:     "http://example.com",
				Headers: map[string]string{"Host": "example.com"},
			},
			"93.184.216.34", 80,
		},
		{
			"HTTPS",
			&models.CapturedRequest{
				URL:     "https://example.com",
				Headers: map[string]string{"Host": "example.com"},
			},
			"93.184.216.34", 443,
		},
		{
			"WithPort",
			&models.CapturedRequest{
				URL:     "http://example.com:8080",
				Headers: map[string]string{"Host": "example.com:8080"},
			},
			"93.184.216.34", 8080,
		},
		{
			"NoHostHeader",
			&models.CapturedRequest{
				URL:     "http://example.com",
				Headers: map[string]string{},
			},
			"93.184.216.34", 80,
		},
		{
			"HostWithoutPort",
			&models.CapturedRequest{
				URL:     "http://example.com",
				Headers: map[string]string{"Host": "example.com"},
			},
			"93.184.216.34", 80, // Should resolve despite no port in Host header
		},
		{
			"HostOverridesDefault",
			&models.CapturedRequest{
				URL:     "/", // Relative URL
				Headers: map[string]string{"Host": "example.com:8080"},
			},
			"93.184.216.34", 8080, // New logic should return 8080, not 80
		},
		{
			"HostOverridesDefaultHTTPS",
			&models.CapturedRequest{
				URL:     "https://example.com", // Implies 443
				Headers: map[string]string{"Host": "example.com:8443"},
			},
			"93.184.216.34", 8443, // Host header is more specific than default scheme
		},
		{
			"URLOverridesHost",
			&models.CapturedRequest{
				URL:     "http://example.com:9000",
				Headers: map[string]string{"Host": "example.com:8000"},
			},
			"93.184.216.34", 9000, // Explicit URL port wins
		},
	}

	resolver := &MockResolver{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port := resolveTargetIPAndPort(tc.req, resolver)
			if ip != tc.expectedIP {
				t.Errorf("Expected IP %s, got %s", tc.expectedIP, ip)
			}
			if port != tc.expectedPo {
				t.Errorf("Expected port %d, got %d", tc.expectedPo, port)
			}
		})
	}
}

func TestTextToRequest_ContentLength(t *testing.T) {
	// Verify that Content-Length is updated
	req := &models.CapturedRequest{
		Headers: map[string]string{"Host": "example.com", "Content-Length": "5"},
	}
	text := "POST http://example.com HTTP/1.1\nHost: example.com\nContent-Length: 5\n\n1234567890" // 10 bytes

	newReq, err := textToRequest(text, req)
	if err != nil {
		t.Fatal(err)
	}

	if newReq.Headers["Content-Length"] != "10" {
		t.Errorf("Content-Length not updated. Got %s, want 10", newReq.Headers["Content-Length"])
	}
}
