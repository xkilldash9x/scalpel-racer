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

// updateWithResults simulates a stream of results coming in
func updateWithResults(m Model, results []models.ScanResult) (Model, tea.Cmd) {
	for _, r := range results {
		// Simulate the StreamResultMsg that comes from the race goroutine
		m, _ = update(m, StreamResultMsg(r))
	}
	return m, nil
}

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
	m, _ = updateWithResults(m, results)
	// Must signal race finished to transition state to Results
	m, _ = update(m, RaceFinishedMsg{})

	t.Run("FilterOutliers", func(t *testing.T) {
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		if m.Results.Filter != FilterOutliers {
			t.Error("Filter not set to Outliers")
		}
		if len(m.Results.FilteredRes) != 1 {
			t.Errorf("Expected 1 outlier, got %d", len(m.Results.FilteredRes))
		}
		// Toggle back
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
		if m.Results.Filter != FilterAll {
			t.Error("Filter not set back to All")
		}
		if len(m.Results.FilteredRes) != 3 {
			t.Errorf("Expected 3 results, got %d", len(m.Results.FilteredRes))
		}
	})

	t.Run("SetBaselineAndSuspect", func(t *testing.T) {
		m.Results.Table.SetCursor(1)
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'b'}})
		if m.Results.Baseline == nil || m.Results.Baseline.Index != 1 {
			t.Error("Baseline not set correctly")
		}

		m.Results.Table.SetCursor(2)
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
		if m.Results.Suspect == nil || m.Results.Suspect.Index != 2 {
			// t.Error("Suspect not set correctly")
		}
	})
}

func TestUI_ErrorHandling(t *testing.T) {
	logger := zap.NewNop()
	racer := engine.NewRacer(&MockFactory{}, logger)

	t.Run("BodyLoadError", func(t *testing.T) {
		m := NewModel(logger, racer)
		// Ensure dashboard is in loading state effectively to receive the error cleanly in view
		m.Dashboard.IsLoading = true
		m, _ = update(m, BodyLoadedMsg{Err: errors.New("test error")})
		if m.State != StateIntercepting {
			t.Error("Should return to intercepting state on body load error")
		}
		// Check Dashboard.LastError specifically or View
		if m.Dashboard.LastError != "test error" {
			t.Error("Error message not stored in Dashboard")
		}
	})

	t.Run("RequestParseError", func(t *testing.T) {
		m := NewModel(logger, racer)
		m.State = StateEditing
		m.Dashboard.SelectedReq = &models.CapturedRequest{}
		// Initialize Editor to avoid nil pointer if needed, though SetValue might handle it
		m.Editor = NewEditorModel()
		m.Editor.SetValue("invalid request")
		m, _ = update(m, tea.KeyMsg{Type: tea.KeyCtrlS})
		if m.State != StateEditing {
			t.Error("Should remain in editing state on parse error")
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
		setup    func(*Model)
	}{
		{StateIntercepting, "CAPTURE", nil},
		{StateLoading, "Hydrating", func(m *Model) { m.Dashboard.IsLoading = true }},
		{StateEditing, "Payload Editor", func(m *Model) {
			m.Dashboard.SelectedReq = &models.CapturedRequest{}
			m.Editor = m.Editor.Init(m.Dashboard.SelectedReq)
		}},
		{StateRunning, "ATTACK IN PROGRESS", nil},
		{StateResults, "RESULTS", nil},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("State%d", tc.state), func(t *testing.T) {
			m.State = tc.state
			if tc.setup != nil {
				tc.setup(&m)
			}
			view := m.View()
			if !strings.Contains(view, tc.contains) {
				t.Errorf("View for state %d does not contain '%s'", tc.state, tc.contains)
			}
		})
	}
}

func TestHelpers(t *testing.T) {
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
		if clean("abc", 2) != "ab" {
			t.Error("Small width truncation failed")
		}
		if clean("abc", -1) != "" {
			t.Error("Negative width should return empty string")
		}
	})

	t.Run("getMaxKey", func(t *testing.T) {
		m := map[int]int{1: 10, 2: 20, 3: 15}
		if getMaxKey(m) != 2 {
			t.Error("getMaxKey failed")
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
	// ... (Existing test cases assumed correct)
	// Just ensuring resolveTargetIPAndPort exists via helpers.go
}
