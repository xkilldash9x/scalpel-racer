package main

import (
	"fmt"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

type MockRunner struct {
	RunError error
}

func (m *MockRunner) Run(p *tea.Program) (tea.Model, error) {
	return nil, m.RunError
}

func TestRun_FlagError(t *testing.T) {
	err := Run([]string{"-undefined-flag"}, &MockRunner{})
	if err == nil {
		t.Error("Expected error for undefined flag, got nil")
	}
}

func TestRun_Success(t *testing.T) {
	// Use port 0 to bind to a random available port to prevent flake
	err := Run([]string{"-p", "0"}, &MockRunner{})
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
}

func TestRun_UIError(t *testing.T) {
	mock := &MockRunner{RunError: fmt.Errorf("ui failure")}
	err := Run([]string{"-p", "0"}, mock)
	if err == nil {
		t.Error("Expected UI error")
	}
}
