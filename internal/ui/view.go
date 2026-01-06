// FILENAME: internal/ui/view.go
package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
)

// Model.View implementation
func (m Model) View() string {
	var content string

	switch m.State {
	case StateIntercepting:
		content = m.Dashboard.View()
	case StateLoading:
		content = m.Dashboard.View()
	case StateEditing:
		// Add header to match test expectations and improve UX
		header := lipgloss.NewStyle().Bold(true).Foreground(config.ColorFocus).Render("Payload Editor")
		content = lipgloss.JoinVertical(lipgloss.Left, header, m.Editor.View())
	case StateRunning:
		content = lipgloss.JoinVertical(lipgloss.Center, "\n\n",
			lipgloss.NewStyle().Foreground(config.ColorErr).Bold(true).Render(" ATTACK IN PROGRESS "),
			"\n", m.ProgressBar.View())
	case StateResults:
		content = m.Results.View()
	}

	return lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), content, m.renderStatusBar())
}

func (m Model) renderHeader() string {
	return lipgloss.NewStyle().Background(config.ColorFocus).Foreground(lipgloss.Color("255")).Bold(true).Padding(0, 1).Render(" SCALPEL RACER | " + m.Strategy)
}

func (m Model) renderStatusBar() string {
	// Uses statusText from styles.go for the inner text styling
	return statusText.Render(fmt.Sprintf(" %s | Threads: %d ", m.State.String(), m.Concurrency))
}
