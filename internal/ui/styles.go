// FILENAME: internal/ui/styles.go
package ui

import "github.com/charmbracelet/lipgloss"

var (
	// -- Palette --
	cFocus  = lipgloss.Color("39")  // Vivid Blue
	cAccent = lipgloss.Color("212") // Pink
	cErr    = lipgloss.Color("196") // Red
	cWarn   = lipgloss.Color("214") // Orange
	cOk     = lipgloss.Color("42")  // Green
	cSub    = lipgloss.Color("240") // Dark Grey

	// -- Components --

	// Panels
	panelStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(cSub).
			Padding(0, 1)

	// Status Bar
	statusBarStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("234")).
			Background(cSub)

	statusText = lipgloss.NewStyle().
			Inherit(statusBarStyle).
			Foreground(lipgloss.Color("255")).
			Padding(0, 1)

	// Diff Viewer
	diffBaseStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	diffSuspectStyle = lipgloss.NewStyle().Foreground(cWarn)

	// Flags
	outlierFlag = lipgloss.NewStyle().Foreground(cErr).Bold(true).SetString("!")
	normalFlag  = lipgloss.NewStyle().SetString(" ")
)

// statusColor returns a style based on standard HTTP status code semantics.
func statusColor(code int) lipgloss.Style {
	s := lipgloss.NewStyle().Bold(true)
	switch {
	case code >= 200 && code < 300:
		return s.Foreground(cOk)
	case code >= 300 && code < 400:
		return s.Foreground(cWarn)
	case code >= 400:
		return s.Foreground(cErr)
	default:
		return s.Foreground(cSub)
	}
}
