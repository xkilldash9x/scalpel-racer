// FILENAME: internal/ui/dashboard.go
package ui

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// DashboardModel handles the capture list.
type DashboardModel struct {
	Table       table.Model
	Spinner     spinner.Model
	History     *RequestHistory
	SelectedReq *models.CapturedRequest
	IsLoading   bool
	LastError   string
	Width       int
	Height      int
}

func NewDashboardModel(history *RequestHistory) DashboardModel {
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "ID", Width: 4},
			{Title: "Method", Width: 6},
			{Title: "Host", Width: 30},
			{Title: "Path", Width: 40},
			{Title: "Proto", Width: 8},
		}),
		table.WithFocused(true),
		table.WithHeight(15),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(config.ColorFocus).Bold(false)
	t.SetStyles(s)

	spin := spinner.New()
	spin.Spinner = spinner.Dot
	// Updated to use local style variable
	spin.Style = lipgloss.NewStyle().Foreground(cAccent)

	return DashboardModel{
		Table:   t,
		Spinner: spin,
		History: history,
	}
}

func (m DashboardModel) Update(msg tea.Msg) (DashboardModel, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.Table.SetWidth(m.Width - 2)
		m.Table.SetHeight(m.Height - 5)

	case CaptureMsg:
		m.History.Add(msg)
		rows := make([]table.Row, len(m.History.List()))
		for i, r := range m.History.List() {
			rows[i] = table.Row{fmt.Sprintf("%d", i), r.Method, r.Headers["Host"], r.URL, r.Protocol}
		}
		m.Table.SetRows(rows)
		if m.Table.Cursor() == len(rows)-2 {
			m.Table.GotoBottom()
		}

	case BodyLoadedMsg:
		m.IsLoading = false
		if msg.Err != nil {
			m.LastError = msg.Err.Error()
		} else {
			m.SelectedReq.Body = msg.Content
		}

	default:
		if m.IsLoading {
			m.Spinner, cmd = m.Spinner.Update(msg)
			return m, cmd
		}
		m.Table, cmd = m.Table.Update(msg)
	}
	return m, cmd
}

func (m DashboardModel) View() string {
	if m.IsLoading {
		return lipgloss.Place(m.Width, m.Height, lipgloss.Center, lipgloss.Center,
			lipgloss.JoinVertical(lipgloss.Center, m.Spinner.View(), "Hydrating payload from disk..."))
	}
	if m.History.size == 0 {
		// Updated to use empty state styles
		return lipgloss.Place(m.Width, m.Height-5, lipgloss.Center, lipgloss.Center,
			lipgloss.JoinVertical(lipgloss.Center,
				emptyTitleStyle.Render("Waiting for Traffic"),
				emptySubtitleStyle.Render("Configure client to proxy via port 8080"),
			))
	}
	return m.Table.View()
}

func (m *DashboardModel) SelectCurrent() tea.Cmd {
	idx := m.Table.Cursor()
	meta := m.History.GetMeta(idx)
	if meta == nil {
		return nil
	}
	m.SelectedReq = meta.Req.Clone()

	if meta.OnDisk {
		m.IsLoading = true
		return func() tea.Msg {
			content, err := os.ReadFile(meta.Req.OffloadPath)
			return BodyLoadedMsg{Content: content, Err: err}
		}
	}
	return func() tea.Msg {
		return BodyLoadedMsg{Content: m.SelectedReq.Body, Err: nil}
	}
}
