// FILENAME: internal/ui/results.go
package ui

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

type ResultsModel struct {
	Table       table.Model
	DiffView    viewport.Model
	Results     []models.ScanResult
	FilteredRes []models.ScanResult
	Baseline    *models.ScanResult
	Suspect     *models.ScanResult
	Filter      FilterMode
	Width       int
	Height      int
}

func NewResultsModel() ResultsModel {
	t := table.New(
		table.WithColumns([]table.Column{
			{Title: "", Width: 1},
			{Title: "ID", Width: 4},
			{Title: "Status", Width: 8},
			{Title: "Size", Width: 8},
			{Title: "Time", Width: 10},
			{Title: "Hash", Width: 8},
		}),
		table.WithFocused(true),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).Bold(true)
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(config.ColorFocus).Bold(false)
	t.SetStyles(s)

	return ResultsModel{
		Table:    t,
		DiffView: viewport.New(0, 0),
		Results:  make([]models.ScanResult, 0),
	}
}

func (m ResultsModel) Update(msg tea.Msg) (ResultsModel, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.updateLayout()

	case models.ScanResult:
		m.Results = append(m.Results, msg)
		if len(m.Results) == 1 {
			m.Baseline = &m.Results[0]
			m.Suspect = &m.Results[0]
		}
		m.refreshTable()

	case tea.KeyMsg:
		switch msg.String() {
		case "up", "down", "k", "j":
			m.Table, cmd = m.Table.Update(msg)
			if s := m.selectedResult(); s != nil {
				m.Suspect = s
				m.updateDiff()
			}
			return m, cmd
		}
		m.DiffView, cmd = m.DiffView.Update(msg)
	}
	return m, cmd
}

func (m ResultsModel) View() string {
	left := panelStyle.Render(m.Table.View())
	header := m.renderDiffHeader()
	right := panelStyle.Render(lipgloss.JoinVertical(lipgloss.Left, header, m.DiffView.View()))
	return lipgloss.JoinHorizontal(lipgloss.Top, left, right)
}

func (m *ResultsModel) refreshTable() {
	sCounts := make(map[int]int)
	lCounts := make(map[int]int)
	for _, r := range m.Results {
		sCounts[r.StatusCode]++
		lCounts[len(r.Body)]++
	}
	modeS := getMaxKey(sCounts)
	modeL := getMaxKey(lCounts)

	var rows []table.Row
	m.FilteredRes = []models.ScanResult{}

	for _, r := range m.Results {
		isOutlier := r.StatusCode != modeS || len(r.Body) != modeL
		if m.Filter == FilterOutliers && !isOutlier {
			continue
		}
		m.FilteredRes = append(m.FilteredRes, r)

		flag := normalFlagStyle.Render(" ")
		if isOutlier {
			flag = outlierFlagStyle.Render("!")
		}

		sStr := strconv.Itoa(r.StatusCode)
		if r.Error != nil {
			sStr = lipgloss.NewStyle().Foreground(config.ColorErr).Render("ERR")
		} else {
			sStr = statusColor(r.StatusCode).Render(sStr)
		}

		// Safe handling for hash display
		hashDisplay := r.BodyHash
		if len(hashDisplay) > 8 {
			hashDisplay = hashDisplay[:8]
		}

		rows = append(rows, table.Row{
			flag,
			strconv.Itoa(r.Index),
			sStr,
			strconv.Itoa(len(r.Body)),
			r.Duration.Round(time.Microsecond).String(),
			hashDisplay,
		})
	}
	m.Table.SetRows(rows)
}

func (m *ResultsModel) updateDiff() {
	if m.Baseline == nil || m.Suspect == nil {
		return
	}
	m.DiffView.SetContent(renderTextDiff(m.Baseline.Body, m.Suspect.Body, m.DiffView.Width))
}

func (m *ResultsModel) selectedResult() *models.ScanResult {
	idx := m.Table.Cursor()
	if idx >= 0 && idx < len(m.FilteredRes) {
		return &m.FilteredRes[idx]
	}
	return nil
}

func (m *ResultsModel) updateLayout() {
	h := m.Height - 5
	tw := int(float64(m.Width) * 0.4)
	if tw < 40 {
		tw = 40
	}

	m.Table.SetWidth(tw)
	m.Table.SetHeight(h)

	m.DiffView.Width = m.Width - tw - 6
	m.DiffView.Height = h - 1
	m.updateDiff()
}

func (m ResultsModel) renderDiffHeader() string {
	if m.Baseline == nil || m.Suspect == nil {
		return ""
	}
	bTitle := "BASE" // Simplification to fit width
	sTitle := "SUSPECT"

	// Ensure we align with the columns in renderTextDiff
	halfW := (m.DiffView.Width - 4) / 2

	return lipgloss.JoinHorizontal(lipgloss.Left,
		diffBaseStyle.Width(halfW).Render(bTitle),
		" | ",
		diffSuspectStyle.Width(halfW).Render(sTitle),
	)
}

// Helper local to results to avoid circular imports
func getMaxKey(m map[int]int) int {
	var keys []int
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	k, v := 0, -1
	for _, key := range keys {
		if m[key] > v {
			k = key
			v = m[key]
		}
	}
	return k
}

func renderTextDiff(b, s []byte, width int) string {
	if isBinary(b) || isBinary(s) {
		return lipgloss.NewStyle().Foreground(config.ColorWarn).Render("Binary Data Detected")
	}

	baseStr := clean(string(b), 0) // Clean but don't truncate yet
	suspStr := clean(string(s), 0)

	baseLines := strings.Split(baseStr, "\n")
	suspLines := strings.Split(suspStr, "\n")

	maxLines := len(baseLines)
	if len(suspLines) > maxLines {
		maxLines = len(suspLines)
	}

	// Calculate column width (half of viewport minus separator and padding)
	colWidth := (width - 4) / 2
	if colWidth < 10 {
		colWidth = 10
	}

	var out strings.Builder

	for i := 0; i < maxLines; i++ {
		bLine := ""
		if i < len(baseLines) {
			bLine = baseLines[i]
		}
		sLine := ""
		if i < len(suspLines) {
			sLine = suspLines[i]
		}

		// Check for differences before truncation
		isDiff := bLine != sLine

		// Truncate for display
		bRender := truncate(bLine, colWidth)
		sRender := truncate(sLine, colWidth)

		style := diffBaseStyle
		if isDiff {
			style = diffSuspectStyle
		}

		// Render side-by-side
		// Left (Base) | Right (Suspect)
		left := diffBaseStyle.Width(colWidth).Render(bRender)
		right := style.Width(colWidth).Render(sRender)

		out.WriteString(lipgloss.JoinHorizontal(lipgloss.Left, left, " | ", right))
		out.WriteString("\n")
	}

	return out.String()
}

func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func truncate(s string, w int) string {
	if len(s) > w {
		if w > 3 {
			return s[:w-3] + "..."
		}
		return s[:w]
	}
	return s
}
