// FILENAME: internal/ui/view.go
package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

func (m Model) View() string {
	var content string

	switch m.State {
	case StateIntercepting:
		content = lipgloss.JoinVertical(lipgloss.Left, m.ReqTable.View())
	case StateLoading:
		content = lipgloss.Place(m.Width, m.Height, lipgloss.Center, lipgloss.Center,
			lipgloss.JoinVertical(lipgloss.Center, m.Spinner.View(), lipgloss.NewStyle().Foreground(cSub).Render("Hydrating payload from disk...")))
	case StateEditing:
		content = lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Foreground(cFocus).Bold(true).Render(" Payload Editor"),
			m.Editor.View())
	case StateRunning:
		content = lipgloss.JoinVertical(lipgloss.Center, "\n\n",
			lipgloss.NewStyle().Foreground(cErr).Bold(true).Render(" ATTACK IN PROGRESS "),
			"\n", m.ProgressBar.View())
	case StateResults:
		left := panelStyle.Render(m.ResTable.View())
		right := panelStyle.Render(m.DiffView.View())
		content = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}

	if m.LastError != "" {
		content = lipgloss.JoinVertical(lipgloss.Left, lipgloss.NewStyle().Foreground(cErr).Render("ERROR: "+m.LastError), content)
	}

	return lipgloss.JoinVertical(lipgloss.Left, m.renderHeader(), content, m.renderStatusBar())
}

func (m Model) renderHeader() string {
	title := " SCALPEL RACER "
	if m.State == StateResults {
		title += "| RESULTS "
	}
	return lipgloss.NewStyle().Background(cFocus).Foreground(lipgloss.Color("255")).Bold(true).Padding(0, 1).Render(title)
}

func (m Model) renderStatusBar() string {
	mode, info := "CAPTURE", fmt.Sprintf("Strategy: %s | Threads: %d | Queued: %d", m.Strategy, m.Concurrency, m.History.size)

	switch m.State {
	case StateEditing:
		mode, info = "EDIT", fmt.Sprintf("%s %s", m.SelectedReq.Method, m.SelectedReq.URL)
	case StateRunning:
		mode, info = "BUSY", "Synchronizing..."
	case StateResults:
		mode, info = "ANALYSIS", fmt.Sprintf("Samples: %d | Outliers: %v", len(m.Results), m.Filter == FilterOutliers)
	}

	keys := []string{}
	switch m.State {
	case StateIntercepting:
		keys = []string{"↑/↓ select", "enter edit", "tab strategy", "q quit"}
	case StateEditing:
		keys = []string{"ctrl+s fire", "esc cancel"}
	case StateResults:
		keys = []string{"enter suspect", "b baseline", "f filter", "esc back"}
	}

	return lipgloss.JoinVertical(lipgloss.Top,
		lipgloss.NewStyle().BorderTop(true).BorderForeground(cSub).Width(m.Width).Render(""),
		lipgloss.JoinHorizontal(lipgloss.Center,
			lipgloss.NewStyle().Background(cAccent).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1).Render(mode),
			statusText.Render(info),
			lipgloss.NewStyle().Width(5).Render(""),
			statusText.Render(strings.Join(keys, " • ")),
		),
	)
}

func (m *Model) updateReqTable() {
	reqs := m.History.List()
	rows := make([]table.Row, len(reqs))
	for i, r := range reqs {
		rows[i] = table.Row{fmt.Sprintf("%d", i), r.Method, r.Headers["Host"], r.URL, r.Protocol}
	}
	m.ReqTable.SetRows(rows)
}

func (m *Model) selectedResult() *models.ScanResult {
	idx := m.ResTable.Cursor()
	if idx >= 0 && idx < len(m.FilteredRes) {
		return &m.FilteredRes[idx]
	}
	return nil
}

func (m *Model) analyzeAndPopulateResults() {
	if len(m.Results) == 0 {
		m.ResTable.SetRows([]table.Row{})
		return
	}

	// Calculate Modes for Outlier Detection
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
		// Filter Logic
		isOutlier := r.StatusCode != modeS || len(r.Body) != modeL
		if m.Filter == FilterOutliers && !isOutlier {
			continue
		}
		m.FilteredRes = append(m.FilteredRes, r)

		// 1. Flag Column
		flag := normalFlag.String()
		if isOutlier {
			flag = outlierFlag.String()
		}

		// 2. ID Column
		idStr := fmt.Sprintf("%d", r.Index)

		// 3. Status Column
		sStr := fmt.Sprintf("%d", r.StatusCode)
		sStr = statusColor(r.StatusCode).Render(sStr)

		// 4. Size Column
		lStr := fmt.Sprintf("%d", len(r.Body))
		if isOutlier {
			lStr = lipgloss.NewStyle().Foreground(cWarn).Render(lStr)
		}

		// 5. Time Column
		tStr := r.Duration.Round(time.Microsecond).String()

		// 6. Hash Column (Safe Truncation)
		hStr := r.BodyHash
		if len(hStr) > 8 {
			hStr = hStr[:8]
		}

		// 7. Heuristic Overrides
		if r.Meta["SEQ_LOCKED"] == "true" {
			sStr = "🔒 " + sStr
			tStr = lipgloss.NewStyle().Foreground(cErr).Render(tStr)
		}

		// Construct Row: Must strictly match the 6 columns defined in NewModel
		rows = append(rows, table.Row{
			flag,  // Col 0: Flag
			idStr, // Col 1: ID
			sStr,  // Col 2: Status
			lStr,  // Col 3: Size
			tStr,  // Col 4: Time
			hStr,  // Col 5: Hash
		})
	}
	m.ResTable.SetRows(rows)
}

func (m *Model) updateDiffView() {
	if m.BaselineRes == nil || m.SuspectRes == nil {
		m.DiffView.SetContent("Waiting for data...")
		return
	}
	m.DiffView.SetContent(renderTextDiff(m.BaselineRes.Body, m.SuspectRes.Body, m.DiffView.Width))
}

// FIX: Added binary detection and stricter sanitization
func renderTextDiff(b, s []byte, width int) string {
	// 1. Safety Check: If data looks binary (e.g., GZIP/Images), do not render.
	if isBinary(b) || isBinary(s) {
		msg := fmt.Sprintf("\n\n[ Binary / Compressed Data Detected ]\n[ Visualization Disabled ]\n\nBaseline Size: %d bytes\nSuspect Size: %d bytes", len(b), len(s))
		return lipgloss.NewStyle().Foreground(cWarn).Align(lipgloss.Center).Width(width).Render(msg)
	}

	var sb strings.Builder
	bLines := strings.Split(string(b), "\n")
	sLines := strings.Split(string(s), "\n")
	max := len(bLines)
	if len(sLines) > max {
		max = len(sLines)
	}
	if max > 200 {
		max = 200
	}

	half := (width / 2) - 4
	if half < 10 {
		half = 10
	}

	for i := 0; i < max; i++ {
		bTxt := ""
		sTxt := ""
		if i < len(bLines) {
			bTxt = clean(bLines[i], half)
		}
		if i < len(sLines) {
			sTxt = clean(sLines[i], half)
		}

		sStyle := diffBaseStyle
		if bTxt != sTxt {
			sStyle = diffSuspectStyle
		}
		sb.WriteString(fmt.Sprintf("%-"+strconv.Itoa(half)+"s │ %s\n", diffBaseStyle.Render(bTxt), sStyle.Render(sTxt)))
	}
	return sb.String()
}

// FIX: Helper to detect binary content
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}

	nonPrintable := 0
	for _, b := range data[:checkLen] {
		// Null byte is a definitive binary indicator
		if b == 0x00 {
			return true
		}
		// Count non-printable characters (excluding standard whitespace)
		if (b < 32 && b != 9 && b != 10 && b != 13) || b == 127 {
			nonPrintable++
		}
	}

	// If >30% of the sample is non-printable, treat as binary
	if nonPrintable > checkLen/3 {
		return true
	}

	return !utf8.Valid(data)
}

func clean(s string, w int) string {
	// 1. Handle standard whitespace first (tab -> 2 spaces)
	s = strings.ReplaceAll(s, "\t", "  ")

	// 2. Strip Carriage Returns entirely (they just mess up line endings)
	s = strings.ReplaceAll(s, "\r", "")

	// 3. Replace other control characters with a visible placeholder '·'
	s = strings.Map(func(r rune) rune {
		// Keep printable characters (Letters, Numbers, Punctuation, Symbols)
		if unicode.IsPrint(r) {
			return r
		}
		// Replace non-printables (Control codes, etc.) with a middle dot
		return '·'
	}, s)

	// 4. Truncate to fit width
	if utf8.RuneCountInString(s) > w {
		return string([]rune(s)[:w-3]) + "..."
	}
	return s
}

func getMaxKey(m map[int]int) int {
	k, v := 0, -1
	for ki, vi := range m {
		if vi > v {
			k = ki
			v = vi
		}
	}
	return k
}

func (m *Model) updateLayout() {
	h := m.Height - 5
	if h < 10 {
		h = 10
	}
	m.ReqTable.SetWidth(m.Width - 2)
	m.ReqTable.SetHeight(h)
	m.Editor.SetWidth(m.Width - 4)
	m.Editor.SetHeight(h)
	m.ProgressBar.Width = m.Width - 10

	tw := m.Width
	if m.Width > 80 {
		tw = 50
	}
	m.ResTable.SetWidth(tw)
	m.ResTable.SetHeight(h)
	m.DiffView.Width = m.Width - tw - 6
	m.DiffView.Height = h
	if m.State == StateResults {
		m.updateDiffView()
	}
}
