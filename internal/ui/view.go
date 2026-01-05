// FILENAME: internal/ui/view.go
package ui

import (
	"fmt"
	"sort"
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
		if m.History.size == 0 {
			h := m.Height - 5
			if h < 0 {
				h = 0
			}
			msg := lipgloss.JoinVertical(lipgloss.Center,
				emptyTitleStyle.Render("Waiting for Traffic"),
				emptySubtitleStyle.Render("Configure your client to proxy through the listener."),
			)
			content = lipgloss.Place(m.Width, h, lipgloss.Center, lipgloss.Center, msg)
		} else {
			content = lipgloss.JoinVertical(lipgloss.Left, m.ReqTable.View())
		}
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

		// UX Enhancement: Fixed Header for Diff View
		// Separates metadata from the scrolling content and aligns columns
		header := m.renderDiffHeader()
		rightContent := lipgloss.JoinVertical(lipgloss.Left,
			header,
			m.DiffView.View(),
		)
		right := panelStyle.Render(rightContent)

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

	return lipgloss.JoinVertical(lipgloss.Top,
		lipgloss.NewStyle().BorderTop(true).BorderForeground(cSub).Width(m.Width).Render(""),
		lipgloss.JoinHorizontal(lipgloss.Center,
			lipgloss.NewStyle().Background(cAccent).Foreground(lipgloss.Color("0")).Bold(true).Padding(0, 1).Render(mode),
			statusText.Render(info),
			lipgloss.NewStyle().Width(5).Render(""),
			m.Help.View(m.HelpKeyMap()),
		),
	)
}

// renderDiffHeader creates a fixed header row for the diff comparison
func (m Model) renderDiffHeader() string {
	if m.BaselineRes == nil || m.SuspectRes == nil {
		return ""
	}

	width := m.DiffView.Width
	half := (width / 2) - 4
	if half < 10 {
		half = 10
	}

	// Dynamic Styles
	baseStyle := lipgloss.NewStyle().
		Foreground(cFocus).
		Bold(true).
		Width(half).
		Align(lipgloss.Left)

	suspectStyle := lipgloss.NewStyle().
		Foreground(cWarn).
		Bold(true).
		Width(half).
		Align(lipgloss.Left)

	sep := lipgloss.NewStyle().Foreground(cSub).SetString(" │ ")

	// Content
	bTitle := fmt.Sprintf("BASELINE [%d]", m.BaselineRes.StatusCode)
	sTitle := fmt.Sprintf("SUSPECT #%d [%d]", m.SuspectRes.Index, m.SuspectRes.StatusCode)

	return lipgloss.JoinHorizontal(lipgloss.Left,
		baseStyle.Render(bTitle),
		sep.Render(),
		suspectStyle.Render(sTitle),
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
		// Strict string formatting to prevent empty strings or "s" artifacts
		var sStr string
		// Explicit Error Handling
		if r.Error != nil || r.StatusCode == 0 {
			sStr = lipgloss.NewStyle().Foreground(cErr).Bold(true).Render("ERR")
		} else {
			sStr = strconv.Itoa(r.StatusCode)
			sStr = statusColor(r.StatusCode).Render(sStr)
		}

		// 4. Size Column
		lStr := strconv.Itoa(len(r.Body))
		if isOutlier {
			lStr = lipgloss.NewStyle().Foreground(cWarn).Render(lStr)
		}

		// 5. Time Column
		// Format specifically to keep width consistent (e.g. 100ms)
		tStr := r.Duration.Round(time.Microsecond).String()

		// 6. Hash Column (Safe Truncation)
		hStr := r.BodyHash
		if len(hStr) > 8 {
			hStr = hStr[:8]
		}

		// 7. Heuristic Overrides
		// Padlock adds width, so we ensure it doesn't break table column calculation
		if r.Meta["SEQ_LOCKED"] == "true" {
			sStr = "🔒" + sStr
			tStr = lipgloss.NewStyle().Foreground(cErr).Render(tStr)
		}

		// Construct Row: Must strictly match the 6 columns defined in NewModel
		rows = append(rows, table.Row{
			flag,  // Col 0: Flag (Width 1)
			idStr, // Col 1: ID (Width 4)
			sStr,  // Col 2: Status (Width 8)
			lStr,  // Col 3: Size (Width 8)
			tStr,  // Col 4: Time (Width 10)
			hStr,  // Col 5: Hash (Width 8)
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

// Helper to detect binary content and prevent terminal corruption
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

	// Styles for proper alignment
	colStyle := lipgloss.NewStyle().Width(half)
	sep := " │ "

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

		// Fix: Use lipgloss for padding to handle ANSI codes correctly.
		// Previous fmt.Sprintf("%-50s", coloredText) failed because ANSI codes were counted in length.
		line := lipgloss.JoinHorizontal(lipgloss.Left,
			colStyle.Render(diffBaseStyle.Render(bTxt)),
			sep,
			sStyle.Render(sTxt),
		)

		sb.WriteString(line + "\n")
	}
	return sb.String()
}

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

	// 2. Strip Carriage Returns entirely
	s = strings.ReplaceAll(s, "\r", "")

	// 3. Replace other control characters
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '·'
	}, s)

	// 4. Truncate to fit width (Panic Fix)
	if w <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) > w {
		if w < 3 {
			return string([]rune(s)[:w])
		}
		return string([]rune(s)[:w-3]) + "..."
	}
	return s
}

// getMaxKey now breaks ties deterministically by sorting keys.
func getMaxKey(m map[int]int) int {
	var keys []int
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys) // Deterministic order

	k, v := 0, -1
	for _, key := range keys {
		val := m[key]
		if val > v {
			k = key
			v = val
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

	// Dynamic Width Calculation
	tw := int(float64(m.Width) * 0.4)
	if tw < 60 {
		tw = 60
	}
	if tw > 90 {
		tw = 90
	}

	// Ensure we don't overflow small screens (Panic Fix)
	if tw > m.Width-10 {
		tw = m.Width - 10
	}
	// Absolute minimum width safety
	if tw < 10 {
		tw = 10
	}

	m.ResTable.SetWidth(tw)
	m.ResTable.SetHeight(h)

	// Diff View takes remaining space
	diffW := m.Width - tw - 6
	if diffW < 10 {
		diffW = 10
	}
	m.DiffView.Width = diffW
	// Reduced height to accommodate the fixed header (1 line)
	m.DiffView.Height = h - 1

	if m.State == StateResults {
		m.updateDiffView()
	}
}
