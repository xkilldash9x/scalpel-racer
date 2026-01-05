// FILENAME: internal/ui/model.go
package ui

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/packet"
	"go.uber.org/zap"
)

const MaxHistory = 1000

// -- Messages --
type CaptureMsg *models.CapturedRequest
type RaceResultMsg []models.ScanResult
type TickMsg time.Time
type BodyLoadedMsg struct {
	Content []byte
	Err     error
}

// -- States --
type State int

const (
	StateIntercepting State = iota
	StateLoading            // Async Hydration
	StateEditing
	StateRunning
	StateResults
)

type FilterMode int

const (
	FilterAll FilterMode = iota
	FilterOutliers
)

// -- KeyMap --
type KeyMap struct {
	Up, Down, Left, Right key.Binding
	Enter, Esc, Tab       key.Binding
	Quit, Save, Filter    key.Binding
	Base, Suspect         key.Binding
}

func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:      key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:    key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Enter:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
		Esc:     key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Tab:     key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "strategy")),
		Quit:    key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
		Save:    key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "attack")),
		Filter:  key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "filter")),
		Base:    key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "baseline")),
		Suspect: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "suspect")),
	}
}

// dynamicKeyMap adapts a slice of bindings to the help.KeyMap interface
type dynamicKeyMap struct {
	short []key.Binding
	full  [][]key.Binding
}

func (k dynamicKeyMap) ShortHelp() []key.Binding {
	return k.short
}

func (k dynamicKeyMap) FullHelp() [][]key.Binding {
	return k.full
}

type Model struct {
	State   State
	History *RequestHistory
	Logger  *zap.Logger
	Racer   *engine.Racer
	Ctx     context.Context
	Cancel  context.CancelFunc
	Keys    KeyMap

	// Config
	Concurrency int
	Strategy    string
	ProxyPort   int

	// UI Components
	ReqTable    table.Model
	Editor      textarea.Model
	ProgressBar progress.Model
	Spinner     spinner.Model
	ResTable    table.Model
	DiffView    viewport.Model
	Help        help.Model

	// Data
	SelectedReq *models.CapturedRequest
	Results     []models.ScanResult
	FilteredRes []models.ScanResult
	BaselineRes *models.ScanResult
	SuspectRes  *models.ScanResult
	Filter      FilterMode

	// Layout
	Width, Height int
	LastError     string
}

func NewModel(logger *zap.Logger, racer *engine.Racer, proxyPort int) Model {
	// Table Setup
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
	s.Selected = s.Selected.Foreground(lipgloss.Color("229")).Background(cFocus).Bold(false)
	t.SetStyles(s)

	// Results Table
	rt := table.New(
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
	rt.SetStyles(s)

	ta := textarea.New()
	ta.Placeholder = "Raw HTTP Request..."
	ta.SetHeight(20)
	ta.ShowLineNumbers = true

	prog := progress.New(progress.WithGradient(string(cFocus), string(cAccent)))
	spin := spinner.New()
	spin.Spinner = spinner.Dot
	spin.Style = lipgloss.NewStyle().Foreground(cAccent)

	ctx, cancel := context.WithCancel(context.Background())

	return Model{
		State:       StateIntercepting,
		History:     NewRequestHistory(MaxHistory, logger),
		ReqTable:    t,
		ResTable:    rt,
		Editor:      ta,
		ProgressBar: prog,
		Spinner:     spin,
		DiffView:    viewport.New(0, 0),
		Help:        help.New(),
		Keys:        DefaultKeyMap(),
		Logger:      logger,
		Concurrency: 20,
		Strategy:    "h2",
		Racer:       racer,
		Ctx:         ctx,
		Cancel:      cancel,
		ProxyPort:   proxyPort,
	}
}

func (m Model) Init() tea.Cmd {
	return m.Spinner.Tick
}

func (m Model) HelpKeyMap() help.KeyMap {
	var short []key.Binding
	var full [][]key.Binding

	switch m.State {
	case StateIntercepting:
		short = []key.Binding{m.Keys.Up, m.Keys.Down, m.Keys.Enter, m.Keys.Tab, m.Keys.Quit}
		full = [][]key.Binding{
			{m.Keys.Up, m.Keys.Down, m.Keys.Enter},
			{m.Keys.Tab, m.Keys.Quit},
		}
	case StateEditing:
		short = []key.Binding{m.Keys.Save, m.Keys.Esc}
		full = [][]key.Binding{{m.Keys.Save, m.Keys.Esc}}
	case StateResults:
		short = []key.Binding{m.Keys.Suspect, m.Keys.Base, m.Keys.Filter, m.Keys.Esc}
		full = [][]key.Binding{
			{m.Keys.Suspect, m.Keys.Base},
			{m.Keys.Filter, m.Keys.Esc},
		}
	case StateRunning:
		short = []key.Binding{m.Keys.Quit}
		full = [][]key.Binding{{m.Keys.Quit}}
	default:
		short = []key.Binding{m.Keys.Quit}
		full = [][]key.Binding{{m.Keys.Quit}}
	}

	return dynamicKeyMap{short: short, full: full}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.updateLayout()
		return m, nil

	case CaptureMsg:
		m.History.Add(msg)
		m.updateReqTable()
		if m.State == StateIntercepting {
			m.ReqTable.GotoBottom()
		}
		return m, nil

	case BodyLoadedMsg:
		// Transition: Loading -> Editing
		if msg.Err != nil {
			m.LastError = "Load Error: " + msg.Err.Error()
			m.State = StateIntercepting
		} else {
			m.SelectedReq.Body = msg.Content
			m.Editor.SetValue(requestToText(m.SelectedReq))
			m.State = StateEditing
			m.Editor.Focus()
		}
		return m, nil

	case TickMsg:
		if m.State == StateRunning && m.ProgressBar.Percent() < 0.95 {
			cmd = m.ProgressBar.IncrPercent(0.01)
			return m, tea.Batch(cmd, tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg { return TickMsg(t) }))
		}
		return m, nil

	case progress.FrameMsg:
		progressModel, cmd := m.ProgressBar.Update(msg)
		m.ProgressBar = progressModel.(progress.Model)
		return m, cmd

	case RaceResultMsg:
		m.Results = []models.ScanResult(msg)
		m.State = StateResults
		m.Filter = FilterAll
		m.ProgressBar.SetPercent(1.0)
		if len(m.Results) > 0 {
			m.BaselineRes = &m.Results[0]
			m.SuspectRes = &m.Results[0]
		}
		m.analyzeAndPopulateResults()
		m.updateDiffView()
		return m, nil

	case tea.KeyMsg:
		if key.Matches(msg, m.Keys.Quit) {
			m.Cancel()
			m.History.Close()
			return m, tea.Quit
		}
	}

	// State Delegation
	switch m.State {
	case StateIntercepting:
		return m.updateIntercepting(msg)
	case StateLoading:
		m.Spinner, cmd = m.Spinner.Update(msg)
		return m, cmd
	case StateEditing:
		return m.updateEditing(msg)
	case StateRunning:
		return m, nil // Block input
	case StateResults:
		return m.updateResults(msg)
	}

	return m, nil
}

func (m Model) updateIntercepting(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.Keys.Tab):
			// Cycle Strategies: h2 <-> h1 (h1 now includes packet sync)
			if m.Strategy == "h2" {
				m.Strategy = "h1"
			} else {
				m.Strategy = "h2"
			}

		case key.Matches(msg, m.Keys.Enter):
			idx := m.ReqTable.Cursor()
			if meta := m.History.GetMeta(idx); meta != nil {
				m.SelectedReq = meta.Req.Clone()
				// If body is on disk, we must load it asynchronously
				if meta.OnDisk {
					m.State = StateLoading
					return m, m.loadBodyCmd(meta.Req.OffloadPath)
				}
				// Otherwise, proceed
				m.Editor.SetValue(requestToText(m.SelectedReq))
				m.State = StateEditing
				m.Editor.Focus()
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.ReqTable, cmd = m.ReqTable.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updateEditing(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.Keys.Esc):
			m.State = StateIntercepting
			m.Editor.Blur()

		case key.Matches(msg, m.Keys.Save):
			updatedReq, err := textToRequest(m.Editor.Value(), m.SelectedReq)
			if err != nil {
				m.LastError = "Parse Error: " + err.Error()
				return m, nil
			}
			m.SelectedReq = updatedReq
			m.State = StateRunning
			m.ProgressBar.SetPercent(0)
			return m, tea.Batch(
				m.runRaceCmd(),
				tea.Tick(50*time.Millisecond, func(t time.Time) tea.Msg { return TickMsg(t) }),
			)
		}
		var cmd tea.Cmd
		m.Editor, cmd = m.Editor.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.Keys.Esc):
			m.State = StateIntercepting
		case key.Matches(msg, m.Keys.Filter):
			if m.Filter == FilterAll {
				m.Filter = FilterOutliers
			} else {
				m.Filter = FilterAll
			}
			m.analyzeAndPopulateResults()
		case key.Matches(msg, m.Keys.Base):
			if s := m.selectedResult(); s != nil {
				m.BaselineRes = s
				m.updateDiffView()
			}
		case key.Matches(msg, m.Keys.Suspect):
			if s := m.selectedResult(); s != nil {
				m.SuspectRes = s
				m.updateDiffView()
			}
		default:
			var cmd tea.Cmd
			m.ResTable, cmd = m.ResTable.Update(msg)
			cmds = append(cmds, cmd)
			// Auto-update diff on nav
			if s := m.selectedResult(); s != nil {
				m.SuspectRes = s
				m.updateDiffView()
			}
			m.DiffView, cmd = m.DiffView.Update(msg)
			cmds = append(cmds, cmd)
		}
	}
	return m, tea.Batch(cmds...)
}

// -- Commands --

func (m *Model) loadBodyCmd(path string) tea.Cmd {
	return func() tea.Msg {
		// Simulate Read Latency for testing responsiveness
		// time.Sleep(50 * time.Millisecond)
		content, err := os.ReadFile(path)
		return BodyLoadedMsg{Content: content, Err: err}
	}
}

// resolveTargetIPAndPort extracts the destination IP and port from the captured request.
// This is critical for configuring the NFQUEUE iptables rule.
func (m *Model) resolveTargetIPAndPort() (string, int) {
	host := m.SelectedReq.Headers["Host"]
	// Fallback to URL host if header is missing
	if host == "" {
		if u, err := url.Parse(m.SelectedReq.URL); err == nil {
			host = u.Host
		}
	}

	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}

	ips, _ := net.LookupIP(host)
	var targetIP string
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip.String()
			break
		}
	}

	if targetIP == "" {
		return "", 0
	}

	port := 80
	if u, err := url.Parse(m.SelectedReq.URL); err == nil {
		if u.Scheme == "https" {
			port = 443
		}
		if u.Port() != "" {
			if p, err := strconv.Atoi(u.Port()); err == nil {
				port = p
			}
		}
	}

	return targetIP, port
}

func (m *Model) runRaceCmd() tea.Cmd {
	return func() tea.Msg {
		var res []models.ScanResult
		var err error

		// FIX: Create a derived context with a strict timeout to prevent UI hangs.
		// Even if the engine logic fails to timeout (unlikely with other fixes), this
		// ensures the UI state machine eventually recovers.
		// 45 seconds gives ample buffer for the 30s race timeout.
		ctx, cancel := context.WithTimeout(m.Ctx, 45*time.Second)
		defer cancel()

		switch m.Strategy {
		case "h1", "first-seq":
			// STRATEGY: H1 + Packet Synchronization (Hybrid)
			// We attempt to start the Packet Controller to synchronize packets at the kernel level.
			// If it fails (e.g., lack of root), we degrade gracefully to standard Pipelining.

			targetIP, port := m.resolveTargetIPAndPort()
			if targetIP != "" {
				pc := packet.NewController(targetIP, port, m.Concurrency, m.Logger)
				if startErr := pc.Start(ctx); startErr == nil {
					// Success: Controller is active.
					defer pc.Close()
					m.Logger.Info("Packet Controller active", zap.String("ip", targetIP))
				} else {
					// Fallback: Log warning but proceed with application-layer sync
					m.Logger.Warn("Packet Controller failed to start (Root required?). Degrading to standard pipelining.", zap.Error(startErr))
				}
			}

			// Pass the timed context to the engine
			res, err = m.Racer.RunH1Race(ctx, m.SelectedReq, m.Concurrency)

		default:
			// STRATEGY: H2 (Single Packet Attack)
			res, err = m.Racer.RunH2Race(ctx, m.SelectedReq, m.Concurrency)
		}

		if err != nil {
			return RaceResultMsg([]models.ScanResult{{Error: err}})
		}
		sort.Slice(res, func(i, j int) bool { return res[i].Index < res[j].Index })
		return RaceResultMsg(res)
	}
}

// -- Helpers --

func requestToText(r *models.CapturedRequest) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s %s %s\n", r.Method, r.URL, r.Protocol))
	for k, v := range r.Headers {
		b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}
	b.WriteString("\n")
	b.Write(r.Body)
	return b.String()
}

func textToRequest(text string, original *models.CapturedRequest) (*models.CapturedRequest, error) {
	req := &models.CapturedRequest{Headers: make(map[string]string)}
	reader := bufio.NewReader(strings.NewReader(text))
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid request line")
	}
	req.Method, req.URL, req.Protocol = parts[0], parts[1], parts[2]
	for {
		l, err := reader.ReadString('\n')
		if err != nil || strings.TrimSpace(l) == "" {
			break
		}
		p := strings.SplitN(l, ":", 2)
		if len(p) == 2 {
			req.Headers[strings.TrimSpace(p[0])] = strings.TrimSpace(p[1])
		}
	}
	req.Body, _ = io.ReadAll(reader)
	if _, ok := req.Headers["Host"]; !ok {
		if h, ok := original.Headers["Host"]; ok {
			req.Headers["Host"] = h
		}
	}
	return req, nil
}
