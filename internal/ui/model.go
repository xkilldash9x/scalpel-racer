// FILENAME: internal/ui/model.go
package ui

import (
	"context"
	"net"
	"net/url"
	"strconv"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-racer/internal/config"
	"github.com/xkilldash9x/scalpel-racer/internal/engine"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
	"github.com/xkilldash9x/scalpel-racer/internal/packet"
	"github.com/xkilldash9x/scalpel-racer/internal/report"
	"go.uber.org/zap"
)

type Resolver interface {
	LookupIP(host string) ([]net.IP, error)
}
type DefaultResolver struct{}

func (d DefaultResolver) LookupIP(host string) ([]net.IP, error) { return net.LookupIP(host) }

// Messages
type CaptureMsg *models.CapturedRequest
type BodyLoadedMsg struct {
	Content []byte
	Err     error
}
type StreamResultMsg models.ScanResult
type RaceFinishedMsg struct{}

// Model defines the main application state.
type Model struct {
	State       State
	History     *RequestHistory
	Logger      *zap.Logger
	Racer       *engine.Racer
	Resolver    Resolver
	Concurrency int
	Strategy    string

	// Sub-Models
	Dashboard DashboardModel
	Editor    EditorModel
	Results   ResultsModel

	// Components
	ProgressBar progress.Model
	Help        help.Model
	Keys        KeyMap

	// Runtime
	Ctx    context.Context
	Cancel context.CancelFunc
	Width  int
	Height int
}

func NewModel(logger *zap.Logger, racer *engine.Racer) Model {
	ctx, cancel := context.WithCancel(context.Background())
	hist := NewRequestHistory(config.MaxHistorySize, logger)

	return Model{
		State:       StateIntercepting,
		History:     hist,
		Logger:      logger,
		Racer:       racer,
		Resolver:    DefaultResolver{},
		Concurrency: config.DefaultConcurrency,
		Strategy:    config.DefaultStrategy,

		Dashboard:   NewDashboardModel(hist),
		Editor:      NewEditorModel(),
		Results:     NewResultsModel(),
		ProgressBar: progress.New(progress.WithGradient(string(config.ColorFocus), string(config.ColorAccent))),
		Help:        help.New(),
		Keys:        DefaultKeyMap(),

		Ctx:    ctx,
		Cancel: cancel,
	}
}

func (m Model) Init() tea.Cmd {
	return m.Dashboard.Spinner.Tick
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		m.Dashboard, _ = m.Dashboard.Update(msg)
		m.Editor, _ = m.Editor.Update(msg)
		m.Results, _ = m.Results.Update(msg)
		m.ProgressBar.Width = m.Width - 10

	case tea.KeyMsg:
		if key.Matches(msg, m.Keys.Quit) {
			m.Cancel()
			m.History.Close()
			return m, tea.Quit
		}
		if m.State == StateIntercepting && key.Matches(msg, m.Keys.Tab) {
			m.cycleStrategy()
			return m, nil
		}

	case CaptureMsg:
		m.Dashboard, cmd = m.Dashboard.Update(msg)
		return m, cmd

	case StreamResultMsg:
		res := models.ScanResult(msg)
		m.Results, _ = m.Results.Update(res)

		if m.Concurrency > 0 {
			pct := float64(len(m.Results.Results)) / float64(m.Concurrency)
			m.ProgressBar.SetPercent(pct)
		}
		return m, nil

	case RaceFinishedMsg:
		m.State = StateResults
		m.ProgressBar.SetPercent(1.0)
		return m, nil
	}

	// State Delegation
	switch m.State {
	case StateIntercepting:
		if k, ok := msg.(tea.KeyMsg); ok && key.Matches(k, m.Keys.Enter) {
			cmd = m.Dashboard.SelectCurrent()
			return m, cmd
		}
		if _, ok := msg.(BodyLoadedMsg); ok {
			m.Dashboard, _ = m.Dashboard.Update(msg)
			if m.Dashboard.LastError == "" && m.Dashboard.SelectedReq != nil {
				m.State = StateEditing
				m.Editor = m.Editor.Init(m.Dashboard.SelectedReq)
			}
			return m, nil
		}
		m.Dashboard, cmd = m.Dashboard.Update(msg)

	case StateEditing:
		if k, ok := msg.(tea.KeyMsg); ok {
			if key.Matches(k, m.Keys.Esc) {
				m.State = StateIntercepting
				return m, nil
			}
			if key.Matches(k, m.Keys.Save) {
				req, err := m.Editor.ParseRequest()
				if err == nil {
					m.State = StateRunning
					m.Results = NewResultsModel() // Reset results
					m.Results.Update(tea.WindowSizeMsg{Width: m.Width, Height: m.Height})
					return m, m.StartRace(req)
				}
			}
		}
		m.Editor, cmd = m.Editor.Update(msg)

	case StateRunning:
		// Safe Type Assertion for ProgressBar
		if progMsg, ok := msg.(progress.FrameMsg); ok {
			var pModel tea.Model
			pModel, cmd = m.ProgressBar.Update(progMsg)
			m.ProgressBar = pModel.(progress.Model)
		}

	case StateResults:
		if k, ok := msg.(tea.KeyMsg); ok {
			if key.Matches(k, m.Keys.Esc) {
				m.State = StateIntercepting
				return m, nil
			}
			if key.Matches(k, m.Keys.Save) {
				w := report.NewWriter("reports")
				_ = w.WriteArtifacts(m.Results.Results, "race")
			}
			if key.Matches(k, m.Keys.Filter) {
				if m.Results.Filter == FilterAll {
					m.Results.Filter = FilterOutliers
				} else {
					m.Results.Filter = FilterAll
				}
				m.Results.refreshTable()
				return m, nil
			}
			if key.Matches(k, m.Keys.Base) {
				m.Results.Baseline = m.Results.selectedResult()
				m.Results.updateDiff()
				return m, nil
			}
			if key.Matches(k, m.Keys.Suspect) {
				m.Results.Suspect = m.Results.selectedResult()
				m.Results.updateDiff()
				return m, nil
			}
		}
		m.Results, cmd = m.Results.Update(msg)
	}

	cmds = append(cmds, cmd)
	return m, tea.Batch(cmds...)
}

func (m *Model) StartRace(req *models.CapturedRequest) tea.Cmd {
	ch := make(chan models.ScanResult, m.Concurrency+1)
	targetIP, port := ResolveTargetIPAndPort(req, m.Resolver)

	go func() {
		ctx, cancel := context.WithTimeout(m.Ctx, config.RaceTimeout)
		defer cancel()

		if (m.Strategy == "h1" || m.Strategy == "h2") && targetIP != "" {
			pc := packet.NewController(targetIP, port, m.Concurrency, m.Logger)
			if err := pc.Start(ctx); err == nil {
				defer pc.Close()
			}
		}

		attackReq := req.Clone()
		if targetIP != "" {
			if u, err := url.Parse(attackReq.URL); err == nil {
				if attackReq.Headers["Host"] == "" {
					attackReq.Headers["Host"] = u.Host
				}
				u.Host = net.JoinHostPort(targetIP, strconv.Itoa(port))
				attackReq.URL = u.String()
			}
		}

		switch m.Strategy {
		case "h3":
			m.Racer.RunH3Race(ctx, attackReq, m.Concurrency, ch)
		case "h2":
			m.Racer.RunH2Race(ctx, attackReq, m.Concurrency, ch)
		default:
			m.Racer.RunH1Race(ctx, attackReq, m.Concurrency, ch)
		}
	}()

	return m.waitForResult(ch)
}

func (m *Model) waitForResult(ch <-chan models.ScanResult) tea.Cmd {
	return func() tea.Msg {
		res, ok := <-ch
		if !ok {
			return RaceFinishedMsg{}
		}
		return tea.Batch(
			func() tea.Msg { return StreamResultMsg(res) },
			m.waitForResult(ch),
		)()
	}
}

func (m *Model) cycleStrategy() {
	switch m.Strategy {
	case "h2":
		m.Strategy = "h1"
	case "h1":
		m.Strategy = "h3"
	default:
		m.Strategy = "h2"
	}
}
