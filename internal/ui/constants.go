// FILENAME: internal/ui/constants.go
package ui

import "github.com/charmbracelet/bubbles/key"

// State represents the application's global state.
type State int

const (
	StateIntercepting State = iota
	StateLoading
	StateEditing
	StateRunning
	StateResults
)

func (s State) String() string {
	switch s {
	case StateIntercepting:
		return "CAPTURE"
	case StateLoading:
		return "LOADING"
	case StateEditing:
		return "EDIT"
	case StateRunning:
		return "BUSY"
	case StateResults:
		return "RESULTS"
	default:
		return "UNKNOWN"
	}
}

// FilterMode determines which results are shown.
type FilterMode int

const (
	FilterAll FilterMode = iota
	FilterOutliers
)

// KeyMap defines the keybindings for the application.
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
