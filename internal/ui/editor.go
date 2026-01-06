// FILENAME: internal/ui/editor.go
package ui

import (
	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

type EditorModel struct {
	TextArea    textarea.Model
	OriginalReq *models.CapturedRequest
}

func NewEditorModel() EditorModel {
	ta := textarea.New()
	ta.Placeholder = "Request Body..."
	ta.Focus()
	return EditorModel{
		TextArea: ta,
	}
}

func (m EditorModel) Init(req *models.CapturedRequest) EditorModel {
	m.OriginalReq = req
	text := RequestToText(req)
	m.TextArea.SetValue(text)
	return m
}

func (m EditorModel) Update(msg tea.Msg) (EditorModel, tea.Cmd) {
	var cmd tea.Cmd
	m.TextArea, cmd = m.TextArea.Update(msg)
	return m, cmd
}

func (m EditorModel) View() string {
	return m.TextArea.View()
}

func (m EditorModel) ParseRequest() (*models.CapturedRequest, error) {
	return TextToRequest(m.TextArea.Value(), m.OriginalReq)
}

func (m *EditorModel) SetValue(s string) {
	m.TextArea.SetValue(s)
}

func (m *EditorModel) Value() string {
	return m.TextArea.Value()
}
