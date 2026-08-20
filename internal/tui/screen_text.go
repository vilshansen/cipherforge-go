package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var textAreaStyle = lipgloss.NewStyle()

// TextInputModel lets the user type or paste multi-line text.
type TextInputModel struct {
	prompt string
	area   textarea.Model
	width  int
	height int
}

func NewTextInputModel(prompt string) TextInputModel {
	ta := textarea.New()
	ta.Placeholder = "Type or paste here..."
	ta.CharLimit = 0
	ta.ShowLineNumbers = false
	ta.SetWidth(70)
	ta.SetHeight(10)
	ta.Focus()

	return TextInputModel{
		prompt: prompt,
		area:   ta,
	}
}

func (m *TextInputModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	m.area.SetWidth(70)
	m.area.SetHeight(h - 8)
}

func (m TextInputModel) Init() tea.Cmd {
	return textarea.Blink
}

func (m TextInputModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(m.prompt))
	b.WriteString("\n\n")
	b.WriteString(textAreaStyle.Render(m.area.View()))
	b.WriteString("\n\n")
	b.WriteString(helpStyle.Render("ctrl+s: confirm  •  esc: back"))

	return b.String()
}

func (m Model) updateTextInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.textInput.area, cmd = m.textInput.area.Update(msg)
		return m, cmd
	}

	switch key.String() {
	case "esc":
		m.screen = ScreenMainMenu
		m.mainMenu = NewMainMenuModel(m.version, m.gitCommit)
		return m, nil

	case "ctrl+s":
		m.inputText = m.textInput.area.Value()
		if strings.TrimSpace(m.inputText) == "" {
			m.showError(fmt.Errorf("input cannot be empty"))
			return m, nil
		}
		m.passwordEntry = NewPasswordModel(m.operation, "text input")
		m.passwordEntry.textMode = true
		m.screen = ScreenPassword
		return m, m.passwordEntry.Init()
	}

	var cmd tea.Cmd
	m.textInput.area, cmd = m.textInput.area.Update(msg)
	return m, cmd
}
