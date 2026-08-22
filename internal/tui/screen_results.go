package tui

import (
	"fmt"
	"strings"

	"github.com/atotto/clipboard"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ResultsModel shows a summary after the operation completes.
// If the password was auto-generated, it is displayed prominently here.
type ResultsModel struct {
	operation   string
	inputFile   string
	outputFile  string
	success     bool
	err         error
	genPassword string
	outputText  string
	textMode    bool
	copiedPwd   bool
	copiedOut   bool
	width       int
	height      int
}

func buildResults(operation, inputFile, outputFile string, err error, genPassword, outputText string, textMode bool) ResultsModel {
	return ResultsModel{
		operation:   operation,
		inputFile:   inputFile,
		outputFile:  outputFile,
		success:     err == nil,
		err:         err,
		genPassword: genPassword,
		outputText:  outputText,
		textMode:    textMode,
	}
}

func (m *ResultsModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

var (
	successStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	failStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	pwdBoxStyle  = lipgloss.NewStyle().
			Padding(0, 2).
			Width(74)
	outBoxStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Width(74)
	pwdLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("226"))
	copiedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	hintIndent    = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
)

func (m ResultsModel) View() string {
	var b strings.Builder

	status := "Failed"
	statusStyle := failStyle
	if m.success {
		status = "Success"
		statusStyle = successStyle
	}

	b.WriteString(titleStyle.Render(fmt.Sprintf("%s — %s", strings.Title(m.operation), statusStyle.Render(status))))
	b.WriteString("\n\n")

	if m.textMode {
		if m.success && m.outputText != "" {
			label := "Encrypted (armored):"
			if m.operation == "decrypt" {
				label = "Decrypted text:"
			}
			b.WriteString(pwdLabelStyle.Render(label))
			b.WriteString("\n\n")

			text := m.outputText
			// Truncate long output so the heading stays on screen.
			if len(text) > 1000 {
				text = text[:1000] + " [...]"
			}

			if m.operation == "decrypt" {
				b.WriteString(outBoxStyle.Render(text))
			} else {
				b.WriteString(pwdBoxStyle.Render(text))
			}
			b.WriteString("\n\n")
			if m.copiedOut {
				b.WriteString(copiedStyle.Render("✓ Output copied to clipboard"))
			} else {
				b.WriteString(hintIndent.Render("Press Shift+C to copy output to clipboard"))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString(fmt.Sprintf("    Input:   %s\n", m.inputFile))
		b.WriteString(fmt.Sprintf("    Output:  %s\n", m.outputFile))
	}

	if m.err != nil {
		b.WriteString(errorStyle.Render(fmt.Sprintf("Error: %s", m.err.Error())))
		b.WriteString("\n")
	}

	if m.success && m.genPassword != "" {
		b.WriteString("\n")
		b.WriteString(pwdLabelStyle.Render("Generated password (save it; unrecoverable if lost):"))
		b.WriteString("\n\n")
		b.WriteString(pwdBoxStyle.Render(m.genPassword))
		b.WriteString("\n\n")
		if m.copiedPwd {
			b.WriteString(copiedStyle.Render("✓ Password copied to clipboard"))
		} else {
			b.WriteString(hintIndent.Render("Press c to copy password to clipboard"))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("enter/esc: return to main menu"))

	return b.String()
}

func (m Model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "enter", "esc":
		m.screen = ScreenMainMenu
		m.mainMenu = NewMainMenuModel(m.version, m.gitCommit)
		m.resetWorkflow()
		return m, nil

	case "c":
		if m.results.genPassword != "" {
			clipboard.WriteAll(m.results.genPassword)
			m.results.copiedPwd = true
		}
		return m, nil

	case "C":
		if m.results.outputText != "" {
			clipboard.WriteAll(m.results.outputText)
			m.results.copiedOut = true
		}
		return m, nil
	}

	return m, nil
}
