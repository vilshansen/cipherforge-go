package tui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
)

// PasswordModel handles generated secrets for encryption and secret entry for
// decryption.
type PasswordModel struct {
	operation string
	inputFile string
	textMode  bool

	passwordInput textinput.Model
	autoGen       bool
	base64Enabled bool
	genPassword   string
	retryMsg      string
	focus         int

	width  int
	height int
}

func NewPasswordModel(operation, inputFile string) PasswordModel {
	ti := textinput.New()
	ti.Placeholder = "Enter password..."
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.Width = 70
	ti.Focus()

	return PasswordModel{
		operation:     operation,
		inputFile:     inputFile,
		passwordInput: ti,
		autoGen:       operation == "encrypt",
		focus:         0,
	}
}

func (m *PasswordModel) SetSize(w, h int) {
	m.width = w
	m.height = h
	m.passwordInput.Width = 70
}

func (m PasswordModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m PasswordModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(fmt.Sprintf("%s — Password", strings.Title(m.operation))))
	b.WriteString("\n")

	if !m.textMode {
		b.WriteString(subtleStyle.Render(fmt.Sprintf("File: %s", m.inputFile)))
		b.WriteString("\n")
	}

	// Retry message (shown after a failed decrypt attempt).
	if m.retryMsg != "" {
		b.WriteString(errorStyle.Render(m.retryMsg))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	if m.operation == "encrypt" {
		b.WriteString(subtleStyle.Render("A random secret will be generated and shown after encryption."))
		b.WriteString("\n\n")
		if !m.textMode {
			b.WriteString(m.checkbox("Base64 encode output", m.base64Enabled, m.focus == 0))
			b.WriteString("\n\n")
		}
	} else {
		label := "    Secret: "
		if m.focus == 0 {
			label = "▶   Secret: "
		}
		b.WriteString(label)
		b.WriteString(m.passwordInput.View())
		b.WriteString("\n\n")
		if !m.textMode {
			// File decrypt: base64 checkbox.
			b.WriteString(m.checkbox("Input is armored base64", m.base64Enabled, m.focus == 1))
			b.WriteString("\n\n")
		}
	}

	// Confirm button.
	confirmFocus := m.maxFocus() - 1
	if m.focus == confirmFocus {
		b.WriteString("▶   [Continue]\n")
	} else {
		b.WriteString("    [Continue]\n")
	}

	b.WriteString("\n")
	if m.isCheckboxFocus() {
		b.WriteString(helpStyle.Render("space/enter: toggle  •  ↑/↓ or tab: next  •  esc: back"))
	} else {
		b.WriteString(helpStyle.Render("enter: confirm  •  ↑/↓ or tab: next  •  esc: back"))
	}

	return b.String()
}

// checkbox renders a single checkbox line.
func (m PasswordModel) checkbox(label string, checked, focused bool) string {
	mark := "[ ]"
	style := lipgloss.NewStyle()
	if checked {
		mark = "[✓]"
		style = style.Bold(true).Foreground(lipgloss.Color("42"))
	}
	line := fmt.Sprintf("    %s %s", mark, label)
	if focused {
		line = "▶ " + line[2:]
	}
	return style.Render(line)
}

// updatePassword handles keyboard input for the password screen.
func (m Model) updatePassword(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		if m.passwordEntry.operation == "decrypt" && m.passwordEntry.focus == 0 {
			var cmd tea.Cmd
			m.passwordEntry.passwordInput, cmd = m.passwordEntry.passwordInput.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	switch key.String() {
	case "esc":
		if m.textMode {
			m.screen = ScreenTextInput
			return m, m.textInput.Init()
		}
		m.screen = ScreenFilePicker
		return m, nil

	case "tab", "down":
		m.passwordEntry.cycleFocus(1)
		return m, nil

	case "shift+tab", "up":
		m.passwordEntry.cycleFocus(-1)
		return m, nil

	case " ":
		m.passwordEntry.toggleFocused()
		return m, nil

	case "enter":
		if m.passwordEntry.isConfirmFocus() || (m.passwordEntry.operation == "decrypt" && m.passwordEntry.focus == 0) {
			return m.confirmPassword()
		}
		// Enter on a checkbox toggles it.
		m.passwordEntry.toggleFocused()
		return m, nil
	}

	if m.passwordEntry.operation == "decrypt" && m.passwordEntry.focus == 0 {
		m.passwordEntry.retryMsg = ""
		if key.String() == "enter" {
			return m.confirmPassword()
		}
		var cmd tea.Cmd
		m.passwordEntry.passwordInput, cmd = m.passwordEntry.passwordInput.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m *PasswordModel) maxFocus() int {
	if m.operation == "encrypt" {
		if m.textMode {
			return 1
		}
		return 2
	}
	if m.textMode {
		return 2
	}
	return 3
}

func (m *PasswordModel) isConfirmFocus() bool {
	return m.focus == m.maxFocus()-1
}

func (m *PasswordModel) isCheckboxFocus() bool {
	if m.operation == "encrypt" {
		return !m.textMode && m.focus == 0
	}
	return !m.textMode && m.focus == 1
}

func (m *PasswordModel) cycleFocus(dir int) {
	if m.operation == "decrypt" && m.focus == 0 {
		m.passwordInput.Blur()
	}
	max := m.maxFocus()
	m.focus = ((m.focus+dir)%max + max) % max
	if m.operation == "decrypt" && m.focus == 0 {
		m.passwordInput.Focus()
	}
}

func (m *PasswordModel) toggleFocused() {
	switch {
	case !m.textMode && m.operation == "encrypt" && m.focus == 0:
		m.base64Enabled = !m.base64Enabled
	case !m.textMode && m.operation != "encrypt" && m.focus == 1:
		m.base64Enabled = !m.base64Enabled
	}
}

func (m Model) confirmPassword() (tea.Model, tea.Cmd) {
	if m.operation == "encrypt" {
		m.passwordEntry.regenerate()
		m.password = []byte(m.passwordEntry.genPassword)
		m.genPassword = m.passwordEntry.genPassword
	} else {
		inputVal := m.passwordEntry.passwordInput.Value()
		if inputVal == "" {
			m.showError(fmt.Errorf("secret cannot be empty"))
			return m, nil
		}
		m.password = []byte(inputVal)
	}

	m.base64 = m.passwordEntry.base64Enabled

	if !m.textMode {
		if m.outputFile == "" {
			m.outputFile = deriveOutputPathTUI(m.operation, m.inputFile)
		}
		// Refuse to replace an existing file without asking. The CLI requires -f
		// for this and the TUI has no -f, so the user must confirm explicitly:
		// decrypting archive.txt.cfo while archive.txt still exists would
		// otherwise destroy a file they did not know was in the way.
		if m.outputFile != "-" {
			if _, err := os.Stat(m.outputFile); err == nil {
				m.confirmOverwrite = NewConfirmOverwriteModel(m.outputFile)
				m.screen = ScreenConfirmOverwrite
				return m, nil
			}
		}
	}

	return m.startOperation(false)
}

// startOperation launches the worker goroutine and switches to the progress
// screen. force reports whether the user has consented to replacing an existing
// output file: it is false when the output path was free at submit time, and
// true when the overwrite-confirmation screen was accepted. It reaches the
// publish step, so a file that appears at the output path during a long
// operation is refused rather than silently replaced.
func (m Model) startOperation(force bool) (tea.Model, tea.Cmd) {
	m.confirmOverwrite = ConfirmOverwriteModel{}
	m.forceOverwrite = force
	m.progress = NewProgressModel(m.operation, m.inputFile, m.outputFile)
	m.screen = ScreenProgress

	ch := make(chan progressTickMsg, 256)
	m.progressCh = ch
	go runOperation(m, ch)

	return m, waitForProgress(ch)
}

func (m *PasswordModel) regenerate() {
	pwd, err := crypto.GenerateSecret()
	if err != nil {
		return
	}
	// The secret is held as a string because the Bubble Tea render path is
	// string-only, and a string cannot be zeroed. Copying into a string
	// duplicates the secret, so the []byte original is wiped here immediately:
	// the copy is unavoidable and is about to be displayed anyway, but the
	// slice does not need to outlive it.
	m.genPassword = string(pwd)
	crypto.ZeroBytes(pwd)
}

func deriveOutputPathTUI(operation, inputFile string) string {
	if operation == "encrypt" {
		return inputFile + ".cfo"
	}
	if strings.HasSuffix(inputFile, ".cfo") {
		return strings.TrimSuffix(inputFile, ".cfo")
	}
	return inputFile + ".dec"
}
