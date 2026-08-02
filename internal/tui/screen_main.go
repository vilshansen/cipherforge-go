package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// MainMenuModel is the first screen the user sees. It presents three choices:
// Encrypt, Decrypt, and Quit.
type MainMenuModel struct {
	width     int
	height    int
	choices   []string
	cursor    int
	version   string
	gitCommit string
}

func NewMainMenuModel(version, gitCommit string) MainMenuModel {
	return MainMenuModel{
		choices:   []string{"Encrypt file", "Decrypt file", "Encrypt text", "Decrypt text", "Quit"},
		cursor:    0,
		version:   version,
		gitCommit: gitCommit,
	}
}

func (m *MainMenuModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

func (m MainMenuModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Cipherforge"))
	b.WriteString("\n")

	// Version line: "cfo 4.0.0 (abc1234) — encrypt and decrypt files..."
	verLine := fmt.Sprintf("cfo %s", m.version)
	if m.gitCommit != "none" && m.gitCommit != "" {
		verLine += fmt.Sprintf(" (%s)", m.gitCommit)
	}
	verLine += " — encrypt and decrypt files with XChaCha20-Poly1305 and Argon2id."
	b.WriteString(subtleStyle.Render(verLine))
	b.WriteString("\n\n")

	for i, choice := range m.choices {
		cursor := "    "
		if m.cursor == i {
			cursor = "▶   "
		}
		style := lipgloss.NewStyle()
		if m.cursor == i {
			style = style.Bold(true).Foreground(lipgloss.Color("63"))
		}
		b.WriteString(fmt.Sprintf("%s%d. %s\n", cursor, i+1, style.Render(choice)))
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate  •  1-5: shortcut  •  enter: select  •  q: quit"))

	return b.String()
}

// updateMainMenu handles keyboard input for the main menu.
func (m Model) updateMainMenu(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "up", "k":
		if m.mainMenu.cursor > 0 {
			m.mainMenu.cursor--
		}
		return m, nil

	case "down", "j":
		if m.mainMenu.cursor < len(m.mainMenu.choices)-1 {
			m.mainMenu.cursor++
		}
		return m, nil

	case "1":
		m.mainMenu.cursor = 0
		return m.selectMenuOption()
	case "2":
		m.mainMenu.cursor = 1
		return m.selectMenuOption()
	case "3":
		m.mainMenu.cursor = 2
		return m.selectMenuOption()
	case "4":
		m.mainMenu.cursor = 3
		return m.selectMenuOption()
	case "5":
		m.mainMenu.cursor = 4
		return m.selectMenuOption()

	case "enter":
		return m.selectMenuOption()
	}

	return m, nil
}

func (m Model) selectMenuOption() (tea.Model, tea.Cmd) {
	switch m.mainMenu.cursor {
	case 0: // Encrypt file
		m.operation = "encrypt"
		m.filePicker = NewFilePickerModel(false)
		m.filePicker.SetSize(m.width, m.height)
		m.screen = ScreenFilePicker
		return m, m.filePicker.Init()
	case 1: // Decrypt file
		m.operation = "decrypt"
		m.filePicker = NewFilePickerModel(true)
		m.filePicker.SetSize(m.width, m.height)
		m.screen = ScreenFilePicker
		return m, m.filePicker.Init()
	case 2: // Encrypt text
		m.operation = "encrypt"
		m.textMode = true
		m.textInput = NewTextInputModel("Enter text to encrypt:")
		m.textInput.SetSize(m.width, m.height)
		m.screen = ScreenTextInput
		return m, m.textInput.Init()
	case 3: // Decrypt text
		m.operation = "decrypt"
		m.textMode = true
		m.textInput = NewTextInputModel("Paste base64-encoded ciphertext:")
		m.textInput.SetSize(m.width, m.height)
		m.screen = ScreenTextInput
		return m, m.textInput.Init()
	case 4: // Quit
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}
