// Package tui provides a full-screen terminal user interface for Cipherforge,
// built on the Bubble Tea framework (github.com/charmbracelet/bubbletea).
//
// The TUI guides the user through a workflow of screens:
//
//	Main Menu → File Picker → Password Entry → Progress → Results
//
// When the TUI exits, it returns a Config that the CLI entry point uses
// to execute the actual encryption/decryption via the existing engine.
//
// All encryption/decryption work happens inside the TUI with live progress
// bars. The TUI loops until the user explicitly quits (q from main menu or
// q anywhere).
//
// Design principles:
//   - Keep it simple: one concern per file, clear screen transitions.
//   - No CGo, no system dependencies — pure Go, statically linked.
//   - Keyboard-driven: arrow keys, Enter, Esc, Tab for everything.
//   - Graceful errors: show error messages in the TUI, never panic.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
)

// Screen identifies the current screen in the TUI workflow.
type Screen int

const (
	ScreenMainMenu Screen = iota
	ScreenFilePicker
	ScreenTextInput
	ScreenPassword
	ScreenProgress
	ScreenResults
)

// progressTickMsg carries a progress update from the encrypt/decrypt goroutine.
type progressTickMsg struct {
	bytes  int64
	done   bool
	err    error
	result string // text output for text mode operations
}

// Model is the top-level Bubble Tea model. It holds the current screen
// and delegates Update/View to the active screen's sub-model.
type Model struct {
	screen Screen
	width  int
	height int

	// Build metadata (passed from main).
	version   string
	gitCommit string

	// Workflow state accumulated across screens.
	operation  string
	inputFile  string
	outputFile string
	password   []byte
	base64     bool
	textMode   bool   // true for text encrypt/decrypt (not file)
	inputText  string // plaintext or base64 ciphertext from user
	outputText string // result text to display on results screen

	// Auto-generated password to display on the results screen.
	genPassword string

	// Progress channel for streaming ticks from the worker goroutine.
	progressCh chan progressTickMsg

	// Sub-models for each screen.
	mainMenu      MainMenuModel
	filePicker    FilePickerModel
	textInput     TextInputModel
	passwordEntry PasswordModel
	progress      ProgressModel
	results       ResultsModel

	// Error state: if set, display error and return to previous screen.
	err        error
	prevScreen Screen

	// Quitting: set to true when the user wants to exit.
	quitting bool
}

// shared styles used across all screens.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("63")).
			MarginBottom(1).
			MarginLeft(4)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1).
			MarginLeft(4)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true).
			MarginLeft(4)

	subtleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("243")).
			MarginLeft(4)
)

// Run launches the full-screen TUI. It loops until the user quits.
func Run(version, gitCommit string) error {
	m := Model{
		screen:    ScreenMainMenu,
		mainMenu:  NewMainMenuModel(version, gitCommit),
		version:   version,
		gitCommit: gitCommit,
		width:     80,
		height:    24,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// Init is the first Bubble Tea command. Each screen may have its own Init.
func (m Model) Init() tea.Cmd {
	return m.initForScreen()
}

func (m Model) initForScreen() tea.Cmd {
	switch m.screen {
	case ScreenMainMenu:
		return nil
	case ScreenFilePicker:
		return m.filePicker.Init()
	case ScreenTextInput:
		return m.textInput.Init()
	case ScreenPassword:
		return m.passwordEntry.Init()
	case ScreenProgress:
		return m.progress.Init()
	case ScreenResults:
		return nil
	default:
		return nil
	}
}

// Update handles messages from the Bubble Tea runtime. It delegates to the
// active screen's Update method and handles screen transitions.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		// Propagate size to sub-models.
		m.mainMenu.SetSize(msg.Width, msg.Height)
		m.filePicker.SetSize(msg.Width, msg.Height)
		m.passwordEntry.SetSize(msg.Width, msg.Height)
		m.progress.SetSize(msg.Width, msg.Height)
		m.results.SetSize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "q":
			if m.screen == ScreenMainMenu {
				m.quitting = true
				return m, tea.Quit
			}
		}

		if m.err != nil {
			m.screen = m.prevScreen
			m.err = nil
			return m, nil
		}

	case progressTickMsg:
		return m.handleProgressTick(msg)
	}

	// Delegate to the active screen.
	return m.updateScreen(msg)
}

func (m Model) updateScreen(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenMainMenu:
		return m.updateMainMenu(msg)
	case ScreenFilePicker:
		return m.updateFilePicker(msg)
	case ScreenTextInput:
		return m.updateTextInput(msg)
	case ScreenPassword:
		return m.updatePassword(msg)
	case ScreenProgress:
		return m.updateProgress(msg)
	case ScreenResults:
		return m.updateResults(msg)
	default:
		return m, nil
	}
}

// View renders the current screen.
func (m Model) View() string {
	var content string
	if m.err != nil {
		content = errorStyle.Render(fmt.Sprintf("Error: %s\n\nPress any key to continue...", m.err.Error()))
	} else {
		switch m.screen {
		case ScreenMainMenu:
			content = m.mainMenu.View()
		case ScreenFilePicker:
			content = m.filePicker.View()
		case ScreenTextInput:
			content = m.textInput.View()
		case ScreenPassword:
			content = m.passwordEntry.View()
		case ScreenProgress:
			content = m.progress.View()
		case ScreenResults:
			content = m.results.View()
		default:
			content = "Unknown screen"
		}
	}
	// Pad to fill the terminal height.
	if m.height > 0 {
		n := m.height - strings.Count(content, "\n") - 1
		if n > 0 {
			content += strings.Repeat("\n", n)
		}
	}
	return content
}

// showError temporarily displays an error message, then returns to prevScreen.
func (m *Model) showError(err error) {
	m.err = err
	m.prevScreen = m.screen
	m.screen = ScreenMainMenu // placeholder; View checks m.err first
}

// handleProgressTick processes a progress update from the worker goroutine.
// Only handles messages while still on the progress screen.
func (m Model) handleProgressTick(msg progressTickMsg) (tea.Model, tea.Cmd) {
	if m.screen != ScreenProgress {
		return m, nil
	}
	if msg.err != nil {
		if m.operation == "decrypt" {
			crypto.ZeroBytes(m.password)
			m.password = nil
			m.passwordEntry.retryMsg = "Wrong password or corrupt input — try again."
			m.screen = ScreenPassword
			return m, m.passwordEntry.Init()
		}
		m.results = buildResults(m.operation, m.inputFile, m.outputFile, msg.err, m.genPassword, m.outputText, m.textMode)
		m.results.SetSize(m.width, m.height)
		m.screen = ScreenResults
		return m, nil
	}
	if msg.done {
		if msg.result != "" {
			m.outputText = msg.result
		}
		m.results = buildResults(m.operation, m.inputFile, m.outputFile, nil, m.genPassword, m.outputText, m.textMode)
		m.results.SetSize(m.width, m.height)
		m.screen = ScreenResults
		return m, nil
	}
	m.progress.bytesProcessed = msg.bytes
	return m, waitForProgress(m.progressCh)
}

// waitForProgress returns a command that reads the next tick from the channel.
func waitForProgress(ch chan progressTickMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return progressTickMsg{done: true}
		}
		return msg
	}
}

// resetWorkflow clears per-operation state so the user can do another operation.
func (m *Model) resetWorkflow() {
	crypto.ZeroBytes(m.password)
	m.operation = ""
	m.inputFile = ""
	m.outputFile = ""
	m.password = nil
	m.base64 = false
	m.textMode = false
	m.inputText = ""
	m.outputText = ""
	m.genPassword = ""
}
