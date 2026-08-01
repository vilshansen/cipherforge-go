package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// FilePickerModel lets the user navigate the filesystem and select files.
// In single-select mode (decrypt), pressing enter on a file selects it.
// Supports type-ahead: typing characters jumps to matching entries.
type FilePickerModel struct {
	currentDir string
	entries    []dirEntry
	cursor     int
	singleOnly bool // true for decrypt (pick one .cfo file)

	// Scroll offset for large directories.
	scrollOffset int

	// Type-ahead search: accumulated keystrokes for jumping to matching entries.
	typeAhead string

	width  int
	height int
}

type dirEntry struct {
	name  string
	isDir bool
}

func NewFilePickerModel(singleOnly bool) FilePickerModel {
	dir, _ := os.Getwd()
	return FilePickerModel{
		currentDir: dir,
		singleOnly: singleOnly,
	}
}

func (m *FilePickerModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

func (m *FilePickerModel) Init() tea.Cmd {
	m.refreshEntries()
	return nil
}

func (m *FilePickerModel) refreshEntries() {
	m.entries = nil
	m.cursor = 0
	m.scrollOffset = 0

	entries, err := os.ReadDir(m.currentDir)
	if err != nil {
		return
	}

	for _, e := range entries {
		name := e.Name()
		// Skip hidden files/dirs (except . and ..).
		if strings.HasPrefix(name, ".") && name != "." && name != ".." {
			continue
		}
		entry := dirEntry{name: name, isDir: e.IsDir()}
		// In decrypt mode, only show directories and .cfo files.
		if m.singleOnly && !e.IsDir() && !strings.HasSuffix(strings.ToLower(name), ".cfo") {
			continue
		}
		// In encrypt mode, skip .cfo files to prevent double-encryption.
		if !m.singleOnly && !e.IsDir() && strings.HasSuffix(strings.ToLower(name), ".cfo") {
			continue
		}
		m.entries = append(m.entries, entry)
	}

	// Sort: directories first, then alphabetically.
	sort.Slice(m.entries, func(i, j int) bool {
		if m.entries[i].isDir != m.entries[j].isDir {
			return m.entries[i].isDir
		}
		return strings.ToLower(m.entries[i].name) < strings.ToLower(m.entries[j].name)
	})
}

// View renders the file picker.
func (m *FilePickerModel) View() string {
	var b strings.Builder

	// Title
	op := "encrypt"
	if m.singleOnly {
		op = "decrypt"
	}
	b.WriteString(titleStyle.Render(fmt.Sprintf("Select file to %s", op)))
	b.WriteString("\n")

	// Current directory
	dirDisplay := m.currentDir
	if len(dirDisplay) > m.width-4 && m.width > 10 {
		dirDisplay = "..." + dirDisplay[len(dirDisplay)-(m.width-7):]
	}
	b.WriteString(subtleStyle.Render(dirDisplay))
	b.WriteString("\n\n")

	// Visible area: height minus border+padding (4) and title/dir/blank/help (5).
	visibleRows := m.height - 9
	if visibleRows < 5 {
		visibleRows = 5
	}

	// Adjust scroll offset to keep cursor visible.
	if m.cursor < m.scrollOffset {
		m.scrollOffset = m.cursor
	}
	if m.cursor >= m.scrollOffset+visibleRows {
		m.scrollOffset = m.cursor - visibleRows + 1
	}

	endIdx := m.scrollOffset + visibleRows
	if endIdx > len(m.entries) {
		endIdx = len(m.entries)
	}

	for i := m.scrollOffset; i < endIdx; i++ {
		e := m.entries[i]
		cursor := "    "
		if i == m.cursor {
			cursor = "▶   "
		}

		style := lipgloss.NewStyle()
		if i == m.cursor {
			style = style.Bold(true).Foreground(lipgloss.Color("63"))
		}

		name := e.name
		if e.isDir {
			name = name + "/"
			style = style.Foreground(lipgloss.Color("39")) // blue for dirs
		}

		b.WriteString(fmt.Sprintf("%s%s\n", cursor, style.Render(name)))
	}

	if len(m.entries) == 0 {
		b.WriteString("    (empty directory)\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓: navigate  •  type to search  •  enter: open  •  backspace: up  •  esc: back  •  q: quit"))

	return b.String()
}

// jumpToMatch moves the cursor to the first entry whose name starts with the
// accumulated typeAhead string (case-insensitive). If no match is found the
// cursor stays where it is.
func (m *FilePickerModel) jumpToMatch() {
	if m.typeAhead == "" || len(m.entries) == 0 {
		return
	}
	for i, e := range m.entries {
		if strings.HasPrefix(strings.ToLower(e.name), m.typeAhead) {
			m.cursor = i
			return
		}
	}
	// No match — drop the last character and try again (allows backspacing
	// through type-ahead by just retyping).
	m.typeAhead = m.typeAhead[:len(m.typeAhead)-1]
	if m.typeAhead != "" {
		m.jumpToMatch()
	}
}

// updateFilePicker handles keyboard input for the file picker.
func (m Model) updateFilePicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	// Type-ahead: single printable characters jump to matching entries.
	if ks := key.String(); len(ks) == 1 && ks[0] >= 32 && ks[0] < 127 {
		m.filePicker.typeAhead += strings.ToLower(ks)
		m.filePicker.jumpToMatch()
		return m, nil
	}

	// Any other keypress resets the type-ahead buffer.
	m.filePicker.typeAhead = ""

	switch key.String() {
	case "up", "k":
		if m.filePicker.cursor > 0 {
			m.filePicker.cursor--
		}
		return m, nil

	case "down", "j":
		if m.filePicker.cursor < len(m.filePicker.entries)-1 {
			m.filePicker.cursor++
		}
		return m, nil

	case "backspace":
		// Go up one directory level.
		parent := filepath.Dir(m.filePicker.currentDir)
		if parent != m.filePicker.currentDir {
			m.filePicker.currentDir = parent
			m.filePicker.refreshEntries()
		}
		return m, nil

	case "esc":
		// Back to main menu.
		m.screen = ScreenMainMenu
		return m, nil

	case "enter":
		if len(m.filePicker.entries) == 0 {
			return m, nil
		}
		e := m.filePicker.entries[m.filePicker.cursor]
		if e.isDir {
			// Navigate into directory.
			m.filePicker.currentDir = filepath.Join(m.filePicker.currentDir, e.name)
			m.filePicker.refreshEntries()
			return m, nil
		}

		// Selected a file.
		fullPath := filepath.Join(m.filePicker.currentDir, e.name)
		m.inputFile = fullPath

		// Check the file is valid before proceeding.
		info, err := os.Stat(fullPath)
		if err != nil {
			m.showError(fmt.Errorf("cannot access %s: %w", e.name, err))
			return m, nil
		}
		if info.IsDir() {
			// Just in case (shouldn't happen due to the isDir check above).
			m.filePicker.currentDir = fullPath
			m.filePicker.refreshEntries()
			return m, nil
		}

		// Proceed to password screen.
		m.passwordEntry = NewPasswordModel(m.operation, fullPath)
		m.screen = ScreenPassword
		return m, m.passwordEntry.Init()

	default:
		return m, nil
	}
}
