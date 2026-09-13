package tui

import (
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ConfirmOverwriteModel asks the user before an operation replaces an existing
// file.
//
// The CLI refuses to overwrite unless -f is given, so the TUI must not clobber
// silently either. The case that matters most is decryption: decrypting
// archive.txt.cfo when archive.txt is still present would destroy an existing
// file the user did not know was in the way. The cursor starts on Cancel so a
// stray Enter cannot overwrite anything.
type ConfirmOverwriteModel struct {
	outputPath string
	focus      int // 0 = Cancel (default), 1 = Overwrite

	width  int
	height int
}

// NewConfirmOverwriteModel returns a confirmation prompt for the given path.
func NewConfirmOverwriteModel(outputPath string) ConfirmOverwriteModel {
	return ConfirmOverwriteModel{outputPath: outputPath}
}

func (m *ConfirmOverwriteModel) SetSize(w, h int) { m.width, m.height = w, h }
func (m ConfirmOverwriteModel) Init() tea.Cmd     { return nil }

// overwriteFocused reports whether the Overwrite option is selected.
func (m ConfirmOverwriteModel) overwriteFocused() bool { return m.focus == 1 }

func (m ConfirmOverwriteModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Overwrite existing file?"))
	b.WriteString("\n\n")
	b.WriteString(errorStyle.Render("This file already exists:"))
	b.WriteString("\n\n")
	b.WriteString("    " + shortenPath(m.outputPath, 68))
	b.WriteString("\n\n")
	b.WriteString(subtleStyle.Render("Overwriting it cannot be undone. The current contents are lost."))
	b.WriteString("\n\n")

	if m.overwriteFocused() {
		b.WriteString("    [Cancel]    ▶   [Overwrite]\n")
	} else {
		b.WriteString("▶   [Cancel]        [Overwrite]\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("←/→ or tab: choose  •  enter: confirm  •  n or esc: cancel  •  y: overwrite"))

	return b.String()
}

// updateConfirmOverwrite handles keys on the overwrite-confirmation screen.
func (m Model) updateConfirmOverwrite(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "left", "shift+tab":
		m.confirmOverwrite.focus = 0
		return m, nil

	case "right", "tab":
		m.confirmOverwrite.focus = 1
		return m, nil

	case "y":
		return m.startOperation(true)

	case "enter":
		if m.confirmOverwrite.overwriteFocused() {
			return m.startOperation(true)
		}
		return m.cancelOverwrite()

	case "n", "esc":
		return m.cancelOverwrite()
	}

	return m, nil
}

// cancelOverwrite returns to the secret screen. The typed secret is still in
// the sub-model, so the user does not have to enter it again.
func (m Model) cancelOverwrite() (tea.Model, tea.Cmd) {
	m.confirmOverwrite = ConfirmOverwriteModel{}
	m.screen = ScreenPassword
	return m, m.passwordEntry.Init()
}

// shortenPath trims a long path so it fits within max columns, preferring to
// keep the file name visible because that is the part the user recognises.
// Runes are counted rather than bytes so a multi-byte path is never cut in half.
func shortenPath(p string, max int) string {
	r := []rune(p)
	if len(r) <= max {
		return p
	}
	base := []rune(filepath.Base(p))
	if len(base)+4 <= max {
		return string(r[:max-len(base)-4]) + "..." + string(filepath.Separator) + string(base)
	}
	return "..." + string(r[len(r)-(max-3):])
}
