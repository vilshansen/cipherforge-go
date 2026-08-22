package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var textAreaStyle = lipgloss.NewStyle()

// maxTextLength caps how much text can be entered on the text screens.
const maxTextLength = 100_000

// confirmStyle highlights the discard-confirmation prompt on the text screen.
var confirmStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))

// TextInputModel lets the user type or paste multi-line text.
type TextInputModel struct {
	prompt         string
	area           textarea.Model
	confirmDiscard bool // true while asking to discard entered text
	atLimit        bool // true when the value has reached maxTextLength
	scrollY        int  // tracked viewport offset for the scrollbar
	width          int
	height         int
}

func NewTextInputModel(prompt string) TextInputModel {
	ta := textarea.New()
	ta.Placeholder = "Type or paste here..."
	ta.CharLimit = maxTextLength
	ta.ShowLineNumbers = false
	ta.SetWidth(70)
	ta.SetHeight(10)
	ta.Focus()

	return TextInputModel{
		prompt: prompt,
		area:   ta,
	}
}

// refreshLimit keeps atLimit in sync with the current value length. It uses
// the textarea's own Length() so the flag matches the enforced CharLimit.
func (m *TextInputModel) refreshLimit() {
	m.atLimit = m.area.Length() >= maxTextLength
}

// wrappedRowCount returns how many visual rows `text` occupies when wrapped to
// `width` columns. This is a cheap width-based estimate (rather than a full
// word-wrap render) so that pasting very long input stays responsive; it stays
// within a few rows of the textarea's own wrapping for typical text.
func wrappedRowCount(text string, width int) int {
	if width <= 0 {
		width = 1
	}
	if text == "" {
		return 1
	}
	n := lipgloss.Width(text)
	rows := n / width
	if n%width != 0 {
		rows++
	}
	if rows < 1 {
		rows = 1
	}
	return rows
}

// contentRows returns the number of visual rows the whole value occupies.
func (m TextInputModel) contentRows() int {
	width := m.area.Width()
	total := 0
	for _, ln := range strings.Split(m.area.Value(), "\n") {
		total += wrappedRowCount(ln, width)
	}
	return total
}

// cursorRow returns the visual row of the cursor within the whole content.
func (m TextInputModel) cursorRow() int {
	width := m.area.Width()
	row := 0
	for i, ln := range strings.Split(m.area.Value(), "\n") {
		if i == m.area.Line() {
			// A line no wider than the wrap width can't wrap, so the cursor
			// sits on its first row — skip the expensive LineInfo() call.
			if lipgloss.Width(ln) <= width {
				return row
			}
			return row + m.area.LineInfo().RowOffset
		}
		row += wrappedRowCount(ln, width)
	}
	return row
}

// syncScroll tracks the textarea's viewport offset using the same
// "keep the cursor in view" rule the textarea applies internally.
func (m *TextInputModel) syncScroll() {
	visible := m.area.Height()
	total := m.contentRows()
	if total <= visible {
		m.scrollY = 0
		return
	}
	cr := m.cursorRow()
	if cr < m.scrollY {
		m.scrollY = cr
	} else if cr > m.scrollY+visible-1 {
		m.scrollY = cr - (visible - 1)
	}
	if m.scrollY < 0 {
		m.scrollY = 0
	}
	if maxY := total - visible; m.scrollY > maxY {
		m.scrollY = maxY
	}
}

// withScrollbar overlays the same │/█ scrollbar used on the results screen
// along the right edge of the textarea view when the input overflows.
func (m TextInputModel) withScrollbar(view string, total int) string {
	lines := strings.Split(view, "\n")
	visible := len(lines)
	if visible < 1 {
		return view
	}
	thumb := computeThumb(total, visible, m.scrollY)
	out := make([]string, 0, len(lines))
	for i, ln := range lines {
		glyph := '│'
		if i >= thumb.pos && i < thumb.pos+thumb.size {
			glyph = '█'
		}
		out = append(out, ln+string(glyph))
	}
	return strings.Join(out, "\n")
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

	areaView := m.area.View()
	if total := m.contentRows(); total > m.area.Height() {
		areaView = m.withScrollbar(areaView, total)
	}
	b.WriteString(textAreaStyle.Render(areaView))
	b.WriteString("\n\n")

	if m.confirmDiscard {
		b.WriteString(confirmStyle.Render("Discard entered text?  y: discard  •  esc: keep editing"))
	} else if m.atLimit {
		b.WriteString(confirmStyle.Render(fmt.Sprintf("Maximum message length reached (%d chars)", maxTextLength)))
	} else {
		b.WriteString(helpStyle.Render("ctrl+s: confirm  •  esc: back"))
	}

	return b.String()
}

func (m Model) updateTextInput(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		var cmd tea.Cmd
		m.textInput.area, cmd = m.textInput.area.Update(msg)
		m.textInput.refreshLimit()
		m.textInput.syncScroll()
		return m, cmd
	}

	// While the discard prompt is showing, only y/n/esc have meaning.
	if m.textInput.confirmDiscard {
		switch key.String() {
		case "y", "Y":
			m.textInput.confirmDiscard = false
			m.screen = ScreenMainMenu
			m.mainMenu = NewMainMenuModel(m.version, m.gitCommit)
			return m, nil
		case "n", "N", "esc":
			m.textInput.confirmDiscard = false
			return m, nil
		default:
			return m, nil
		}
	}

	switch key.String() {
	case "esc":
		if strings.TrimSpace(m.textInput.area.Value()) == "" {
			m.screen = ScreenMainMenu
			m.mainMenu = NewMainMenuModel(m.version, m.gitCommit)
			return m, nil
		}
		m.textInput.confirmDiscard = true
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

	case "pgup", "pgdown":
		// Page up/down: move the cursor to a target one page above/below the
		// current viewport so the textarea's viewport scrolls with it, matching
		// the paging on the results screen.
		page := max(1, m.textInput.area.Height()-1)
		m.textInput.syncScroll()
		if key.String() == "pgup" {
			target := max(0, m.textInput.scrollY-page)
			for m.textInput.cursorRow() > target {
				m.textInput.area, _ = m.textInput.area.Update(tea.KeyMsg{Type: tea.KeyUp})
			}
		} else {
			last := m.textInput.contentRows() - 1
			target := min(last, m.textInput.scrollY+m.textInput.area.Height()-1+page)
			for m.textInput.cursorRow() < target {
				m.textInput.area, _ = m.textInput.area.Update(tea.KeyMsg{Type: tea.KeyDown})
			}
		}
		m.textInput.refreshLimit()
		m.textInput.syncScroll()
		return m, nil
	}

	var cmd tea.Cmd
	m.textInput.area, cmd = m.textInput.area.Update(msg)
	m.textInput.refreshLimit()
	m.textInput.syncScroll()
	return m, cmd
}
