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
	scroll      int // line offset for the scrollable text view
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

// Box geometry for the scrollable results text view.
const (
	resultsBoxWidth     = 74
	resultsBoxHPad      = 2
	resultsContentWidth = resultsBoxWidth - 2*resultsBoxHPad // 70
)

// wrapResultsText wraps text to the results content width (70 columns),
// matching the width-74 output box with 2-char side padding. The returned
// lines are each exactly resultsContentWidth columns wide.
func wrapResultsText(text string) []string {
	if text == "" {
		return []string{}
	}
	lines := strings.Split(lipgloss.NewStyle().Width(resultsContentWidth).Render(text), "\n")
	// Lipgloss appends a trailing empty element after the final newline.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// textBoxViewport returns how many rows the scrollable output box should
// occupy so the whole results screen fits within the terminal height.
func (m ResultsModel) textBoxViewport() int {
	h := m.height
	if h <= 0 {
		h = 24
	}
	// Rows taken by everything except the output box: title block, label,
	// copy hint, footer help, and (when shown) the password section. One extra
	// row is reserved for the blank line under the title that appears when the
	// output needs scrolling. The top-level View adds screenTopPad blank lines
	// above every screen, so the box leaves that much room to fill the screen
	// exactly.
	fixed := resultsFixedLines
	if m.genPassword != "" {
		fixed += resultsPasswordLines
	}
	return max(1, h-fixed-1-screenTopPad)
}

const (
	// resultsFixedLines is the number of rows the results screen occupies
	// when the text box is absent (decrypt text, no auto-generated password).
	resultsFixedLines = 10
	// resultsPasswordLines is the extra rows added by the password section.
	resultsPasswordLines = 4
)

// maxScroll returns the largest valid scroll offset for the text view.
func (m ResultsModel) maxScroll() int {
	return max(0, len(wrapResultsText(m.outputText))-m.textBoxViewport())
}

// clampScroll keeps scroll within [0, maxScroll].
func (m *ResultsModel) clampScroll() {
	m.scroll = max(0, min(m.scroll, m.maxScroll()))
}

// scrollable reports whether the output text overflows the box and needs
// scrolling. When true, the results screen also adds a blank line under the
// title to separate it from the heading.
func (m ResultsModel) scrollable() bool {
	return m.textMode && m.success && m.outputText != "" && len(wrapResultsText(m.outputText)) > m.textBoxViewport()
}

// scrollbarThumb describes where the scrollbar thumb sits within its track.
type scrollbarThumb struct{ pos, size int }

// computeThumb computes a proportional thumb position and size for a track of
// `viewport` rows over `total` content rows at scroll offset `offset`.
func computeThumb(total, viewport, offset int) scrollbarThumb {
	if total <= viewport {
		return scrollbarThumb{}
	}
	size := max(1, viewport*viewport/total)
	if size > viewport {
		size = viewport
	}
	pos := 0
	if maxOff := total - viewport; maxOff > 0 {
		pos = offset * (viewport - size) / maxOff
	}
	return scrollbarThumb{pos: pos, size: size}
}

// renderTextBox renders the scrollable text view inside the 74-wide output
// box, with a scrollbar in the right gutter when the text overflows. The box
// hugs its content up to `viewport` rows, so short output doesn't leave a
// large empty rectangle in the middle of the screen; long output fills the
// viewport and scrolls.
func (m ResultsModel) renderTextBox(viewport int) string {
	lines := wrapResultsText(m.outputText)
	boxHeight := min(len(lines), viewport)
	if boxHeight < 1 {
		boxHeight = 1
	}
	scrollable := len(lines) > boxHeight
	m.clampScroll()
	start := m.scroll

	out := make([]string, 0, boxHeight)
	thumb := computeThumb(len(lines), boxHeight, start)
	for i := 0; i < boxHeight; i++ {
		var line string
		if idx := start + i; idx < len(lines) {
			// Content is left-aligned with the surrounding labels; the trailing
			// padding keeps the scrollbar anchored to the right edge.
			line = lines[idx] + strings.Repeat(" ", resultsBoxHPad*2)
		} else {
			line = strings.Repeat(" ", resultsBoxWidth)
		}
		if scrollable {
			glyph := '│'
			if i >= thumb.pos && i < thumb.pos+thumb.size {
				glyph = '█'
			}
			r := []rune(line)
			r[resultsBoxWidth-1] = glyph
			line = string(r)
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

var (
	successStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	failStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	// resultsTitleStyle mirrors titleStyle but without the bottom margin, so
	// the results screen can control spacing tightly around the output box.
	resultsTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("63"))
	pwdBoxStyle = lipgloss.NewStyle().
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

	b.WriteString(resultsTitleStyle.Render(fmt.Sprintf("%s — %s", strings.Title(m.operation), statusStyle.Render(status))))
	b.WriteString("\n")
	// Blank line separating the screen title from the heading below it.
	b.WriteString("\n")

	if m.textMode {
		if m.success && m.outputText != "" {
			label := "Encrypted (armored):"
			if m.operation == "decrypt" {
				label = "Decrypted text:"
			}
			b.WriteString(pwdLabelStyle.Render(label))
			b.WriteString("\n\n\n")
			b.WriteString(m.renderTextBox(m.textBoxViewport()))
			b.WriteString("\n\n\n")
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

	helpHint := "esc: return to main menu"
	if m.scrollable() {
		helpHint = "↑/↓/enter: scroll  •  pgup/pgdn: page  •  esc: return to main menu"
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render(helpHint))

	return b.String()
}

func (m Model) updateResults(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "esc":
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

	case "up", "k", "shift+tab":
		m.results.scroll--
		m.results.clampScroll()
		return m, nil

	case "down", "j", "tab", "enter":
		m.results.scroll++
		m.results.clampScroll()
		return m, nil

	case "pgup":
		m.results.scroll -= max(1, m.results.textBoxViewport()-1)
		m.results.clampScroll()
		return m, nil

	case "pgdown":
		m.results.scroll += max(1, m.results.textBoxViewport()-1)
		m.results.clampScroll()
		return m, nil

	case "home":
		m.results.scroll = 0
		return m, nil

	case "end":
		m.results.scroll = m.results.maxScroll()
		m.results.clampScroll()
		return m, nil
	}

	return m, nil
}
