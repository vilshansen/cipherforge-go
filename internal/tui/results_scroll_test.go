package tui

import (
	"strconv"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// longResultsText returns a body of text long enough to overflow the
// results text box at typical terminal heights.
func longResultsText() string {
	return strings.Repeat("The quick brown fox jumps over the lazy dog. ", 200)
}

// scrollResults applies a key message to the results screen and returns the
// updated model (updateResults returns a tea.Model interface).
func scrollResults(m Model, msg tea.Msg) Model {
	got, _ := m.updateResults(msg)
	return got.(Model)
}

// TestResultsViewFitsHeight ensures the results screen renders exactly to the
// terminal height (including the top padding and bottom fill of the top-level
// View) for both decrypt (no password) and encrypt (password shown) modes
// across a range of terminal sizes. This guards the layout constants that the
// scrollable text box height is derived from.
func TestResultsViewFitsHeight(t *testing.T) {
	text := longResultsText()
	// Decrypt (no password) fits even on very short terminals; the encrypt
	// screen shows the password section too, so it needs a bit more room.
	decryptHeights := []int{15, 20, 24, 30, 40}
	encryptHeights := []int{20, 24, 30, 40}

	for _, h := range decryptHeights {
		t.Run("decrypt_h"+strconv.Itoa(h), func(t *testing.T) {
			m := Model{screen: ScreenResults, width: 80, height: h, results: buildResults("decrypt", "", "", nil, "", text, true)}
			m.results.SetSize(80, h)
			if got := strings.Count(m.View(), "\n") + 1; got != h {
				t.Errorf("decrypt rendered %d lines, want %d (viewport=%d)", got, h, m.results.textBoxViewport())
			}
		})
	}
	for _, h := range encryptHeights {
		t.Run("encrypt_h"+strconv.Itoa(h), func(t *testing.T) {
			m := Model{screen: ScreenResults, width: 80, height: h, results: buildResults("encrypt", "", "", nil, "PASS012345678901234567890123456789012345", text, true)}
			m.results.SetSize(80, h)
			if got := strings.Count(m.View(), "\n") + 1; got != h {
				t.Errorf("encrypt rendered %d lines, want %d (viewport=%d)", got, h, m.results.textBoxViewport())
			}
		})
	}
}

// TestResultsViewHeightStableAcrossScroll ensures the total rendered line
// count does not change as the user scrolls (no layout jump).
func TestResultsViewHeightStableAcrossScroll(t *testing.T) {
	text := longResultsText()
	base := buildResults("decrypt", "", "", nil, "", text, true)
	base.SetSize(80, 24)
	base.scroll = 0
	h0 := strings.Count(base.View(), "\n") + 1

	atEnd := buildResults("decrypt", "", "", nil, "", text, true)
	atEnd.SetSize(80, 24)
	atEnd.scroll = atEnd.maxScroll()
	hEnd := strings.Count(atEnd.View(), "\n") + 1

	if h0 != hEnd {
		t.Errorf("line count changed while scrolling: scroll=0 -> %d, scroll=max -> %d", h0, hEnd)
	}
}

// TestResultsScrollKeys verifies the scroll key handlers move the offset and
// clamp it within valid bounds.
func TestResultsScrollKeys(t *testing.T) {
	text := longResultsText()
	newModel := func() Model {
		m := Model{screen: ScreenResults, results: buildResults("decrypt", "", "", nil, "", text, true)}
		m.results.SetSize(80, 24)
		return m
	}

	t.Run("starts at top", func(t *testing.T) {
		m := newModel()
		if m.results.scroll != 0 {
			t.Fatalf("initial scroll = %d, want 0", m.results.scroll)
		}
		if m.results.maxScroll() == 0 {
			t.Fatal("test text should be scrollable")
		}
	})

	t.Run("down advances and up retreats", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyDown})
		if m.results.scroll != 1 {
			t.Errorf("down: scroll = %d, want 1", m.results.scroll)
		}
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyUp})
		if m.results.scroll != 0 {
			t.Errorf("up after down: scroll = %d, want 0", m.results.scroll)
		}
	})

	t.Run("j and k scroll", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
		if m.results.scroll != 1 {
			t.Errorf("j: scroll = %d, want 1", m.results.scroll)
		}
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("k")})
		if m.results.scroll != 0 {
			t.Errorf("k: scroll = %d, want 0", m.results.scroll)
		}
	})

	t.Run("enter scrolls down", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyEnter})
		if m.results.scroll != 1 {
			t.Errorf("enter: scroll = %d, want 1", m.results.scroll)
		}
	})

	t.Run("esc returns to main menu", func(t *testing.T) {
		m := newModel()
		got, _ := m.updateResults(tea.KeyMsg{Type: tea.KeyEsc})
		nm := got.(Model)
		if nm.screen != ScreenMainMenu {
			t.Errorf("esc: screen = %v, want ScreenMainMenu", nm.screen)
		}
	})

	t.Run("up at top stays at top", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyUp})
		if m.results.scroll != 0 {
			t.Errorf("up at top: scroll = %d, want 0", m.results.scroll)
		}
	})

	t.Run("down at bottom stays clamped", func(t *testing.T) {
		m := newModel()
		m.results.scroll = m.results.maxScroll()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyDown})
		if m.results.scroll != m.results.maxScroll() {
			t.Errorf("down at bottom: scroll = %d, want %d", m.results.scroll, m.results.maxScroll())
		}
	})

	t.Run("end and home jump", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyEnd})
		if m.results.scroll != m.results.maxScroll() {
			t.Errorf("end: scroll = %d, want %d", m.results.scroll, m.results.maxScroll())
		}
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyHome})
		if m.results.scroll != 0 {
			t.Errorf("home: scroll = %d, want 0", m.results.scroll)
		}
	})

	t.Run("pgdown pages forward", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyPgDown})
		want := m.results.textBoxViewport() - 1
		if m.results.scroll != want {
			t.Errorf("pgdown: scroll = %d, want %d", m.results.scroll, want)
		}
	})

	t.Run("pgup pages back", func(t *testing.T) {
		m := newModel()
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyPgDown})
		m = scrollResults(m, tea.KeyMsg{Type: tea.KeyPgUp})
		if m.results.scroll != 0 {
			t.Errorf("pgup after pgdown: scroll = %d, want 0", m.results.scroll)
		}
	})
}

// TestResultsShortTextNotScrollable ensures a short text that fits the box
// does not show a scrollbar and cannot be scrolled.
func TestResultsShortTextNotScrollable(t *testing.T) {
	short := "just a short line"
	m := Model{screen: ScreenResults, results: buildResults("decrypt", "", "", nil, "", short, true)}
	m.results.SetSize(80, 24)

	if m.results.maxScroll() != 0 {
		t.Fatalf("short text maxScroll = %d, want 0", m.results.maxScroll())
	}

	m = scrollResults(m, tea.KeyMsg{Type: tea.KeyDown})
	if m.results.scroll != 0 {
		t.Errorf("down on short text: scroll = %d, want 0", m.results.scroll)
	}

	view := m.results.View()
	if strings.Contains(view, "█") || strings.Contains(view, "│") {
		t.Error("short text should not render a scrollbar")
	}
}

// TestResultsScrollbarRenderedWhenOverflow ensures the scrollbar thumb is
// drawn in the right gutter when the text overflows the box.
func TestResultsScrollbarRenderedWhenOverflow(t *testing.T) {
	m := Model{screen: ScreenResults, results: buildResults("decrypt", "", "", nil, "", longResultsText(), true)}
	m.results.SetSize(80, 24)
	view := m.results.View()
	if !strings.Contains(view, "█") {
		t.Error("overflowing text should render a scrollbar thumb (█)")
	}
	if !strings.Contains(view, "│") {
		t.Error("overflowing text should render a scrollbar track (│)")
	}
	if !strings.Contains(view, "↑/↓/enter: scroll") {
		t.Error("help bar should mention scroll keys when text overflows")
	}
}

// TestResultsBoxAlignsWithLabels ensures the output box and password box
// content share the same left column as the surrounding labels.
func TestResultsBoxAlignsWithLabels(t *testing.T) {
	armor := "-----BEGIN CIPHERFORGE MESSAGE-----\nVersion: Cipherforge 1\n\nAAAA\n-----END CIPHERFORGE MESSAGE-----"
	m := Model{screen: ScreenResults, width: 80, height: 24, results: buildResults("encrypt", "", "", nil, "SECRETpassword123", armor, true)}
	m.results.SetSize(80, 24)

	cols := map[string]int{}
	for _, ln := range strings.Split(m.View(), "\n") {
		trimmed := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(trimmed, "Encrypted (armored):"):
			cols["label"] = strings.Index(ln, trimmed)
		case strings.HasPrefix(trimmed, "-----BEGIN"):
			cols["box"] = strings.Index(ln, trimmed)
		case strings.HasPrefix(trimmed, "Generated password"):
			cols["pwdlbl"] = strings.Index(ln, trimmed)
		case strings.HasPrefix(trimmed, "SECRETpassword"):
			cols["pwdbox"] = strings.Index(ln, trimmed)
		}
	}
	if cols["label"] != cols["box"] {
		t.Errorf("output box (col %d) not aligned with label (col %d)", cols["box"], cols["label"])
	}
	if cols["pwdlbl"] != cols["pwdbox"] {
		t.Errorf("password box (col %d) not aligned with its label (col %d)", cols["pwdbox"], cols["pwdlbl"])
	}
}

// TestResultsTitleSeparatedFromHeading ensures a blank line always separates
// the screen title from the heading below it.
func TestResultsTitleSeparatedFromHeading(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"long output", longResultsText()},
		{"short output", "short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Model{screen: ScreenResults, results: buildResults("decrypt", "", "", nil, "", tc.text, true)}
			m.results.SetSize(80, 24)
			lines := strings.Split(m.results.View(), "\n")
			if strings.TrimSpace(lines[0]) != "Decrypt — Success" {
				t.Fatalf("line 1 = %q, want title", strings.TrimSpace(lines[0]))
			}
			if strings.TrimSpace(lines[1]) != "" {
				t.Errorf("line 2 = %q, want blank (separator)", strings.TrimSpace(lines[1]))
			}
			if strings.TrimSpace(lines[2]) != "Decrypted text:" {
				t.Errorf("line 3 = %q, want heading", strings.TrimSpace(lines[2]))
			}
		})
	}
}
