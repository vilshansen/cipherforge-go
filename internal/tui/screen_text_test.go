package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// newTextModel returns a Model on the text-input screen with the given text
// already typed into the textarea.
func newTextModel(text string) Model {
	m := Model{
		screen:    ScreenTextInput,
		operation: "encrypt",
		textInput: NewTextInputModel("Enter Text to Encrypt"),
	}
	m.textInput.area.SetValue(text)
	return m
}

func TestTextInputEscWithEmptyTextGoesBack(t *testing.T) {
	m := newTextModel("")
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyEsc})
	nm := got.(Model)
	if nm.screen != ScreenMainMenu {
		t.Errorf("esc with empty text: screen = %v, want ScreenMainMenu", nm.screen)
	}
	if nm.textInput.confirmDiscard {
		t.Error("no confirmation expected when text is empty")
	}
}

func TestTextInputEscWithTextAsksConfirmation(t *testing.T) {
	m := newTextModel("hello world")
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyEsc})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("esc with text: screen = %v, want ScreenTextInput (stay to confirm)", nm.screen)
	}
	if !nm.textInput.confirmDiscard {
		t.Error("esc with text should set confirmDiscard")
	}
}

func TestTextInputConfirmYesDiscards(t *testing.T) {
	m := newTextModel("hello world")
	m.textInput.confirmDiscard = true
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
	nm := got.(Model)
	if nm.screen != ScreenMainMenu {
		t.Errorf("y on confirm: screen = %v, want ScreenMainMenu", nm.screen)
	}
	if nm.textInput.confirmDiscard {
		t.Error("confirmDiscard should be cleared after y")
	}
}

func TestTextInputConfirmNoKeepsEditing(t *testing.T) {
	m := newTextModel("hello world")
	m.textInput.confirmDiscard = true
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("n on confirm: screen = %v, want ScreenTextInput", nm.screen)
	}
	if nm.textInput.confirmDiscard {
		t.Error("n should clear confirmDiscard")
	}
	if nm.textInput.area.Value() != "hello world" {
		t.Errorf("text should be preserved, got %q", nm.textInput.area.Value())
	}
}

func TestTextInputConfirmEscKeepsEditing(t *testing.T) {
	m := newTextModel("hello world")
	m.textInput.confirmDiscard = true
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyEsc})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("esc on confirm: screen = %v, want ScreenTextInput", nm.screen)
	}
	if nm.textInput.confirmDiscard {
		t.Error("esc on confirm should cancel the prompt")
	}
}

func TestTextInputConfirmIgnoresOtherKeys(t *testing.T) {
	m := newTextModel("hello")
	m.textInput.confirmDiscard = true
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	nm := got.(Model)
	if !nm.textInput.confirmDiscard {
		t.Error("other keys while confirming should keep the prompt up")
	}
	if nm.textInput.area.Value() != "hello" {
		t.Errorf("text should not change while confirming, got %q", nm.textInput.area.Value())
	}
}

func TestTextInputConfirmPromptInView(t *testing.T) {
	m := newTextModel("hello")
	m.textInput.confirmDiscard = true
	view := m.textInput.View()
	if !strings.Contains(view, "Discard entered text?") {
		t.Error("confirmation prompt should appear in the view")
	}
	if strings.Contains(view, "ctrl+s: confirm") {
		t.Error("normal help bar should be replaced by the confirmation prompt")
	}
}

func TestTextInputMaxLengthSetsCharLimit(t *testing.T) {
	m := NewTextInputModel("Enter Text to Encrypt")
	if m.area.CharLimit != maxTextLength {
		t.Errorf("CharLimit = %d, want %d", m.area.CharLimit, maxTextLength)
	}
}

func TestTextInputAtLimitShowsMessage(t *testing.T) {
	m := newTextModel(strings.Repeat("a", maxTextLength))
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	nm := got.(Model)
	if !nm.textInput.atLimit {
		t.Error("at limit: atLimit should be true")
	}
	if len([]rune(nm.textInput.area.Value())) != maxTextLength {
		t.Errorf("value length = %d, want %d (should stay capped)", len([]rune(nm.textInput.area.Value())), maxTextLength)
	}
	view := nm.textInput.View()
	if !strings.Contains(view, "Maximum message length reached") {
		t.Error("view should show the maximum-length message at the limit")
	}
}

func TestTextInputBelowLimitNoMessage(t *testing.T) {
	m := newTextModel("short text")
	got, _ := m.updateTextInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	nm := got.(Model)
	if nm.textInput.atLimit {
		t.Error("below limit: atLimit should be false")
	}
	view := nm.textInput.View()
	if strings.Contains(view, "Maximum message length reached") {
		t.Error("view should not show the maximum-length message below the limit")
	}
}

func TestTextInputLimitClearsAfterDeleting(t *testing.T) {
	m := newTextModel(strings.Repeat("a", maxTextLength))
	// Delete one character so the value drops below the cap.
	for i := 0; i < 10; i++ {
		m = sendTextKey(m, tea.KeyMsg{Type: tea.KeyBackspace})
	}
	if m.textInput.atLimit {
		t.Error("atLimit should clear once the value drops below the limit")
	}
	view := m.textInput.View()
	if strings.Contains(view, "Maximum message length reached") {
		t.Error("view should not show the maximum-length message after deleting")
	}
}

// sendTextKey applies a key to the text-input screen and returns the updated model.
func sendTextKey(m Model, msg tea.Msg) Model {
	got, _ := m.updateTextInput(msg)
	return got.(Model)
}

func TestTextInputScrollbarShownWhenOverflow(t *testing.T) {
	m := newTextModel(strings.Repeat("line of text\n", 40)) // 40 rows > 16 visible
	m.textInput.SetSize(80, 24)
	m.textInput.syncScroll()
	view := m.textInput.View()
	if !strings.Contains(view, "█") {
		t.Error("long input should show a scrollbar thumb (█)")
	}
	if m.textInput.contentRows() <= m.textInput.area.Height() {
		t.Error("test input should overflow the visible area")
	}
}

func TestTextInputNoScrollbarWhenShort(t *testing.T) {
	m := newTextModel("short")
	m.textInput.SetSize(80, 24)
	m.textInput.syncScroll()
	view := m.textInput.View()
	if strings.Contains(view, "█") {
		t.Error("short input should not show a scrollbar thumb (█)")
	}
}

func TestTextInputScrollTracksCursor(t *testing.T) {
	m := newTextModel(strings.Repeat("line of text\n", 40))
	m.textInput.SetSize(80, 24)
	m.textInput.syncScroll()
	maxY := m.textInput.contentRows() - m.textInput.area.Height()
	if m.textInput.scrollY != maxY {
		t.Errorf("cursor at end: scrollY = %d, want %d", m.textInput.scrollY, maxY)
	}
	// Re-syncing from a stale offset must keep the cursor in view.
	m.textInput.scrollY = 0
	m.textInput.syncScroll()
	if m.textInput.scrollY != maxY {
		t.Errorf("resync: scrollY = %d, want %d", m.textInput.scrollY, maxY)
	}
}

func TestTextInputPgUpDownScrolls(t *testing.T) {
	m := newTextModel(strings.Repeat("line of text\n", 40))
	m.textInput.SetSize(80, 24)
	m.textInput.syncScroll()
	maxY := m.textInput.contentRows() - m.textInput.area.Height()

	// PgUp scrolls the view up by a page.
	m = sendTextKey(m, tea.KeyMsg{Type: tea.KeyPgUp})
	if m.textInput.scrollY >= maxY {
		t.Errorf("PgUp: scrollY = %d, want < %d (view should scroll up)", m.textInput.scrollY, maxY)
	}
	if m.textInput.scrollY == 0 {
		t.Errorf("PgUp from the end should not jump all the way to the top in one press")
	}

	// PgDn scrolls back down to the end.
	m = sendTextKey(m, tea.KeyMsg{Type: tea.KeyPgDown})
	if m.textInput.scrollY != maxY {
		t.Errorf("PgDn: scrollY = %d, want %d (view should scroll to the bottom)", m.textInput.scrollY, maxY)
	}
}

// BenchmarkContentRows guards the scroll-row counting against accidental
// regressions back to slow full-wrap rendering (which made large pastes lag).
func BenchmarkContentRows(b *testing.B) {
	m := newTextModel(strings.Repeat("The quick brown fox jumps over the lazy dog and keeps running. \n", 1000))
	m.textInput.SetSize(80, 24)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.textInput.contentRows()
	}
}
