package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestBuildResults(t *testing.T) {
	r := buildResults("encrypt", "in.txt", "out.cfo", nil, "pwd123", "base64out", true)
	if !r.success {
		t.Error("expected success when err is nil")
	}
	if r.genPassword != "pwd123" {
		t.Errorf("genPassword = %q, want %q", r.genPassword, "pwd123")
	}
	if r.outputText != "base64out" {
		t.Errorf("outputText = %q, want %q", r.outputText, "base64out")
	}
	if !r.textMode {
		t.Error("textMode should be true")
	}

	r2 := buildResults("decrypt", "in.cfo", "out.txt", nil, "", "", false)
	if !r2.success {
		t.Error("expected success")
	}
	if r2.textMode {
		t.Error("textMode should be false")
	}
	if r2.genPassword != "" {
		t.Errorf("genPassword should be empty, got %q", r2.genPassword)
	}
}

func TestDeriveOutputPathTUI(t *testing.T) {
	tests := []struct {
		op    string
		input string
		want  string
	}{
		{"encrypt", "doc.pdf", "doc.pdf.cfo"},
		{"decrypt", "doc.pdf.cfo", "doc.pdf"},
		{"decrypt", "doc.pdf", "doc.pdf.dec"},
		{"encrypt", "file", "file.cfo"},
		{"decrypt", "archive.tar.gz.cfo", "archive.tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.op+"_"+tt.input, func(t *testing.T) {
			got := deriveOutputPathTUI(tt.op, tt.input)
			if got != tt.want {
				t.Errorf("deriveOutputPathTUI(%q, %q) = %q, want %q", tt.op, tt.input, got, tt.want)
			}
		})
	}
}

func TestPasswordEscReturnsToTextInput(t *testing.T) {
	m := Model{
		screen:        ScreenPassword,
		operation:     "encrypt",
		textMode:      true,
		passwordEntry: NewPasswordModel("encrypt", "text input"),
		textInput:     NewTextInputModel("Enter text to encrypt:"),
	}
	m.passwordEntry.textMode = true

	got, cmd := m.updatePassword(tea.KeyMsg{Type: tea.KeyEsc})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("esc in text mode: screen = %v, want ScreenTextInput", nm.screen)
	}
	if cmd == nil {
		t.Error("esc in text mode: expected non-nil init command to restart cursor blink")
	}
}

func TestPasswordEscReturnsToFilePicker(t *testing.T) {
	m := Model{
		screen:        ScreenPassword,
		operation:     "decrypt",
		textMode:      false,
		passwordEntry: NewPasswordModel("decrypt", "/tmp/doc.cfo"),
		filePicker:    NewFilePickerModel(true),
	}

	got, _ := m.updatePassword(tea.KeyMsg{Type: tea.KeyEsc})
	nm := got.(Model)
	if nm.screen != ScreenFilePicker {
		t.Errorf("esc in file mode: screen = %v, want ScreenFilePicker", nm.screen)
	}
}

func TestErrorDismissReturnsToPreviousScreen(t *testing.T) {
	m := Model{
		screen:     ScreenMainMenu, // placeholder set by showError
		prevScreen: ScreenTextInput,
		err:        errors.New("input cannot be empty"),
		textInput:  NewTextInputModel("Enter text to encrypt:"),
	}

	got, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("screen = %v, want ScreenTextInput", nm.screen)
	}
	if nm.err != nil {
		t.Errorf("err should be cleared, got %v", nm.err)
	}
	if cmd == nil {
		t.Error("expected non-nil init command after error dismissal")
	}
}

func TestErrorDismissDoesNotQuitOnQ(t *testing.T) {
	m := Model{
		screen:     ScreenMainMenu, // placeholder set by showError
		prevScreen: ScreenTextInput,
		err:        errors.New("input cannot be empty"),
		textInput:  NewTextInputModel("Enter Text to Encrypt"),
	}

	got, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	nm := got.(Model)
	if nm.screen != ScreenTextInput {
		t.Errorf("screen = %v, want ScreenTextInput (q should dismiss error, not quit)", nm.screen)
	}
	if nm.quitting {
		t.Error("q on error screen should not quit")
	}
}

func TestDecryptedTextWraps(t *testing.T) {
	long := strings.Repeat("word ", 60) // 300 chars, single line
	m := buildResults("decrypt", "", "", nil, "", long, true)

	maxWidth := 0
	for _, ln := range strings.Split(m.View(), "\n") {
		if w := lipgloss.Width(ln); w > maxWidth {
			maxWidth = w
		}
	}

	if maxWidth > 78 {
		t.Errorf("decrypted text not wrapped: max line width = %d, want <= 78", maxWidth)
	}
}
