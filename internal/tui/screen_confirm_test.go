package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// newOverwriteTestModel builds a model sitting on the password screen for a
// file operation, with the given input and output paths.
func newOverwriteTestModel(t *testing.T, operation, inputFile, outputFile string) Model {
	t.Helper()

	m := Model{
		screen:     ScreenPassword,
		width:      80,
		height:     24,
		operation:  operation,
		inputFile:  inputFile,
		outputFile: outputFile,
	}
	m.passwordEntry = NewPasswordModel(operation, inputFile)
	m.passwordEntry.focus = m.passwordEntry.maxFocus() - 1 // [Continue]
	if operation == "decrypt" {
		m.passwordEntry.passwordInput.SetValue("AAAAB-BBBBC-CCCCD-DDDDE-EEEEF-FFFFG-GGGGH-HHHHJ-JJJJK")
	}
	return m
}

// TestConfirmOverwriteAppearsWhenOutputExists covers the case the CLI guards
// with -f: decrypting archive.txt.cfo while archive.txt is still present must
// not silently destroy archive.txt.
func TestConfirmOverwriteAppearsWhenOutputExists(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")

	if err := os.WriteFile(input, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := newOverwriteTestModel(t, "decrypt", input, "")
	next, _ := m.confirmPassword()

	got := next.(Model)
	if got.screen != ScreenConfirmOverwrite {
		t.Fatalf("screen = %v, want ScreenConfirmOverwrite", got.screen)
	}
	if got.confirmOverwrite.outputPath != output {
		t.Errorf("confirmed path = %q, want %q", got.confirmOverwrite.outputPath, output)
	}
	// The cursor must land on Cancel so a stray Enter cannot overwrite.
	if got.confirmOverwrite.overwriteFocused() {
		t.Error("Overwrite is focused by default; Cancel must be the safe default")
	}
}

// TestConfirmOverwriteShownInView checks the prompt names the file and warns
// that the contents are lost.
func TestConfirmOverwriteShownInView(t *testing.T) {
	// A short path is shown in full.
	short := "C:/data/archive.txt"
	view := NewConfirmOverwriteModel(short).View()
	if !strings.Contains(view, short) {
		t.Errorf("view does not name the file being replaced:\n%s", view)
	}
	if !strings.Contains(view, "cannot be undone") {
		t.Errorf("view does not warn that the overwrite is irreversible:\n%s", view)
	}
	if !strings.Contains(view, "Cancel") || !strings.Contains(view, "Overwrite") {
		t.Errorf("view does not offer both choices:\n%s", view)
	}

	// A long path still identifies the file by name.
	long := filepath.Join(t.TempDir(), "deeply", "nested", "archive.txt")
	longView := NewConfirmOverwriteModel(long).View()
	if !strings.Contains(longView, "archive.txt") {
		t.Errorf("view does not name the file being replaced:\n%s", longView)
	}
}

// TestConfirmOverwriteSkippedWhenOutputFree checks that a free output path goes
// straight to the progress screen.
func TestConfirmOverwriteSkippedWhenOutputFree(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.txt.cfo")
	if err := os.WriteFile(input, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := newOverwriteTestModel(t, "decrypt", input, "")
	next, _ := m.confirmPassword()

	got := next.(Model)
	if got.screen != ScreenProgress {
		t.Fatalf("screen = %v, want ScreenProgress when the output does not exist", got.screen)
	}
}

// TestConfirmOverwriteCancelReturnsToPassword checks that cancelling leaves the
// typed secret intact and does not touch the file.
func TestConfirmOverwriteCancelReturnsToPassword(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")

	if err := os.WriteFile(input, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}

	secret := "AAAAB-BBBBC-CCCCD-DDDDE-EEEEF-FFFFG-GGGGH-HHHHJ-JJJJK"
	m := newOverwriteTestModel(t, "decrypt", input, "")
	next, _ := m.confirmPassword()
	confirming := next.(Model)

	for _, key := range []string{"n", "esc"} {
		cancelled, _ := confirming.updateConfirmOverwrite(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		got := cancelled.(Model)
		if got.screen != ScreenPassword {
			t.Errorf("%q: screen = %v, want ScreenPassword", key, got.screen)
		}
		if got.passwordEntry.passwordInput.Value() != secret {
			t.Errorf("%q: typed secret was lost", key)
		}
		if got.confirmOverwrite.outputPath != "" {
			t.Errorf("%q: confirmation state was not cleared", key)
		}
	}

	if data, _ := os.ReadFile(output); string(data) != "existing plaintext" {
		t.Errorf("cancel modified the file: %q", data)
	}
}

// TestConfirmOverwriteEnterOnCancelCancels checks that the default focus makes
// Enter safe: it cancels rather than overwriting.
func TestConfirmOverwriteEnterOnCancelCancels(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")

	if err := os.WriteFile(input, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := newOverwriteTestModel(t, "decrypt", input, "")
	next, _ := m.confirmPassword()
	confirming := next.(Model)

	cancelled, _ := confirming.updateConfirmOverwrite(tea.KeyMsg{Type: tea.KeyEnter})
	if got := cancelled.(Model); got.screen != ScreenPassword {
		t.Fatalf("Enter on Cancel moved to %v, want ScreenPassword", got.screen)
	}
}

// TestConfirmOverwriteAcceptStartsOperation checks that choosing Overwrite (or
// pressing y) proceeds to the progress screen.
func TestConfirmOverwriteAcceptStartsOperation(t *testing.T) {
	for _, useKey := range []bool{false, true} {
		dir := t.TempDir()
		input := filepath.Join(dir, "archive.txt.cfo")
		output := filepath.Join(dir, "archive.txt")

		if err := os.WriteFile(input, []byte("ciphertext"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, []byte("existing plaintext"), 0o600); err != nil {
			t.Fatal(err)
		}

		m := newOverwriteTestModel(t, "decrypt", input, "")
		next, _ := m.confirmPassword()
		confirming := next.(Model)

		var started tea.Model
		if useKey {
			started, _ = confirming.updateConfirmOverwrite(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("y")})
		} else {
			focused, _ := confirming.updateConfirmOverwrite(tea.KeyMsg{Type: tea.KeyRight})
			started, _ = focused.(Model).updateConfirmOverwrite(tea.KeyMsg{Type: tea.KeyEnter})
		}

		got := started.(Model)
		if got.screen != ScreenProgress {
			t.Fatalf("useKey=%v: screen = %v, want ScreenProgress", useKey, got.screen)
		}
		if got.progressCh == nil {
			t.Fatalf("useKey=%v: progress channel was not created", useKey)
		}
		// Drain the worker so it cannot outlive the test.
		for range got.progressCh {
		}
	}
}

// TestConfirmOverwriteSkippedForTextMode checks that text operations, which
// write nothing to disk, never prompt.
func TestConfirmOverwriteSkippedForTextMode(t *testing.T) {
	m := Model{
		screen:    ScreenPassword,
		width:     80,
		height:    24,
		operation: "encrypt",
		textMode:  true,
	}
	m.passwordEntry = NewPasswordModel("encrypt", "")
	m.passwordEntry.textMode = true
	m.passwordEntry.focus = m.passwordEntry.maxFocus() - 1

	next, _ := m.confirmPassword()
	if got := next.(Model); got.screen != ScreenProgress {
		t.Fatalf("screen = %v, want ScreenProgress for text mode", got.screen)
	}
	if next.(Model).progressCh != nil {
		for range next.(Model).progressCh {
		}
	}
}

func TestShortenPath(t *testing.T) {
	short := "a/b.txt"
	if got := shortenPath(short, 40); got != short {
		t.Errorf("short path was altered: %q", got)
	}

	long := "C:/very/long/directory/name/that/keeps/going/and/going/archive.txt"
	got := shortenPath(long, 40)
	if len([]rune(got)) > 40 {
		t.Errorf("shortened path is %d runes, want at most 40: %q", len([]rune(got)), got)
	}
	if !strings.Contains(got, "archive.txt") {
		t.Errorf("shortened path dropped the file name: %q", got)
	}
	if !strings.Contains(got, "...") {
		t.Errorf("shortened path does not look truncated: %q", got)
	}
}
