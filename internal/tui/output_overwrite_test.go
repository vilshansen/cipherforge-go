package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

// writeEncryptedFile encrypts plaintext into a real .cfo file at outputPath.
func writeEncryptedFile(t *testing.T, outputPath, plaintext, secret string) {
	t.Helper()

	f, err := os.Create(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := cipherforge.NewEncrypter([]byte(secret)).
		Encrypt(strings.NewReader(plaintext), f, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
}

// assertNoStagingFiles fails if a .cfo-* staging file was left behind.
func assertNoStagingFiles(t *testing.T, dir string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".cfo-") {
			t.Errorf("staging file %q was left behind", e.Name())
		}
	}
}

// drainTicks empties a progress channel so a worker goroutine cannot outlive the
// test.
func drainTicks(ch chan progressTickMsg) {
	if ch == nil {
		return
	}
	for range ch {
	}
}

// TestStartOperationRecordsOverwriteConsent pins the plumbing that connects the
// confirmation screen to the publish step: without it the TUI would have to
// guess whether the user ever agreed to replace anything.
func TestStartOperationRecordsOverwriteConsent(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	base := Model{
		operation:  "decrypt",
		inputFile:  input,
		outputFile: filepath.Join(dir, "out.txt"),
		width:      80,
		height:     24,
	}

	unconfirmed, _ := base.startOperation(false)
	m, ok := unconfirmed.(Model)
	if !ok {
		t.Fatalf("startOperation returned %T, want Model", unconfirmed)
	}
	if m.forceOverwrite {
		t.Error("forceOverwrite = true, but the user never confirmed an overwrite")
	}
	if m.screen != ScreenProgress {
		t.Errorf("screen = %v, want ScreenProgress", m.screen)
	}
	drainTicks(m.progressCh)

	confirmed, _ := base.startOperation(true)
	m2 := confirmed.(Model)
	if !m2.forceOverwrite {
		t.Error("forceOverwrite = false, but the user confirmed the overwrite")
	}
	drainTicks(m2.progressCh)

	// Consent must not leak into the next operation.
	m2.resetWorkflow()
	if m2.forceOverwrite {
		t.Error("resetWorkflow left the overwrite consent set")
	}
}

// TestRunEncryptRefusesToReplaceFileThatAppeared is the CF-2026-05 regression
// test for encryption: the TUI checked the output path once, before the
// confirmation screen and before the operation, so anything that appeared later
// was replaced without a word.
func TestRunEncryptRefusesToReplaceFileThatAppeared(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	output := filepath.Join(dir, "plain.txt.cfo")
	const occupied = "something the user cares about"

	if err := os.WriteFile(input, []byte("secret plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte(occupied), 0o600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan progressTickMsg, 256)
	err := runEncrypt(input, output, []byte(repairableSecret), false, false, ch)
	if err == nil {
		t.Fatal("runEncrypt replaced an existing output file without consent")
	}
	// The path is rendered with %q, so match the bare file name rather than the
	// escaped full path.
	if !strings.Contains(err.Error(), filepath.Base(output)) {
		t.Errorf("error %q should name the output file", err)
	}
	if got, _ := os.ReadFile(output); string(got) != occupied {
		t.Errorf("existing output was modified: %q", got)
	}
	assertNoStagingFiles(t, dir)
}

// TestRunDecryptRefusesToReplaceFileThatAppeared is the same test for the path
// where it matters most: decrypting archive.txt.cfo while archive.txt exists
// destroys the plaintext original.
func TestRunDecryptRefusesToReplaceFileThatAppeared(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")
	const occupied = "a different file that appeared meanwhile"

	writeEncryptedFile(t, cipherPath, "the original plaintext", repairableSecret)
	if err := os.WriteFile(output, []byte(occupied), 0o600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan progressTickMsg, 256)
	if _, err := runDecrypt(cipherPath, output, []byte(repairableSecret), false, false, ch); err == nil {
		t.Fatal("runDecrypt replaced an existing output file without consent")
	}
	if got, _ := os.ReadFile(output); string(got) != occupied {
		t.Errorf("existing output was modified: %q", got)
	}
	assertNoStagingFiles(t, dir)
}

// TestRunDecryptForceReplacesExistingFile checks the consented path still works:
// force comes from the overwrite-confirmation screen, and must behave like -f.
func TestRunDecryptForceReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")

	writeEncryptedFile(t, cipherPath, "the original plaintext", repairableSecret)
	if err := os.WriteFile(output, []byte("will be replaced"), 0o600); err != nil {
		t.Fatal(err)
	}

	ch := make(chan progressTickMsg, 256)
	if _, err := runDecrypt(cipherPath, output, []byte(repairableSecret), false, true, ch); err != nil {
		t.Fatalf("runDecrypt with consent = %v, want success", err)
	}
	if got, _ := os.ReadFile(output); string(got) != "the original plaintext" {
		t.Errorf("output = %q, want the decrypted plaintext", got)
	}
	assertNoStagingFiles(t, dir)
}

// TestRunDecryptRepairsAndPublishes guards the timing of the CF-2026-06 fix: the
// repaired secret must be zeroed after the retry decryption, not before it. If
// the wipe happened too early the Decrypter would derive keys from zero bytes
// and this test would fail with an authentication error.
func TestRunDecryptRepairsAndPublishes(t *testing.T) {
	dir := t.TempDir()
	cipherPath := filepath.Join(dir, "archive.txt.cfo")
	output := filepath.Join(dir, "archive.txt")

	writeEncryptedFile(t, cipherPath, "recovered plaintext", repairableSecret)

	ch := make(chan progressTickMsg, 256)
	corrected, err := runDecrypt(cipherPath, output, []byte(oneEditAway()), false, false, ch)
	if err != nil {
		t.Fatalf("runDecrypt with a one-edit secret = %v, want success", err)
	}
	if corrected != repairableSecret {
		t.Errorf("corrected secret = %q, want %q", corrected, repairableSecret)
	}
	if got, _ := os.ReadFile(output); string(got) != "recovered plaintext" {
		t.Errorf("output = %q, want the recovered plaintext", got)
	}
	assertNoStagingFiles(t, dir)
}
