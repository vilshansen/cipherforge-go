package tui

import (
	"bytes"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vilshansen/cipherforge-go/internal/armor"
	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

// repairableSecret mirrors the shape of a generated secret: 45 pool characters
// in nine groups of five.
const repairableSecret = "8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k"

// oneEditAway returns a secret differing from repairableSecret in the last
// character.
func oneEditAway() string {
	return repairableSecret[:len(repairableSecret)-1] + "q"
}

func TestResultsShowsCorrectedSecret(t *testing.T) {
	m := Model{
		screen:  ScreenResults,
		width:   80,
		height:  24,
		results: buildResults("decrypt", "in.cfo", "out.txt", nil, "", "", false),
	}
	m.results.correctedSecret = repairableSecret
	m.results.SetSize(80, 24)

	view := m.View()
	if !strings.Contains(view, "Your secret was mistyped") {
		t.Errorf("results screen does not explain the mistyped secret:\n%s", view)
	}
	if !strings.Contains(view, repairableSecret) {
		t.Errorf("results screen does not show the corrected secret:\n%s", view)
	}
}

func TestResultsHidesCorrectedSecretOnFailure(t *testing.T) {
	m := Model{
		screen:  ScreenResults,
		width:   80,
		height:  24,
		results: buildResults("decrypt", "in.cfo", "out.txt", cipherforge.ErrNoRepair, "", "", false),
	}
	m.results.correctedSecret = repairableSecret
	m.results.SetSize(80, 24)

	if view := m.View(); strings.Contains(view, repairableSecret) {
		t.Errorf("failed operation must not display a corrected secret:\n%s", view)
	}
}

func TestResultsCopyKeyPrefersCorrectedSecret(t *testing.T) {
	m := Model{
		screen:  ScreenResults,
		width:   80,
		height:  24,
		results: buildResults("decrypt", "in.cfo", "out.txt", nil, "", "", false),
	}
	m.results.correctedSecret = repairableSecret
	m.results.SetSize(80, 24)

	updated, _ := m.updateResults(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
	got, ok := updated.(Model)
	if !ok {
		t.Fatalf("updateResults returned %T, want Model", updated)
	}
	if !got.results.copiedPwd {
		t.Error("pressing c should copy the corrected secret and mark it copied")
	}
	if view := got.View(); !strings.Contains(view, "Corrected secret copied") {
		t.Errorf("results screen does not confirm the copy:\n%s", view)
	}
}

func TestRunTextDecryptRecoversFromTypo(t *testing.T) {
	const plaintext = "recover this text"

	var raw bytes.Buffer
	if err := cipherforge.NewEncrypter([]byte(repairableSecret)).
		Encrypt(strings.NewReader(plaintext), &raw, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	armored, err := armor.EncodeBytes(raw.Bytes())
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}

	// Buffered so the progress sends from the worker cannot block.
	ch := make(chan progressTickMsg, 256)

	got, corrected, err := runTextDecrypt(armored, []byte(oneEditAway()), ch)
	if err != nil {
		t.Fatalf("runTextDecrypt with a one-character typo = %v, want success", err)
	}
	if got != plaintext {
		t.Errorf("decrypted %q, want %q", got, plaintext)
	}
	if corrected != repairableSecret {
		t.Errorf("corrected secret = %q, want %q", corrected, repairableSecret)
	}
}

func TestRunTextDecryptReportsNoCorrectionOnSuccess(t *testing.T) {
	const plaintext = "clean run"

	var raw bytes.Buffer
	if err := cipherforge.NewEncrypter([]byte(repairableSecret)).
		Encrypt(strings.NewReader(plaintext), &raw, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	armored, err := armor.EncodeBytes(raw.Bytes())
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}

	ch := make(chan progressTickMsg, 256)

	got, corrected, err := runTextDecrypt(armored, []byte(repairableSecret), ch)
	if err != nil {
		t.Fatalf("runTextDecrypt = %v, want success", err)
	}
	if got != plaintext {
		t.Errorf("decrypted %q, want %q", got, plaintext)
	}
	if corrected != "" {
		t.Errorf("corrected secret = %q, want empty for an exact secret", corrected)
	}
}

func TestRunTextDecryptFailsWhenNoCorrectionExists(t *testing.T) {
	var raw bytes.Buffer
	if err := cipherforge.NewEncrypter([]byte(repairableSecret)).
		Encrypt(strings.NewReader("payload"), &raw, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	armored, err := armor.EncodeBytes(raw.Bytes())
	if err != nil {
		t.Fatalf("armor encode: %v", err)
	}

	ch := make(chan progressTickMsg, 256)

	// Two characters wrong: outside the supported single-edit search.
	unrelated := "Zq7vT-bN2wX-9kPmR-4sJhL-cF6yD-gK8uE-aW3nZ-xV5tB-mQ2rS"
	got, corrected, err := runTextDecrypt(armored, []byte(unrelated), ch)
	if err == nil {
		t.Fatal("expected decryption with an unrelated secret to fail")
	}
	if got != "" || corrected != "" {
		t.Errorf("failed decryption returned (%q, %q), want empty results", got, corrected)
	}
}
