package armor

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	original := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	armored, err := EncodeBytes(original)
	if err != nil {
		t.Fatalf("EncodeBytes: %v", err)
	}
	if !strings.HasPrefix(armored, Header+"\n") || !strings.HasSuffix(strings.TrimSpace(armored), Footer) {
		t.Fatalf("missing markers:\n%s", armored)
	}
	decoded, err := DecodeString(armored)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Errorf("round-trip mismatch: got %q, want %q", decoded, original)
	}
}

func TestWrapWidth(t *testing.T) {
	original := bytes.Repeat([]byte("CipherforgeArmorTestData!"), 8)
	armored, err := EncodeBytes(original)
	if err != nil {
		t.Fatalf("EncodeBytes: %v", err)
	}
	for _, line := range strings.Split(armored, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		if len(line) > BlockWidth {
			t.Errorf("line too long: %d > %d", len(line), BlockWidth)
		}
	}
}

func TestRejectBareBase64(t *testing.T) {
	// Bare (un-armored) base64 is no longer accepted — armor is required.
	if _, err := DecodeString("aGVsbG8gd29ybGQ="); err == nil {
		t.Error("expected error for bare base64 input")
	}
	if _, err := DecodeBytes([]byte("aGVsbG8gd29ybGQ=")); err == nil {
		t.Error("expected error for bare base64 input (DecodeBytes)")
	}
}

func TestArmorIncludesVersionAndChecksum(t *testing.T) {
	armored, err := EncodeBytes([]byte("header and checksum test"))
	if err != nil {
		t.Fatalf("EncodeBytes: %v", err)
	}
	if !strings.Contains(armored, "\n"+Version+"\n") {
		t.Errorf("missing Version header line:\n%s", armored)
	}
	foundChecksum := false
	for _, line := range strings.Split(armored, "\n") {
		if strings.HasPrefix(line, "=") {
			foundChecksum = true
		}
	}
	if !foundChecksum {
		t.Errorf("missing CRC-24 checksum line:\n%s", armored)
	}
}

func TestChecksumVerification(t *testing.T) {
	original := []byte("checksum verification data 1234567890")
	armored, err := EncodeBytes(original)
	if err != nil {
		t.Fatalf("EncodeBytes: %v", err)
	}
	// Tamper with the first character of the base64 body.
	i := strings.Index(armored, "\n\n") // end of the header block
	if i < 0 {
		t.Fatal("no header separator in armor")
	}
	bodyStart := i + 2
	if bodyStart >= len(armored) {
		t.Fatal("armor has no body")
	}
	tampered := armored[:bodyStart] + "X" + armored[bodyStart+1:]
	if _, err := DecodeString(tampered); err == nil {
		t.Error("expected error for tampered armor (checksum mismatch)")
	}
}
