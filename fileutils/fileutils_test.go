package fileutils

import (
	"bytes"
	"os"
	"testing"
)

func TestEncryptionRoundTrip(t *testing.T) {
	plaintext := []byte("The quick brown fox jumps over the lazy dog.")
	pass := []byte("secure-test-pass")

	src := "test.txt"
	enc := "test.txt.cfo"
	dec := "test_dec.txt"

	os.WriteFile(src, plaintext, 0644)
	defer os.Remove(src)
	defer os.Remove(enc)
	defer os.Remove(dec)

	// Test Encrypt
	if err := EncryptFile(src, enc, pass); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Test Decrypt
	if err := DecryptFile(enc, dec, pass); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Compare Result
	decryptedData, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, decryptedData) {
		t.Error("Decrypted data does not match original plaintext")
	}
}
