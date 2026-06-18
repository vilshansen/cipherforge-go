package cipherforge

import (
	"bytes"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/format"
)

// fastParams are lightweight Argon2id parameters to keep tests fast.
var fastParams = format.Argon2Params{
	Time:    1,
	Memory:  64 * 1024, // 64 MiB
	Threads: 1,
}

func TestRoundTrip(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("Hello, Cipherforge!")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	encrypted := out.Bytes()
	decIn := bytes.NewReader(encrypted)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	if err := dec.Decrypt(decIn, decOut, nil); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decOut.Bytes(), plaintext) {
		t.Errorf("got %q, want %q", decOut.Bytes(), plaintext)
	}
}

func TestEmptyFile(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decIn := bytes.NewReader(out.Bytes())
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	if err := dec.Decrypt(decIn, decOut, nil); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decOut.Len() != 0 {
		t.Errorf("expected empty output, got %d bytes", decOut.Len())
	}
}

func TestLargeFile(t *testing.T) {
	password := []byte("test-password")
	// 2.5 MB to test multiple segments
	plaintext := make([]byte, 2500000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decIn := bytes.NewReader(out.Bytes())
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	if err := dec.Decrypt(decIn, decOut, nil); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decOut.Bytes(), plaintext) {
		t.Error("round-trip failed for large file")
	}
}

func TestWrongPassword(t *testing.T) {
	password := []byte("correct-password")
	wrongPassword := []byte("wrong-password")
	plaintext := []byte("sensitive data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	enc.Encrypt(in, out, nil)

	decIn := bytes.NewReader(out.Bytes())
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(wrongPassword)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong password")
	}
	if err.Error() != "authentication failed" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestTamperDetection(t *testing.T) {
	password := []byte("password")
	plaintext := []byte("data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	enc.Encrypt(in, out, nil)

	data := out.Bytes()
	// Header is 64 bytes in v2 format. Tamper a byte in the payload region.
	data[80] ^= 0xFF

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected decryption to fail for tampered file")
	}
}

func TestV3RoundTrip(t *testing.T) {
	// Test v3 format round-trip: encrypt and decrypt a file.
	// v3 no longer supports v1/v2 files (breaking change).
	// To decrypt v1/v2 files, use v2.1.0.

	password := []byte("test-password")
	plaintext := []byte("hello")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decIn := bytes.NewReader(out.Bytes())
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	if err := dec.Decrypt(decIn, decOut, nil); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decOut.Bytes(), plaintext) {
		t.Errorf("v3 round-trip failed: got %q, want %q", decOut.Bytes(), plaintext)
	}
}
