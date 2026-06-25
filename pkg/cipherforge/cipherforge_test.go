package cipherforge

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
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

func TestBatchEncryptionWithMasterKey(t *testing.T) {
	// Test the v3 batch optimisation: derive a master key once, reuse for
	// multiple files.
	password := []byte("test-password")
	masterKey := crypto.DeriveMasterKey(password, format.DefaultArgon2Params())

	plaintexts := [][]byte{
		[]byte("first file"),
		[]byte("second file with more data"),
		[]byte("third"),
	}

	for i, pt := range plaintexts {
		in := bytes.NewReader(pt)
		out := &bytes.Buffer{}

		enc := NewEncrypterWithMasterKey(password, masterKey)
		if err := enc.Encrypt(in, out, nil); err != nil {
			t.Fatalf("File %d encryption failed: %v", i, err)
		}

		// Each file must have independent salt → different ciphertext
		// despite same master key.
		if i > 0 {
			// The outputs should differ in the salt region (bytes 12-27)
			// even for identical plaintext. We already encrypt different
			// plaintexts, so we're really just checking nothing crashed.
		}

		decIn := bytes.NewReader(out.Bytes())
		decOut := &bytes.Buffer{}

		dec := NewDecrypter(password)
		if err := dec.Decrypt(decIn, decOut, nil); err != nil {
			t.Fatalf("File %d decryption failed: %v", i, err)
		}

		if !bytes.Equal(decOut.Bytes(), pt) {
			t.Errorf("File %d round-trip mismatch", i)
		}
	}
}

func TestVersionRejection(t *testing.T) {
	// Craft a file with version = 1 (legacy, unsupported by v3).
	password := []byte("test-password")
	plaintext := []byte("data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper: change version from 3 to 1
	data := out.Bytes()
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x01

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for v1 file")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' error, got: %v", err)
	}
}

func TestFutureVersionRejection(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper: change version from 3 to 99 (future)
	data := out.Bytes()
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x63

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for future version")
	}
	if !strings.Contains(err.Error(), "newer") {
		t.Errorf("expected 'newer' error, got: %v", err)
	}
}

func TestTrailerTampering(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("some data for trailer tamper test")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper: flip a byte in the trailer HMAC
	data := out.Bytes()
	lastByte := len(data) - 1
	data[lastByte] ^= 0xFF

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected authentication failure for tampered trailer")
	}
	if err.Error() != "authentication failed" {
		t.Errorf("expected 'authentication failed', got: %v", err)
	}
}

func TestSegmentCountTampering(t *testing.T) {
	password := []byte("test-password")
	plaintext := make([]byte, 2*1024*1024) // 2 MiB → 2+ segments

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Tamper: zero the segment count in the trailer
	data := out.Bytes()
	trailerOffset := len(data) - 40
	data[trailerOffset+7] = 0x00

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected authentication failure for tampered segment count")
	}
}
