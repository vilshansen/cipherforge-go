package cipherforge

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
)

// fastParams are lightweight Argon2id parameters to keep tests fast.
var fastParams = format.FastTestParams()

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
	// Header is 65 bytes in v4 format. Tamper a byte in the payload region.
	data[80] ^= 0xFF

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected decryption to fail for tampered file")
	}
}

func TestV4RoundTrip(t *testing.T) {
	// Test v4 format round-trip: encrypt and decrypt a file.

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
		t.Errorf("v4 round-trip failed: got %q, want %q", decOut.Bytes(), plaintext)
	}
}

func TestBatchEncryptionWithMasterKey(t *testing.T) {
	// Test the v4 batch optimisation: derive a master key once, reuse for
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

func TestExactSegmentBoundary(t *testing.T) {
	// Exactly 1 MiB: should produce exactly 1 segment.
	password := []byte("test-password")
	plaintext := make([]byte, 1048576) // 1 MiB exactly
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
		t.Error("round-trip failed for exact 1 MiB file")
	}
}

func TestOneByteOverSegmentBoundary(t *testing.T) {
	// 1 MiB + 1 byte: should produce 2 segments, the second with 1 byte.
	password := []byte("test-password")
	plaintext := make([]byte, 1048577) // 1 MiB + 1
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
		t.Error("round-trip failed for 1 MiB + 1 byte file")
	}
}

func TestSingleByteFile(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("X")

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
		t.Errorf("round-trip failed for single-byte file: got %q, want %q", decOut.Bytes(), plaintext)
	}
}

func TestProgressCallback(t *testing.T) {
	password := []byte("test-password")
	plaintext := make([]byte, 2500000) // 2.5 MB → 3 segments
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	// --- Encryption progress ---
	var encProgressValues []int64
	encProgress := func(bytesDone int64) {
		encProgressValues = append(encProgressValues, bytesDone)
	}

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, encProgress); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Progress should be reported after each segment.
	// 2.5 MB = 2 full 1 MiB segments + 1 partial = 3 callbacks.
	if len(encProgressValues) == 0 {
		t.Error("encryption progress callback was never called")
	}
	// Last progress value should equal total plaintext size.
	if encProgressValues[len(encProgressValues)-1] != int64(len(plaintext)) {
		t.Errorf("final encryption progress = %d, want %d",
			encProgressValues[len(encProgressValues)-1], len(plaintext))
	}
	// Values should be monotonically increasing.
	for i := 1; i < len(encProgressValues); i++ {
		if encProgressValues[i] <= encProgressValues[i-1] {
			t.Errorf("encryption progress not monotonic: %d after %d",
				encProgressValues[i], encProgressValues[i-1])
		}
	}

	// --- Decryption progress ---
	var decProgressValues []int64
	decProgress := func(bytesDone int64) {
		decProgressValues = append(decProgressValues, bytesDone)
	}

	decIn := bytes.NewReader(out.Bytes())
	decOut := &bytes.Buffer{}
	dec := NewDecrypter(password)
	if err := dec.Decrypt(decIn, decOut, decProgress); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decProgressValues) == 0 {
		t.Error("decryption progress callback was never called")
	}
	if decProgressValues[len(decProgressValues)-1] != int64(len(plaintext)) {
		t.Errorf("final decryption progress = %d, want %d",
			decProgressValues[len(decProgressValues)-1], len(plaintext))
	}
	for i := 1; i < len(decProgressValues); i++ {
		if decProgressValues[i] <= decProgressValues[i-1] {
			t.Errorf("decryption progress not monotonic: %d after %d",
				decProgressValues[i], decProgressValues[i-1])
		}
	}
}

func TestMagicTampering(t *testing.T) {
	password := []byte("test-password")
	plaintext := []byte("sensitive data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	data := out.Bytes()
	// Tamper the magic bytes (byte 0).
	data[0] = 0x00

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for tampered magic bytes")
	}
	if !strings.Contains(err.Error(), "not a valid .cfo file") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestHeaderSaltTampering(t *testing.T) {
	// Tampering the salt in the header should cause the trailer HMAC to fail.
	password := []byte("test-password")
	plaintext := []byte("sensitive data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Salt is at bytes 12-27. Flip a byte in the salt region.
	data := out.Bytes()
	data[15] ^= 0xFF

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected authentication failure for tampered salt")
	}
	if err.Error() != "authentication failed" {
		t.Errorf("expected 'authentication failed', got: %v", err)
	}
}

func TestHeaderSeedTampering(t *testing.T) {
	// Tampering the Segment Seed in the header should cause the trailer HMAC
	// to fail (because the seed is covered by the HMAC).
	password := []byte("test-password")
	plaintext := []byte("sensitive data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Segment Seed is at bytes 28-51. Flip a byte.
	data := out.Bytes()
	data[30] ^= 0xFF

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected authentication failure for tampered segment seed")
	}
}

func TestFileTooSmall(t *testing.T) {
	// A .cfo file must be at least 104 bytes (64 header + 40 trailer).
	// Feed the decoder a file that's too small.
	password := []byte("test-password")
	tooSmall := make([]byte, 50) // Way too small

	decIn := bytes.NewReader(tooSmall)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for file too small")
	}
}

func TestTruncatedBeforeTrailer(t *testing.T) {
	// Remove the trailer entirely: the file should fail trailer read.
	password := []byte("test-password")
	plaintext := []byte("some data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Truncate: remove the last 50 bytes (more than the 40-byte trailer).
	data := out.Bytes()
	data = data[:len(data)-50]

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for truncated file")
	}
}

func TestNewEncrypterRoundTrip(t *testing.T) {
	// Test the default constructor (NewEncrypter, not NewEncrypterWithParams).
	// This uses production-hardened Argon2id params, which are slow,
	// so keep the plaintext tiny.
	password := []byte("test-password")
	plaintext := []byte("tiny")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypter(password)
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
		t.Errorf("got %q, want %q", decOut.Bytes(), plaintext)
	}
}

func TestCorruptSegmentLength(t *testing.T) {
	// Craft a file where the segment length field is impossibly large.
	password := []byte("test-password")
	plaintext := []byte("data")

	in := bytes.NewReader(plaintext)
	out := &bytes.Buffer{}

	enc := NewEncrypterWithParams(password, fastParams)
	if err := enc.Encrypt(in, out, nil); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	data := out.Bytes()
	// The segment length is at byte 64 (right after the header).
	// Set it to an impossibly large value (max + 1).
	data[64+0] = 0x00
	data[64+1] = 0x10 // Make it much larger than valid range
	data[64+2] = 0x00
	data[64+3] = 0x00
	data[64+4] = 0x00
	data[64+5] = 0x00
	data[64+6] = 0x00
	data[64+7] = 0x00

	decIn := bytes.NewReader(data)
	decOut := &bytes.Buffer{}

	dec := NewDecrypter(password)
	err := dec.Decrypt(decIn, decOut, nil)
	if err == nil {
		t.Fatal("expected error for corrupt segment length")
	}
	if !strings.Contains(err.Error(), "corrupt segment") {
		t.Errorf("expected 'corrupt segment', got: %v", err)
	}
}
