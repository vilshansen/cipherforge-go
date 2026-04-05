package fileutils

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/constants"
)

// TestMain sets minimal Argon2id parameters for the entire test binary.
// The production defaults (t=4, m=1GiB) allocate 1 GiB per DeriveKeys call,
// which causes the test suite to stall and be OOM-killed. These values still
// exercise the full Argon2id code path; they are just not hardened.
func TestMain(m *testing.M) {
	constants.Argon2Time = 1
	constants.Argon2Memory = 64 * 1024 // 64 MiB
	constants.Argon2Threads = 1
	os.Exit(m.Run())
}

func TestEncryptionRoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		plaintext []byte
		password  []byte
	}{
		{
			name:      "small file",
			plaintext: []byte("The quick brown fox jumps over the lazy dog."),
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "empty file",
			plaintext: []byte(""),
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "single byte",
			plaintext: []byte("X"),
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "exact segment size (1MB)",
			plaintext: bytes.Repeat([]byte("A"), constants.SegmentSize),
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "multiple segments",
			plaintext: bytes.Repeat([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), constants.SegmentSize/26*3),
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD, 0x00, 0xFF},
			password:  []byte("secure-test-pass"),
		},
		{
			name:      "long password",
			plaintext: []byte("test content"),
			password:  []byte("this-is-a-very-long-password-that-exceeds-typical-lengths"),
		},
		{
			name:      "unicode text",
			plaintext: []byte("Hello 世界 こんにちは 🌍"),
			password:  []byte("pass123"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(t.TempDir(), "test.txt")
			enc := filepath.Join(t.TempDir(), "test.txt.cfo")
			dec := filepath.Join(t.TempDir(), "test_dec.txt")

			if err := os.WriteFile(src, tc.plaintext, 0644); err != nil {
				t.Fatalf("Failed to create source file: %v", err)
			}

			if err := EncryptFile(src, enc, tc.password); err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			if err := DecryptFile(enc, dec, tc.password); err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			decryptedData, err := os.ReadFile(dec)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if !bytes.Equal(tc.plaintext, decryptedData) {
				t.Errorf("Decrypted data does not match original. Got length %d, want %d",
					len(decryptedData), len(tc.plaintext))
			}
		})
	}
}

func TestEncryptFileErrors(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() (src, dst string, password []byte)
		expectError bool
		errContains string
	}{
		{
			name: "nonexistent input file",
			setup: func() (string, string, []byte) {
				return "/nonexistent/file.txt", "output.cfo", []byte("pass")
			},
			expectError: true,
			errContains: "unable to open input file",
		},
		{
			name: "invalid output path",
			setup: func() (string, string, []byte) {
				src := filepath.Join(t.TempDir(), "src.txt")
				os.WriteFile(src, []byte("test"), 0644)
				return src, "/invalid/path/output.cfo", []byte("pass")
			},
			expectError: true,
			errContains: "unable to create output file",
		},
		{
			name: "empty password",
			setup: func() (string, string, []byte) {
				src := filepath.Join(t.TempDir(), "src.txt")
				os.WriteFile(src, []byte("test"), 0644)
				return src, filepath.Join(t.TempDir(), "output.cfo"), []byte("")
			},
			expectError: false, // Empty password is allowed but weak
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, dst, pass := tt.setup()
			err := EncryptFile(src, dst, pass)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectError && tt.errContains != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestDecryptFileErrors(t *testing.T) {
	// Create a valid encrypted file first
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "plain.txt")
	enc := filepath.Join(tempDir, "valid.cfo")
	password := []byte("test-password")

	if err := os.WriteFile(src, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(src, enc, password); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		setup       func() (input, output string, pass []byte)
		expectError bool
		errContains string
	}{
		{
			name: "nonexistent input file",
			setup: func() (string, string, []byte) {
				return "/nonexistent/file.cfo", "output.txt", password
			},
			expectError: true,
			errContains: "unable to open input file",
		},
		{
			name: "wrong password",
			setup: func() (string, string, []byte) {
				return enc, filepath.Join(tempDir, "output.txt"), []byte("wrong-password")
			},
			expectError: true,
			errContains: "authentication failed",
		},
		{
			name: "corrupted file - modified magic byte",
			setup: func() (string, string, []byte) {
				corrupted := filepath.Join(tempDir, "corrupted.cfo")
				data, _ := os.ReadFile(enc)
				if len(data) > 0 {
					data[0] ^= 0xFF // Flip bits in first byte (magic)
				}
				os.WriteFile(corrupted, data, 0644)
				return corrupted, filepath.Join(tempDir, "output.txt"), password
			},
			expectError: true,
			errContains: "not a valid .cfo file",
		},
		{
			name: "corrupted file - modified payload byte",
			setup: func() (string, string, []byte) {
				corrupted := filepath.Join(tempDir, "corrupted_payload.cfo")
				data, _ := os.ReadFile(enc)
				// Flip a byte well into the payload, past the 12-byte header
				if len(data) > 20 {
					data[20] ^= 0xFF
				}
				os.WriteFile(corrupted, data, 0644)
				return corrupted, filepath.Join(tempDir, "output2.txt"), password
			},
			expectError: true,
			errContains: "authentication failed",
		},
		{
			name: "truncated file",
			setup: func() (string, string, []byte) {
				truncated := filepath.Join(tempDir, "truncated.cfo")
				data, _ := os.ReadFile(enc)
				if len(data) > 100 {
					data = data[:len(data)-50]
				}
				os.WriteFile(truncated, data, 0644)
				return truncated, filepath.Join(tempDir, "output.txt"), password
			},
			expectError: true,
			// Truncation may trip the min-size check or the trailer read,
			// depending on how much data remains after removing 50 bytes.
			errContains: "file too small",
		},
		{
			name: "file too small",
			setup: func() (string, string, []byte) {
				small := filepath.Join(tempDir, "small.cfo")
				// 9 bytes: passes the 8-byte magic read but fails the magic
				// comparison, so the error is "not a valid .cfo file".
				os.WriteFile(small, []byte("too small"), 0644)
				return small, filepath.Join(tempDir, "output.txt"), password
			},
			expectError: true,
			errContains: "not a valid .cfo file",
		},
		{
			name: "wrong version",
			setup: func() (string, string, []byte) {
				wrongVer := filepath.Join(tempDir, "wrongver.cfo")
				data, _ := os.ReadFile(enc)
				// Bytes 8–11 are the version field. Set to version 99 (0x00000063).
				if len(data) >= 12 {
					data[8] = 0x00
					data[9] = 0x00
					data[10] = 0x00
					data[11] = 0x63
				}
				os.WriteFile(wrongVer, data, 0644)
				return wrongVer, filepath.Join(tempDir, "output.txt"), password
			},
			expectError: true,
			errContains: "unsupported file format version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, output, pass := tt.setup()
			err := DecryptFile(input, output, pass)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if tt.expectError && tt.errContains != "" && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestComputeTrailerHMAC(t *testing.T) {
	macKey := make([]byte, 32)
	salt := make([]byte, constants.SaltSize)
	masterNonce := make([]byte, constants.XNonceSize)
	rand.Read(macKey)
	rand.Read(salt)
	rand.Read(masterNonce)

	tests := []struct {
		name          string
		segmentCount  uint64
		modifyKey     bool
		modifySalt    bool
		modifyNonce   bool
		modifyCount   bool
		shouldMatch   bool
	}{
		{
			name:         "valid HMAC",
			segmentCount: 5,
			shouldMatch:  true,
		},
		{
			name:         "zero segments",
			segmentCount: 0,
			shouldMatch:  true,
		},
		{
			name:         "large segment count",
			segmentCount: 999999999999999999,
			shouldMatch:  true,
		},
		{
			name:         "wrong key",
			segmentCount: 5,
			modifyKey:    true,
			shouldMatch:  false,
		},
		{
			name:         "wrong salt",
			segmentCount: 5,
			modifySalt:   true,
			shouldMatch:  false,
		},
		{
			name:         "wrong nonce",
			segmentCount: 5,
			modifyNonce:  true,
			shouldMatch:  false,
		},
		{
			name:         "wrong count",
			segmentCount: 5,
			modifyCount:  true,
			shouldMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := macKey
			s := salt
			nonce := masterNonce
			count := tt.segmentCount

			if tt.modifyKey {
				key = make([]byte, 32)
				rand.Read(key)
			}
			if tt.modifySalt {
				s = make([]byte, constants.SaltSize)
				rand.Read(s)
			}
			if tt.modifyNonce {
				nonce = make([]byte, constants.XNonceSize)
				rand.Read(nonce)
			}
			if tt.modifyCount {
				count = tt.segmentCount + 1
			}

			// Compute HMAC with original parameters
			hmacOriginal, err := computeTrailerHMAC(macKey, salt, masterNonce, tt.segmentCount)
			if err != nil {
				t.Fatalf("computeTrailerHMAC failed: %v", err)
			}

			// Compute HMAC with modified parameters
			hmacModified, err := computeTrailerHMAC(key, s, nonce, count)
			if err != nil {
				t.Fatalf("computeTrailerHMAC failed: %v", err)
			}

			match := bytes.Equal(hmacOriginal, hmacModified)
			if match != tt.shouldMatch {
				t.Errorf("HMAC match = %v, want %v", match, tt.shouldMatch)
			}

			if len(hmacOriginal) != constants.HMACSize {
				t.Errorf("HMAC length = %d, want %d", len(hmacOriginal), constants.HMACSize)
			}
		})
	}
}

func TestDeriveSegmentNonce(t *testing.T) {
	masterNonce := make([]byte, constants.XNonceSize)
	rand.Read(masterNonce)

	tests := []struct {
		name           string
		segmentCounter uint64
		wantErr        bool
	}{
		{
			name:           "counter 0",
			segmentCounter: 0,
			wantErr:        false,
		},
		{
			name:           "counter 1",
			segmentCounter: 1,
			wantErr:        false,
		},
		{
			name:           "counter max uint64",
			segmentCounter: ^uint64(0),
			wantErr:        false,
		},
		{
			name:           "large counter",
			segmentCounter: 1234567890123456789,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce1, err := deriveSegmentNonce(masterNonce, tt.segmentCounter)
			if (err != nil) != tt.wantErr {
				t.Errorf("deriveSegmentNonce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(nonce1) != constants.XNonceSize {
					t.Errorf("Nonce length = %d, want %d", len(nonce1), constants.XNonceSize)
				}

				// Same counter should produce same nonce (deterministic)
				nonce2, _ := deriveSegmentNonce(masterNonce, tt.segmentCounter)
				if !bytes.Equal(nonce1, nonce2) {
					t.Error("deriveSegmentNonce not deterministic")
				}

				// Different counter should produce different nonce
				if tt.segmentCounter < ^uint64(0) {
					nonce3, _ := deriveSegmentNonce(masterNonce, tt.segmentCounter+1)
					if bytes.Equal(nonce1, nonce3) {
						t.Error("Different counters produced same nonce")
					}
				}
			}
		})
	}

	// Test with nil masterNonce (should still work, but not recommended)
	t.Run("nil masterNonce", func(t *testing.T) {
		nonce, err := deriveSegmentNonce(nil, 0)
		if err != nil {
			t.Errorf("Unexpected error with nil masterNonce: %v", err)
		}
		if len(nonce) != constants.XNonceSize {
			t.Errorf("Nonce length = %d, want %d", len(nonce), constants.XNonceSize)
		}
	})
}

func TestExpandInputPaths(t *testing.T) {
	// Create test directory structure
	tempDir := t.TempDir()

	// Create test files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		"secret.cfo",
		"archive.cfo",
		"data.bin",
		"subdir/nested.txt",
		"subdir/nested.cfo",
	}

	for _, f := range testFiles {
		path := filepath.Join(tempDir, f)
		if strings.Contains(f, "/") {
			os.MkdirAll(filepath.Dir(path), 0755)
		}
		os.WriteFile(path, []byte("test"), 0644)
	}

	// Create a subdirectory
	os.Mkdir(filepath.Join(tempDir, "emptydir"), 0755)

	tests := []struct {
		name        string
		inputs      []string
		operation   string
		expectCount int
		expectError bool
		checkFiles  []string
	}{
		{
			name:        "encrypt - single .txt file",
			inputs:      []string{filepath.Join(tempDir, "file1.txt")},
			operation:   "encrypt",
			expectCount: 1,
			expectError: false,
			checkFiles:  []string{"file1.txt"},
		},
		{
			name:        "encrypt - skip .cfo file",
			inputs:      []string{filepath.Join(tempDir, "secret.cfo")},
			operation:   "encrypt",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "decrypt - .cfo file",
			inputs:      []string{filepath.Join(tempDir, "secret.cfo")},
			operation:   "decrypt",
			expectCount: 1,
			expectError: false,
			checkFiles:  []string{"secret.cfo"},
		},
		{
			name:        "decrypt - skip .txt file",
			inputs:      []string{filepath.Join(tempDir, "file1.txt")},
			operation:   "decrypt",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "glob pattern - encrypt all .txt",
			inputs:      []string{filepath.Join(tempDir, "*.txt")},
			operation:   "encrypt",
			expectCount: 2, // file1.txt, file2.txt
			expectError: false,
			checkFiles:  []string{"file1.txt", "file2.txt"},
		},
		{
			name:        "glob pattern - decrypt all .cfo",
			inputs:      []string{filepath.Join(tempDir, "*.cfo")},
			operation:   "decrypt",
			expectCount: 2, // secret.cfo, archive.cfo
			expectError: false,
			checkFiles:  []string{"secret.cfo", "archive.cfo"},
		},
		{
			name:        "multiple inputs - mixed",
			inputs:      []string{filepath.Join(tempDir, "file1.txt"), filepath.Join(tempDir, "secret.cfo")},
			operation:   "encrypt",
			expectCount: 1, // only file1.txt
			expectError: false,
		},
		{
			name:        "nonexistent file",
			inputs:      []string{filepath.Join(tempDir, "nonexistent.txt")},
			operation:   "encrypt",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "glob with no matches",
			inputs:      []string{filepath.Join(tempDir, "*.xyz")},
			operation:   "encrypt",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "directory path",
			inputs:      []string{tempDir},
			operation:   "encrypt",
			expectCount: 0,
			expectError: true,
		},
		{
			name:        "nested glob",
			inputs:      []string{filepath.Join(tempDir, "subdir/*.txt")},
			operation:   "encrypt",
			expectCount: 1,
			expectError: false,
			checkFiles:  []string{"subdir/nested.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := ExpandInputPaths(tt.inputs, tt.operation)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if len(files) != tt.expectCount {
				t.Errorf("Got %d files, want %d", len(files), tt.expectCount)
			}

			for _, expectedFile := range tt.checkFiles {
				found := false
				for _, f := range files {
					if strings.HasSuffix(f, expectedFile) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected file %q not found in results", expectedFile)
				}
			}
		})
	}
}

func TestEncryptDecryptLargeFile(t *testing.T) {
	// Test with a file that spans multiple segments
	size := constants.SegmentSize*3 + 50000 // ~3.05 MB
	plaintext := make([]byte, size)
	rand.Read(plaintext)

	src := filepath.Join(t.TempDir(), "large.txt")
	enc := filepath.Join(t.TempDir(), "large.txt.cfo")
	dec := filepath.Join(t.TempDir(), "large_dec.txt")
	password := []byte("test-password")

	if err := os.WriteFile(src, plaintext, 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	if err := EncryptFile(src, enc, password); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if err := DecryptFile(enc, dec, password); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decrypted, err := os.ReadFile(dec)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Large file round trip failed. Got length %d, want %d",
			len(decrypted), len(plaintext))
	}
}

func TestEncryptDecryptWithDifferentPasswords(t *testing.T) {
	src := filepath.Join(t.TempDir(), "test.txt")
	enc := filepath.Join(t.TempDir(), "test.cfo")
	dec := filepath.Join(t.TempDir(), "dec.txt")
	plaintext := []byte("secret message")
	pass1 := []byte("correct-password")
	pass2 := []byte("wrong-password")

	os.WriteFile(src, plaintext, 0644)

	if err := EncryptFile(src, enc, pass1); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try decryption with wrong password
	if err := DecryptFile(enc, dec, pass2); err == nil {
		t.Error("Decryption with wrong password should fail")
	}

	// Decryption with correct password should work
	if err := DecryptFile(enc, dec, pass1); err != nil {
		t.Fatalf("Decryption with correct password failed: %v", err)
	}
}

func TestEncryptDecryptEmptyPassword(t *testing.T) {
	src := filepath.Join(t.TempDir(), "test.txt")
	enc := filepath.Join(t.TempDir(), "test.cfo")
	dec := filepath.Join(t.TempDir(), "dec.txt")
	plaintext := []byte("test content")
	emptyPass := []byte("")

	os.WriteFile(src, plaintext, 0644)

	if err := EncryptFile(src, enc, emptyPass); err != nil {
		t.Fatalf("Encryption with empty password failed: %v", err)
	}

	if err := DecryptFile(enc, dec, emptyPass); err != nil {
		t.Fatalf("Decryption with empty password failed: %v", err)
	}

	decrypted, _ := os.ReadFile(dec)
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Round trip with empty password failed")
	}
}

func TestConcurrentEncryptDecrypt(t *testing.T) {
	// Test that encryption/decryption can handle special characters in paths
	specialName := filepath.Join(t.TempDir(), "file with spaces and üñîçødê.txt")
	encName := specialName + ".cfo"
	decName := filepath.Join(t.TempDir(), "decoded.txt")
	plaintext := []byte("Content with special characters: !@#$%^&*()")
	password := []byte("test-pass")

	os.WriteFile(specialName, plaintext, 0644)

	if err := EncryptFile(specialName, encName, password); err != nil {
		t.Fatalf("Encryption with special path failed: %v", err)
	}

	if err := DecryptFile(encName, decName, password); err != nil {
		t.Fatalf("Decryption with special path failed: %v", err)
	}

	decrypted, _ := os.ReadFile(decName)
	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Round trip with special characters in path failed")
	}
}

// Benchmark tests
func BenchmarkEncryptFile(b *testing.B) {
	src := filepath.Join(b.TempDir(), "bench.txt")
	enc := filepath.Join(b.TempDir(), "bench.cfo")
	password := []byte("benchmark-password")

	// Create a 10MB test file
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)
	os.WriteFile(src, data, 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptFile(src, enc, password)
		os.Remove(enc)
	}
}

func BenchmarkDecryptFile(b *testing.B) {
	src := filepath.Join(b.TempDir(), "bench.txt")
	enc := filepath.Join(b.TempDir(), "bench.cfo")
	dec := filepath.Join(b.TempDir(), "bench_dec.txt")
	password := []byte("benchmark-password")

	// Create and encrypt a 10MB test file
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)
	os.WriteFile(src, data, 0644)
	EncryptFile(src, enc, password)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecryptFile(enc, dec, password)
		os.Remove(dec)
	}
}

func BenchmarkExpandInputPaths(b *testing.B) {
	tempDir := b.TempDir()
	for i := 0; i < 100; i++ {
		os.WriteFile(filepath.Join(tempDir, fmt.Sprintf("file%d.txt", i)), []byte("test"), 0644)
	}
	pattern := filepath.Join(tempDir, "*.txt")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ExpandInputPaths([]string{pattern}, "encrypt")
	}
}