// fileutils_test.go
package fileutils

import (
	"bytes"
	"os"
	"testing"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
)

// Test helper functions
func createTestFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "cipherforge_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	return tmpFile.Name()
}

func readFileContent(t *testing.T, filename string) string {
	t.Helper()
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}
	return string(content)
}

func cleanupFiles(t *testing.T, files ...string) {
	t.Helper()
	for _, file := range files {
		if file != "" {
			os.Remove(file)
		}
	}
}

func TestEncryptFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:     "successful encryption with user password",
			content:  "This is a test file content for encryption",
			password: "test-password-123",
			wantErr:  false,
		},
		{
			name:     "encrypt empty file",
			content:  "",
			password: "test-password",
			wantErr:  false,
		},
		{
			name:     "encrypt large content",
			content:  string(make([]byte, 1024*1024)), // 1MB of zeros
			password: "large-file-password",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test files
			inputFile := createTestFile(t, tt.content)
			outputFile := inputFile + ".encrypted"
			defer cleanupFiles(t, inputFile, outputFile)

			// Run encryption
			err := EncryptFile(inputFile, outputFile, tt.password)

			// Check results
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errContains != "" && err != nil && !contains(err.Error(), tt.errContains) {
					t.Errorf("EncryptFile() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			// Verify output file exists and has content
			stat, err := os.Stat(outputFile)
			if err != nil {
				t.Errorf("EncryptFile() output file doesn't exist: %v", err)
				return
			}

			// Encrypted file should be larger than original due to header and authentication tag
			if stat.Size() <= int64(len(tt.content)) {
				t.Errorf("EncryptFile() encrypted file size %d should be larger than original %d",
					stat.Size(), len(tt.content))
			}

			// Verify file is actually encrypted (not plaintext)
			encryptedContent, err := os.ReadFile(outputFile)
			if err != nil {
				t.Errorf("Failed to read encrypted file: %v", err)
				return
			}

			if string(encryptedContent) == tt.content {
				t.Error("EncryptFile() file was not encrypted - content matches original")
			}

			// Verify it starts with magic marker
			if !bytes.HasPrefix(encryptedContent, []byte(constants.MagicMarker)) {
				t.Error("EncryptFile() encrypted file doesn't start with magic marker")
			}
		})
	}
}

func TestEncryptFile_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		inputFile   string
		outputFile  string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name:        "non-existent input file",
			inputFile:   "/non/existent/path/file.txt",
			outputFile:  "output.enc",
			password:    "test",
			wantErr:     true,
			errContains: "kunne ikke åbne inputfil",
		},
		{
			name:        "invalid output path",
			inputFile:   createTestFile(t, "test"),
			outputFile:  "/invalid/path/output.enc",
			password:    "test",
			wantErr:     true,
			errContains: "kunne ikke oprette outputfil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if tt.inputFile != "/non/existent/path/file.txt" {
					cleanupFiles(t, tt.inputFile)
				}
			}()

			err := EncryptFile(tt.inputFile, tt.outputFile, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !contains(err.Error(), tt.errContains) {
					t.Errorf("EncryptFile() error = %v, want error containing %v", err, tt.errContains)
				}
			}
		})
	}
}

func TestDecryptFile(t *testing.T) {
	// First create an encrypted file to decrypt
	originalContent := "This is the original content to encrypt and decrypt"
	password := "test-decryption-password"

	t.Run("successful decryption with correct password", func(t *testing.T) {
		// Create and encrypt a test file
		inputFile := createTestFile(t, originalContent)
		encryptedFile := inputFile + ".enc"
		decryptedFile := inputFile + ".dec"

		defer cleanupFiles(t, inputFile, encryptedFile, decryptedFile)

		// Encrypt the file
		err := EncryptFile(inputFile, encryptedFile, password)
		if err != nil {
			t.Fatalf("Setup failed: could not encrypt file: %v", err)
		}

		// Decrypt the file
		err = DecryptFile(encryptedFile, decryptedFile, password)
		if err != nil {
			t.Errorf("DecryptFile() failed: %v", err)
			return
		}

		// Verify decrypted content matches original
		decryptedContent := readFileContent(t, decryptedFile)
		if decryptedContent != originalContent {
			t.Errorf("DecryptFile() decrypted content doesn't match original.\nGot: %q\nWant: %q",
				decryptedContent, originalContent)
		}
	})

	t.Run("decryption with wrong password", func(t *testing.T) {
		// Create and encrypt a test file
		inputFile := createTestFile(t, originalContent)
		encryptedFile := inputFile + ".enc"
		decryptedFile := inputFile + ".dec"

		defer cleanupFiles(t, inputFile, encryptedFile, decryptedFile)

		// Encrypt the file
		err := EncryptFile(inputFile, encryptedFile, password)
		if err != nil {
			t.Fatalf("Setup failed: could not encrypt file: %v", err)
		}

		// Try to decrypt with wrong password
		wrongPassword := "wrong-password-123"
		err = DecryptFile(encryptedFile, decryptedFile, wrongPassword)

		if err == nil {
			t.Error("DecryptFile() should have failed with wrong password")
			return
		}

		if !contains(err.Error(), "autentificering mislykkedes") {
			t.Errorf("DecryptFile() wrong error with incorrect password: %v", err)
		}
	})

	t.Run("decryption of non-encrypted file", func(t *testing.T) {
		// Create a plain text file (not encrypted)
		plainFile := createTestFile(t, "This is not encrypted")
		decryptedFile := plainFile + ".dec"

		defer cleanupFiles(t, plainFile, decryptedFile)

		err := DecryptFile(plainFile, decryptedFile, "any-password")

		if err == nil {
			t.Error("DecryptFile() should have failed with non-encrypted file")
			return
		}

		// Should fail at header reading or magic marker validation
		if !contains(err.Error(), "magic marker") && !contains(err.Error(), "header") {
			t.Errorf("DecryptFile() unexpected error with non-encrypted file: %v", err)
		}
	})

	t.Run("decryption with empty password", func(t *testing.T) {
		// This will trigger interactive password input, but we can test the path
		// by providing empty password and letting it try to read from terminal
		inputFile := createTestFile(t, originalContent)
		encryptedFile := inputFile + ".enc"
		decryptedFile := inputFile + ".dec"

		defer cleanupFiles(t, inputFile, encryptedFile, decryptedFile)

		err := EncryptFile(inputFile, encryptedFile, password)
		if err != nil {
			t.Fatalf("Setup failed: could not encrypt file: %v", err)
		}

		// This should trigger the interactive password path
		err = DecryptFile(encryptedFile, decryptedFile, "")

		// In test environment, term.ReadPassword will fail, so we expect an error
		if err == nil {
			t.Error("DecryptFile() should have failed with empty password in test environment")
		}
		// We don't check the specific error because it depends on the environment
	})
}

func TestDecryptFile_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string // Returns input file path
		outputFile  string
		password    string
		wantErr     bool
		errContains string
	}{
		{
			name: "non-existent input file",
			setup: func(t *testing.T) string {
				return "/non/existent/path/file.enc"
			},
			outputFile:  "output.dec",
			password:    "test",
			wantErr:     true,
			errContains: "kunne ikke åbne inputfil",
		},
		{
			name: "invalid output path",
			setup: func(t *testing.T) string {
				// Create a properly encrypted file for this test
				originalContent := "test content"
				password := "test-password"

				inputFile := createTestFile(t, originalContent)
				encryptedFile := inputFile + ".enc"

				err := EncryptFile(inputFile, encryptedFile, password)
				if err != nil {
					t.Fatalf("Setup failed: could not create encrypted file: %v", err)
				}

				// Clean up the original file, keep the encrypted one
				cleanupFiles(t, inputFile)
				return encryptedFile
			},
			outputFile:  "/invalid/path/that/does/not/exist/output.dec",
			password:    "test-password",
			wantErr:     true,
			errContains: "kunne ikke oprette outputfil",
		},
		{
			name: "corrupted encrypted file - invalid magic marker",
			setup: func(t *testing.T) string {
				// Create a file with some random data that's not properly encrypted
				corruptedFile := createTestFile(t, "this is not a valid encrypted file content")
				return corruptedFile
			},
			outputFile:  "output.dec",
			password:    "test",
			wantErr:     true,
			errContains: "ukendt filformat", // Matches the actual error message
		},
		{
			name: "truncated encrypted file",
			setup: func(t *testing.T) string {
				// Create a properly encrypted file first
				originalContent := "test content"
				password := "test-password"

				inputFile := createTestFile(t, originalContent)
				encryptedFile := inputFile + ".enc"

				err := EncryptFile(inputFile, encryptedFile, password)
				if err != nil {
					t.Fatalf("Setup failed: could not create encrypted file: %v", err)
				}

				// Read the encrypted file
				data, err := os.ReadFile(encryptedFile)
				if err != nil {
					t.Fatalf("Failed to read encrypted file: %v", err)
				}

				// Truncate the file (remove most of the content)
				truncatedFile := encryptedFile + ".truncated"
				err = os.WriteFile(truncatedFile, data[:50], 0644) // Only keep first 50 bytes
				if err != nil {
					t.Fatalf("Failed to write truncated file: %v", err)
				}

				cleanupFiles(t, inputFile, encryptedFile)
				return truncatedFile
			},
			outputFile:  "output.dec",
			password:    "test-password",
			wantErr:     true,
			errContains: "læsning", // Should fail at reading some part of the header
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile := tt.setup(t)
			defer func() {
				// Only clean up if it's not the non-existent file case
				if inputFile != "/non/existent/path/file.enc" {
					cleanupFiles(t, inputFile)
				}
				// Clean up output file if it was created despite error
				if tt.outputFile != "/invalid/path/that/does/not/exist/output.dec" && tt.outputFile != "output.dec" {
					cleanupFiles(t, tt.outputFile)
				}
			}()

			err := DecryptFile(inputFile, tt.outputFile, tt.password)

			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && tt.errContains != "" {
				if err == nil || !contains(err.Error(), tt.errContains) {
					t.Errorf("DecryptFile() error = %v, want error containing %v", err, tt.errContains)
				}
			}
		})
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		content  string
		password string
	}{
		{
			name:     "short text",
			content:  "Hello, World!",
			password: "simple-password",
		},
		{
			name:     "long text",
			content:  "This is a much longer text that should properly test the encryption and decryption round trip with various content lengths and patterns.",
			password: "longer-more-complex-password-123",
		},
		{
			name:     "special characters",
			content:  "Text with special chars: ñáéíóú 中文 русский 🌍",
			password: "password-with-special-chars!@#$",
		},
		{
			name:     "binary data",
			content:  string([]byte{0x00, 0x01, 0x02, 0x7F, 0x80, 0xFF, 0xFE, 0xFD}),
			password: "binary-password",
		},
		{
			name:     "empty content",
			content:  "",
			password: "empty-content-password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test files
			originalFile := createTestFile(t, tc.content)
			encryptedFile := originalFile + ".enc"
			decryptedFile := originalFile + ".dec"

			defer cleanupFiles(t, originalFile, encryptedFile, decryptedFile)

			// Encrypt
			err := EncryptFile(originalFile, encryptedFile, tc.password)
			if err != nil {
				t.Fatalf("EncryptFile failed: %v", err)
			}

			// Verify original and encrypted are different
			originalData, _ := os.ReadFile(originalFile)
			encryptedData, _ := os.ReadFile(encryptedFile)

			if bytes.Equal(originalData, encryptedData) {
				t.Error("Encrypted file should be different from original")
			}

			// Decrypt
			err = DecryptFile(encryptedFile, decryptedFile, tc.password)
			if err != nil {
				t.Fatalf("DecryptFile failed: %v", err)
			}

			// Verify decrypted matches original
			decryptedData, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("Failed to read decrypted file: %v", err)
			}

			if !bytes.Equal(originalData, decryptedData) {
				t.Errorf("Round-trip failed: decrypted content doesn't match original\nOriginal: %q\nDecrypted: %q",
					string(originalData), string(decryptedData))
			}
		})
	}
}

func TestGetRandomBytes(t *testing.T) {
	tests := []struct {
		name      string
		numBytes  int
		wantError bool
	}{
		{
			name:      "generate 16 bytes",
			numBytes:  16,
			wantError: false,
		},
		{
			name:      "generate 32 bytes",
			numBytes:  32,
			wantError: false,
		},
		{
			name:      "generate 0 bytes",
			numBytes:  0,
			wantError: false,
		},
		{
			name:      "generate 1024 bytes",
			numBytes:  1024,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			randomBytes, err := getRandomBytes(tt.numBytes)

			if (err != nil) != tt.wantError {
				t.Errorf("getRandomBytes() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if !tt.wantError {
				if len(randomBytes) != tt.numBytes {
					t.Errorf("getRandomBytes() length = %d, want %d", len(randomBytes), tt.numBytes)
				}

				// Verify bytes are not all zeros (extremely unlikely with crypto/rand)
				if tt.numBytes > 0 {
					allZero := true
					for _, b := range randomBytes {
						if b != 0 {
							allZero = false
							break
						}
					}
					if allZero {
						t.Error("getRandomBytes() returned all zeros")
					}
				}

				// Clean up
				defer cryptoutils.ZeroBytes(randomBytes)
			}
		})
	}
}

func TestEncryptFile_MemorySafety(t *testing.T) {
	// Test that sensitive data is properly zeroed
	// This is a behavioral test rather than a direct memory inspection
	originalContent := "Sensitive data that should be protected"
	password := "test-password"

	inputFile := createTestFile(t, originalContent)
	encryptedFile := inputFile + ".enc"

	defer cleanupFiles(t, inputFile, encryptedFile)

	// Capture any panics that might indicate memory issues
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("EncryptFile panicked: %v", r)
		}
	}()

	err := EncryptFile(inputFile, encryptedFile, password)
	if err != nil {
		t.Fatalf("EncryptFile failed: %v", err)
	}

	// If we get here without panics, memory management is likely working
	// In a real scenario, you might use more advanced techniques to verify
	// that memory was actually zeroed, but that's complex in Go tests
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// Add this to the test file for testing file header corruption
func TestDecryptFile_CorruptedHeader(t *testing.T) {
	// Create a valid encrypted file first
	originalContent := "Test content"
	password := "test-password"

	inputFile := createTestFile(t, originalContent)
	encryptedFile := inputFile + ".enc"

	defer cleanupFiles(t, inputFile, encryptedFile)

	err := EncryptFile(inputFile, encryptedFile, password)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Corrupt the magic marker in the encrypted file
	encryptedData, err := os.ReadFile(encryptedFile)
	if err != nil {
		t.Fatalf("Failed to read encrypted file: %v", err)
	}

	// Corrupt the first byte of magic marker
	encryptedData[0] = 'X'

	// Write corrupted data back
	err = os.WriteFile(encryptedFile, encryptedData, 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Try to decrypt corrupted file
	decryptedFile := encryptedFile + ".dec"
	err = DecryptFile(encryptedFile, decryptedFile, password)

	if err == nil {
		t.Error("DecryptFile should have failed with corrupted magic marker")
	} else if !contains(err.Error(), "magic marker") && !contains(err.Error(), "ukendt filformat") {
		t.Errorf("DecryptFile wrong error with corrupted header: %v", err)
	}

	cleanupFiles(t, decryptedFile)
}
