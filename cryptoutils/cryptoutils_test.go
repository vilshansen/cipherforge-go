package cryptoutils

import (
	"bytes"
	"os"
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

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		salt     []byte
		wantLen  int
	}{
		{
			name:     "normal password and salt",
			password: []byte("test-password"),
			salt:     []byte("test-salt-12345678"),
			wantLen:  32,
		},
		{
			name:     "empty password",
			password: []byte(""),
			salt:     []byte("test-salt-12345678"),
			wantLen:  32,
		},
		{
			name:     "empty salt",
			password: []byte("test-password"),
			salt:     []byte(""),
			wantLen:  32,
		},
		{
			name:     "both empty",
			password: []byte(""),
			salt:     []byte(""),
			wantLen:  32,
		},
		{
			name:     "long password",
			password: []byte("this-is-a-very-long-password-that-exceeds-typical-lengths"),
			salt:     []byte("test-salt-12345678"),
			wantLen:  32,
		},
		{
			name:     "binary password data",
			password: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
			salt:     []byte("test-salt-12345678"),
			wantLen:  32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveKey(tt.password, tt.salt)
			if len(got) != tt.wantLen {
				t.Errorf("DeriveKey() length = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestDeriveKeys(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		salt     []byte
	}{
		{
			name:     "normal password and salt",
			password: []byte("test-password"),
			salt:     []byte("test-salt-12345678"),
		},
		{
			name:     "empty password",
			password: []byte(""),
			salt:     []byte("test-salt-12345678"),
		},
		{
			name:     "empty salt",
			password: []byte("test-password"),
			salt:     []byte(""),
		},
		{
			name:     "both empty",
			password: []byte(""),
			salt:     []byte(""),
		},
		{
			name:     "long password and salt",
			password: []byte("very-long-password-that-is-quite-lengthy-for-testing"),
			salt:     []byte("very-long-salt-value-that-exceeds-typical-length"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encKey, macKey := DeriveKeys(tt.password, tt.salt)

			if len(encKey) != 32 {
				t.Errorf("encKey length = %d, want 32", len(encKey))
			}
			if len(macKey) != 32 {
				t.Errorf("macKey length = %d, want 32", len(macKey))
			}

			// Keys should be different from each other
			if bytes.Equal(encKey, macKey) {
				t.Error("encKey and macKey should be different")
			}

			// Same inputs should produce same outputs
			encKey2, macKey2 := DeriveKeys(tt.password, tt.salt)
			if !bytes.Equal(encKey, encKey2) {
				t.Error("DeriveKeys not deterministic for encKey")
			}
			if !bytes.Equal(macKey, macKey2) {
				t.Error("DeriveKeys not deterministic for macKey")
			}
		})
	}

	// Test that different salts produce different keys
	t.Run("different salts produce different keys", func(t *testing.T) {
		password := []byte("test-password")
		salt1 := []byte("salt-12345678")
		salt2 := []byte("salt-87654321")

		encKey1, macKey1 := DeriveKeys(password, salt1)
		encKey2, macKey2 := DeriveKeys(password, salt2)

		if bytes.Equal(encKey1, encKey2) {
			t.Error("Different salts should produce different encKeys")
		}
		if bytes.Equal(macKey1, macKey2) {
			t.Error("Different salts should produce different macKeys")
		}
	})

	// Test that different passwords produce different keys
	t.Run("different passwords produce different keys", func(t *testing.T) {
		salt := []byte("test-salt-12345678")
		pass1 := []byte("password1")
		pass2 := []byte("password2")

		encKey1, macKey1 := DeriveKeys(pass1, salt)
		encKey2, macKey2 := DeriveKeys(pass2, salt)

		if bytes.Equal(encKey1, encKey2) {
			t.Error("Different passwords should produce different encKeys")
		}
		if bytes.Equal(macKey1, macKey2) {
			t.Error("Different passwords should produce different macKeys")
		}
	})
}

func TestGenerateSalt(t *testing.T) {
	tests := []struct {
		name      string
		wantSize  int
		wantError bool
	}{
		{
			name:      "generate valid salt",
			wantSize:  constants.SaltSize,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSalt()
			if (err != nil) != tt.wantError {
				t.Errorf("GenerateSalt() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if len(got) != tt.wantSize {
				t.Errorf("GenerateSalt() length = %d, want %d", len(got), tt.wantSize)
			}

			// Generate multiple salts and ensure they're different
			salt2, _ := GenerateSalt()
			if bytes.Equal(got, salt2) {
				t.Error("GenerateSalt() should produce unique salts")
			}
		})
	}
}

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		name      string
		wantSize  int
		wantError bool
	}{
		{
			name:      "generate valid nonce",
			wantSize:  constants.XNonceSize,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateNonce()
			if (err != nil) != tt.wantError {
				t.Errorf("GenerateNonce() error = %v, wantError %v", err, tt.wantError)
				return
			}
			if len(got) != tt.wantSize {
				t.Errorf("GenerateNonce() length = %d, want %d", len(got), tt.wantSize)
			}

			// Generate multiple nonces and ensure they're different
			nonce2, _ := GenerateNonce()
			if bytes.Equal(got, nonce2) {
				t.Error("GenerateNonce() should produce unique nonces")
			}
		})
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid length 10",
			length:  10,
			wantErr: false,
		},
		{
			name:    "valid length 20",
			length:  20,
			wantErr: false,
		},
		{
			name:    "valid length 32",
			length:  32,
			wantErr: false,
		},
		{
			name:    "valid length 1",
			length:  1,
			wantErr: false,
		},
		{
			name:        "zero length",
			length:      0,
			wantErr:     true,
			errContains: "length must be positive",
		},
		{
			name:        "negative length",
			length:      -5,
			wantErr:     true,
			errContains: "length must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSecurePassword(tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecurePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err != nil && tt.errContains != "" {
					if !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
						t.Errorf("Error message %q should contain %q", err.Error(), tt.errContains)
					}
				}
				return
			}

			// Check that hyphens are inserted correctly
			// Format: groups of 5 characters separated by hyphens
			// Example: "ABCDE-FGHIJ-KLMNO" (length 15 -> 5 chars, hyphen, 5 chars, hyphen, 5 chars)
			expectedGroups := (tt.length + 4) / 5 // ceil(length/5)
			expectedHyphens := expectedGroups - 1
			
			// Count actual hyphens
			hyphenCount := 0
			for _, c := range got {
				if c == '-' {
					hyphenCount++
				}
			}
			
			if hyphenCount != expectedHyphens {
				t.Errorf("Expected %d hyphens, got %d", expectedHyphens, hyphenCount)
			}
			
			// Check that hyphens are at the correct positions
			// After every 5th character, except at the end
			hyphenPositions := make(map[int]bool)
			for i := 5; i < len(got); i += 6 { // 5 chars + 1 hyphen
				if i < len(got) {
					hyphenPositions[i] = true
				}
			}
			
			for i, c := range got {
				if hyphenPositions[i] {
					if c != '-' {
						t.Errorf("Expected hyphen at position %d, got %c", i, c)
					}
				} else if c == '-' {
					t.Errorf("Unexpected hyphen at position %d", i)
				}
			}

			// Check that all non-hyphen characters are from the character pool
			pool := []byte(constants.CharacterPool)
			for i, c := range got {
				if c == '-' {
					continue
				}
				found := false
				for _, p := range pool {
					if c == p {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Character %c at position %d not in character pool", c, i)
				}
			}

			// Generate multiple passwords and ensure they're different
			got2, _ := GenerateSecurePassword(tt.length)
			if bytes.Equal(got, got2) {
				t.Error("GenerateSecurePassword() should produce unique passwords")
			}
		})
	}
}

func TestRunProgressBar(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		percent int
	}{
		{
			name:    "0 percent",
			prefix:  "Processing",
			percent: 0,
		},
		{
			name:    "25 percent",
			prefix:  "Processing",
			percent: 25,
		},
		{
			name:    "50 percent",
			prefix:  "Processing",
			percent: 50,
		},
		{
			name:    "75 percent",
			prefix:  "Processing",
			percent: 75,
		},
		{
			name:    "100 percent",
			prefix:  "Processing",
			percent: 100,
		},
		{
			name:    "negative percent clamped to 0",
			prefix:  "Processing",
			percent: -10,
		},
		{
			name:    "over 100 percent clamped to 100",
			prefix:  "Processing",
			percent: 150,
		},
		{
			name:    "empty prefix",
			prefix:  "",
			percent: 50,
		},
		{
			name:    "long prefix",
			prefix:  "Encrypting very large file",
			percent: 42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This function only prints to stdout, so we just ensure it doesn't panic
			// In a real test, you might capture stdout and verify output format
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("RunProgressBar panicked: %v", r)
				}
			}()
			RunProgressBar(tt.prefix, tt.percent)
		})
	}
}

func TestZeroBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "nil slice",
			data: nil,
		},
		{
			name: "empty slice",
			data: []byte{},
		},
		{
			name: "single byte",
			data: []byte{0xFF},
		},
		{
			name: "multiple bytes",
			data: []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB},
		},
		{
			name: "large slice",
			data: make([]byte, 10000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.data == nil {
				// Just ensure it doesn't panic
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("ZeroBytes panicked on nil slice: %v", r)
					}
				}()
				ZeroBytes(tt.data)
				return
			}

			// Fill with random data
			for i := range tt.data {
				tt.data[i] = byte(i % 256)
			}

			// Create a copy to verify it was zeroed
			original := make([]byte, len(tt.data))
			copy(original, tt.data)

			ZeroBytes(tt.data)

			// Verify all bytes are zero
			for i, b := range tt.data {
				if b != 0 {
					t.Errorf("Byte at index %d not zeroed: got %d, want 0", i, b)
				}
			}

			// Verify original data is unaffected (different slice)
			for i, b := range original {
				if b == 0 && tt.data[i] == 0 {
					// This is fine - both zero
					continue
				}
				if b == 0 {
					t.Errorf("Original data at index %d was zero, test setup issue", i)
				}
			}
		})
	}

	// Test that ZeroBytes works on a slice from a larger array
	t.Run("slice of array", func(t *testing.T) {
		arr := [10]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		slice := arr[2:8]
		ZeroBytes(slice)

		for i := 2; i < 8; i++ {
			if arr[i] != 0 {
				t.Errorf("Array element at index %d not zeroed: got %d, want 0", i, arr[i])
			}
		}
		// Verify elements outside the slice are unchanged
		if arr[0] != 1 || arr[1] != 2 || arr[8] != 9 || arr[9] != 10 {
			t.Error("ZeroBytes modified elements outside the slice range")
		}
	})
}

// TestMlockBytes verifies that MlockBytes does not panic on various inputs.
// Whether mlock(2) actually succeeds is environment-dependent (e.g. it may
// fail silently inside containers with a low RLIMIT_MEMLOCK), so we only
// assert that the call is safe to make, not that the pages are guaranteed
// to be pinned.
func TestMlockBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "nil slice",
			data: nil,
		},
		{
			name: "empty slice",
			data: []byte{},
		},
		{
			name: "32-byte key-sized slice",
			data: make([]byte, 32),
		},
		{
			name: "large slice",
			data: make([]byte, 4096),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("MlockBytes panicked: %v", r)
				}
			}()
			MlockBytes(tt.data)
		})
	}

	// Verify mlock does not disturb the slice contents.
	t.Run("contents preserved", func(t *testing.T) {
		data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		MlockBytes(data)
		expected := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		if !bytes.Equal(data, expected) {
			t.Errorf("MlockBytes modified slice contents: got %v, want %v", data, expected)
		}
	})
}

// Benchmark tests
func BenchmarkDeriveKey(b *testing.B) {
	password := []byte("benchmark-password-12345")
	salt := []byte("benchmark-salt-12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(password, salt)
	}
}

func BenchmarkDeriveKeys(b *testing.B) {
	password := []byte("benchmark-password-12345")
	salt := []byte("benchmark-salt-12345")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKeys(password, salt)
	}
}

func BenchmarkGenerateSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateSalt()
	}
}

func BenchmarkGenerateNonce(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateNonce()
	}
}

func BenchmarkGenerateSecurePassword(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateSecurePassword(32)
	}
}

func BenchmarkZeroBytes(b *testing.B) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ZeroBytes(data)
	}
}