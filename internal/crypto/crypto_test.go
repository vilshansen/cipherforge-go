package crypto

import (
	"bytes"
	"os"
	"testing"
)

const characterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func TestMain(m *testing.M) {
	Argon2Time = 1
	Argon2Memory = 64 * 1024 // 64 MiB
	Argon2Threads = 1
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

			if bytes.Equal(encKey, macKey) {
				t.Error("encKey and macKey should be different")
			}

			encKey2, macKey2 := DeriveKeys(tt.password, tt.salt)
			if !bytes.Equal(encKey, encKey2) {
				t.Error("DeriveKeys not deterministic for encKey")
			}
			if !bytes.Equal(macKey, macKey2) {
				t.Error("DeriveKeys not deterministic for macKey")
			}
		})
	}

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
	got, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() error = %v", err)
	}
	if len(got) != SaltSize {
		t.Errorf("GenerateSalt() length = %d, want %d", len(got), SaltSize)
	}
	salt2, _ := GenerateSalt()
	if bytes.Equal(got, salt2) {
		t.Error("GenerateSalt() should produce unique salts")
	}
}

func TestGenerateNonce(t *testing.T) {
	got, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce() error = %v", err)
	}
	if len(got) != XNonceSize {
		t.Errorf("GenerateNonce() length = %d, want %d", len(got), XNonceSize)
	}
	nonce2, _ := GenerateNonce()
	if bytes.Equal(got, nonce2) {
		t.Error("GenerateNonce() should produce unique nonces")
	}
}

func TestGenerateSecurePassword(t *testing.T) {
	tests := []struct {
		name        string
		length      int
		wantErr     bool
		errContains string
	}{
		{name: "valid length 44", length: 44, wantErr: false},
		{name: "valid length 10", length: 10, wantErr: false},
		{name: "valid length 1", length: 1, wantErr: false},
		{name: "zero length", length: 0, wantErr: true, errContains: "length must be positive"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSecurePassword(tt.length, characterPool)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecurePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(got) != tt.length {
				t.Errorf("GenerateSecurePassword() length = %d, want %d", len(got), tt.length)
			}

			// All output bytes must come from the pool — no hyphens.
			for _, c := range got {
				if c == '-' {
					t.Errorf("password contains hyphen: %q", got)
				}
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	data := []byte{0xFF, 0xFE, 0xFD}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d not zeroed", i)
		}
	}
}

func TestMlockBytes(t *testing.T) {
	data := []byte{0xDE, 0xAD}
	MlockBytes(data)
	if data[0] != 0xDE || data[1] != 0xAD {
		t.Error("MlockBytes modified data")
	}
}
