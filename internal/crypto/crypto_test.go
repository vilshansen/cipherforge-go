package crypto

import (
	"bytes"
	"os"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/format"
)

const characterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// fastParams are lightweight Argon2id parameters for tests.
var fastParams = format.Argon2Params{
	Time:    1,
	Memory:  64 * 1024, // 64 MiB
	Threads: 1,
}

func TestMain(m *testing.M) {
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
			got := DeriveKey(tt.password, tt.salt, fastParams)
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
			encKey, macKey := DeriveKeys(tt.password, tt.salt, fastParams)

			if len(encKey) != 32 {
				t.Errorf("encKey length = %d, want 32", len(encKey))
			}
			if len(macKey) != 32 {
				t.Errorf("macKey length = %d, want 32", len(macKey))
			}

			if bytes.Equal(encKey, macKey) {
				t.Error("encKey and macKey should be different")
			}

			encKey2, macKey2 := DeriveKeys(tt.password, tt.salt, fastParams)
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

		encKey1, macKey1 := DeriveKeys(password, salt1, fastParams)
		encKey2, macKey2 := DeriveKeys(password, salt2, fastParams)

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

		encKey1, macKey1 := DeriveKeys(pass1, salt, fastParams)
		encKey2, macKey2 := DeriveKeys(pass2, salt, fastParams)

		if bytes.Equal(encKey1, encKey2) {
			t.Error("Different passwords should produce different encKeys")
		}
		if bytes.Equal(macKey1, macKey2) {
			t.Error("Different passwords should produce different macKeys")
		}
	})

	t.Run("different params produce different keys", func(t *testing.T) {
		password := []byte("test-password")
		salt := []byte("test-salt-12345678")

		params1 := format.Argon2Params{Time: 1, Memory: 64 * 1024, Threads: 1}
		params2 := format.Argon2Params{Time: 2, Memory: 64 * 1024, Threads: 1}

		encKey1, _ := DeriveKeys(password, salt, params1)
		encKey2, _ := DeriveKeys(password, salt, params2)

		if bytes.Equal(encKey1, encKey2) {
			t.Error("Different Argon2 params should produce different keys")
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

func TestDeriveMasterKey(t *testing.T) {
	password := []byte("test-password")
	params := format.DefaultArgon2Params()

	mk := DeriveMasterKey(password, params)
	if len(mk) != 32 {
		t.Errorf("DeriveMasterKey length = %d, want 32", len(mk))
	}

	// Deterministic: same password + same params = same master key
	mk2 := DeriveMasterKey(password, params)
	if !bytes.Equal(mk, mk2) {
		t.Error("DeriveMasterKey not deterministic")
	}

	// Different password = different master key
	mk3 := DeriveMasterKey([]byte("different-password"), params)
	if bytes.Equal(mk, mk3) {
		t.Error("Different passwords should produce different master keys")
	}

	// Different params = different master key
	fastParams := format.Argon2Params{Time: 1, Memory: 64 * 1024, Threads: 1}
	mk4 := DeriveMasterKey(password, fastParams)
	if bytes.Equal(mk, mk4) {
		t.Error("Different Argon2 params should produce different master keys")
	}
}

func TestDeriveKeysFromMaster(t *testing.T) {
	password := []byte("test-password")
	params := format.DefaultArgon2Params()
	masterKey := DeriveMasterKey(password, params)

	salt := []byte("test-salt-12345678")
	encKey, macKey := DeriveKeysFromMaster(masterKey, salt)

	if len(encKey) != 32 {
		t.Errorf("encKey length = %d, want 32", len(encKey))
	}
	if len(macKey) != 32 {
		t.Errorf("macKey length = %d, want 32", len(macKey))
	}

	// The two keys must be different
	if bytes.Equal(encKey, macKey) {
		t.Error("encKey and macKey should be different")
	}

	// Deterministic
	encKey2, macKey2 := DeriveKeysFromMaster(masterKey, salt)
	if !bytes.Equal(encKey, encKey2) || !bytes.Equal(macKey, macKey2) {
		t.Error("DeriveKeysFromMaster not deterministic")
	}

	// Different salt = different keys
	encKey3, macKey3 := DeriveKeysFromMaster(masterKey, []byte("different-salt-1234"))
	if bytes.Equal(encKey, encKey3) {
		t.Error("Different salts should produce different encKeys")
	}
	if bytes.Equal(macKey, macKey3) {
		t.Error("Different salts should produce different macKeys")
	}
}

func TestV3KeyDerivationRoundTrip(t *testing.T) {
	// Simulate the full v3 key derivation flow: encrypt side derives masterKey
	// + per-file keys, then decrypt side independently does the same and
	// should arrive at identical keys.
	password := []byte("test-password")
	params := format.DefaultArgon2Params()
	salt := []byte("0123456789abcdef") // 16 bytes

	// Encrypt side
	mkEnc := DeriveMasterKey(password, params)
	encKeyEnc, macKeyEnc := DeriveKeysFromMaster(mkEnc, salt)

	// Decrypt side (independent derivation)
	mkDec := DeriveMasterKey(password, params)
	encKeyDec, macKeyDec := DeriveKeysFromMaster(mkDec, salt)

	if !bytes.Equal(encKeyEnc, encKeyDec) {
		t.Error("encKey mismatch between encrypt and decrypt sides")
	}
	if !bytes.Equal(macKeyEnc, macKeyDec) {
		t.Error("macKey mismatch between encrypt and decrypt sides")
	}
}

func TestRandReader(t *testing.T) {
	r := RandReader()
	if r == nil {
		t.Error("RandReader returned nil")
	}
}
