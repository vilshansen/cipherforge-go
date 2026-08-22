package crypto

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/format"
)

// fastParams are lightweight Argon2id parameters for tests.
var fastParams = format.FastTestParams()

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
			got, err := GenerateSecurePassword(tt.length, CharacterPool)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSecurePassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if err != nil && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if len(got) != tt.length {
				t.Errorf("GenerateSecurePassword() length = %d, want %d", len(got), tt.length)
			}

			// Every character must be from the pool.
			for i, c := range got {
				if !strings.ContainsRune(CharacterPool, rune(c)) {
					t.Errorf("character at index %d (%q) is not in the character pool", i, c)
				}
			}

			// Generate a second password — it should be different.
			got2, _ := GenerateSecurePassword(tt.length, CharacterPool)
			if bytes.Equal(got, got2) {
				t.Error("two generated passwords should be different")
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
	params := fastParams

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
	diffParams := format.Argon2Params{Time: 2, Memory: 64 * 1024, Threads: 1}
	mk4 := DeriveMasterKey(password, diffParams)
	if bytes.Equal(mk, mk4) {
		t.Error("Different Argon2 params should produce different master keys")
	}
}

func TestDeriveKeysFromMaster(t *testing.T) {
	password := []byte("test-password")
	params := fastParams
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

func TestV4KeyDerivationRoundTrip(t *testing.T) {
	// Simulate the full v4 key derivation flow: encrypt side derives masterKey
	// + per-file keys, then decrypt side independently does the same and
	// should arrive at identical keys.
	password := []byte("test-password")
	params := fastParams
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
