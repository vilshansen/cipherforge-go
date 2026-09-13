package crypto

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

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

/*
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

}
*/

func TestDeriveKeys(t *testing.T) {
	secret := []byte("generated-secret")
	salt := []byte("test-salt-12345678")
	encKey, macKey := DeriveKeys(secret, salt)
	if len(encKey) != 32 || len(macKey) != 32 {
		t.Fatal("derived keys must be 32 bytes")
	}
	encKey2, macKey2 := DeriveKeys(secret, salt)
	if !bytes.Equal(encKey, encKey2) || !bytes.Equal(macKey, macKey2) {
		t.Fatal("DeriveKeys not deterministic")
	}
	encKey3, macKey3 := DeriveKeys(secret, []byte("different-salt-1234"))
	if bytes.Equal(encKey, encKey3) || bytes.Equal(macKey, macKey3) {
		t.Fatal("different salts must produce different keys")
	}
}

func TestRandReader(t *testing.T) {
	r := RandReader()
	if r == nil {
		t.Error("RandReader returned nil")
	}
}

func TestGroupSecret(t *testing.T) {
	// 63 characters ▒ 12 separators.
	raw := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!")
	want := "abcde-fghij-klmno-pqrst-uvwxy-zABCD-EFGHI-JKLMN-OPQRS-TUVWX-YZ012-34567-89!"

	if got := string(GroupSecret(raw)); got != want {
		t.Errorf("GroupSecret() = %q, want %q", got, want)
	}
}

func TestGroupSecretLeavesShortInputAlone(t *testing.T) {
	// Anything at or below one group is returned unchanged: no leading,
	// trailing, or duplicate separators.
	for _, in := range []string{"", "a", "abc", "abcde"} {
		if got := string(GroupSecret([]byte(in))); got != in {
			t.Errorf("GroupSecret(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestSecretLengthIsMinimalMultipleOfGroupSize(t *testing.T) {
	bitsPerChar := math.Log2(float64(len(CharacterPool)))

	if SecretLength%SecretGroupSize != 0 {
		t.Errorf("SecretLength = %d, want a multiple of %d", SecretLength, SecretGroupSize)
	}
	if got := float64(SecretLength) * bitsPerChar; got < 256 {
		t.Errorf("SecretLength = %d gives %.1f bits, want at least 256", SecretLength, got)
	}
	// The next smaller multiple of the group size must fall short of 256 bits,
	// otherwise a shorter secret would do.
	if smaller := SecretLength - SecretGroupSize; float64(smaller)*bitsPerChar >= 256 {
		t.Errorf("%d characters also clears 256 bits; SecretLength is not minimal", smaller)
	}
}

func TestGenerateSecretIsGroupedPoolCharacters(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	if len(secret) != SecretDisplayLength {
		t.Fatalf("len(secret) = %d, want %d", len(secret), SecretDisplayLength)
	}
	if secret[len(secret)-1] == SecretSeparator {
		t.Error("secret must not end with a separator")
	}

	groups := strings.Split(string(secret), string(SecretSeparator))
	if len(groups) != SecretLength/SecretGroupSize {
		t.Fatalf("got %d groups, want %d", len(groups), SecretLength/SecretGroupSize)
	}
	for i, group := range groups {
		if len(group) != SecretGroupSize {
			t.Errorf("group %d = %q, want %d characters", i, group, SecretGroupSize)
		}
		for _, c := range group {
			if !strings.ContainsRune(CharacterPool, c) {
				t.Errorf("group %d contains %q, which is outside CharacterPool", i, c)
			}
		}
	}

	other, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if bytes.Equal(secret, other) {
		t.Error("GenerateSecret() should produce a different secret each call")
	}
}
