package cryptoutils

import (
	"bytes"
	"testing"
)

func TestDeriveKey(t *testing.T) {
	pass := []byte("password")
	salt := make([]byte, 16) // Static salt for reproducibility
	key1 := DeriveKey(pass, salt)
	key2 := DeriveKey(pass, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("DeriveKey is not deterministic for the same salt/pass")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	ZeroBytes(b)
	for _, v := range b {
		if v != 0 {
			t.Fatal("ZeroBytes failed to wipe memory")
		}
	}
}
