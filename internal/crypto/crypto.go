package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"golang.org/x/crypto/argon2"
)

// RandReader returns the source of cryptographically secure random bytes.
func RandReader() io.Reader {
	return rand.Reader
}

// Argon2id parameters. These are variables so tests can override them.
var (
	Argon2Time    uint32 = 4
	Argon2Memory  uint32 = 1024 * 1024 // 1 GiB
	Argon2Threads uint8  = 4
)

const (
	SaltSize   = 16
	XNonceSize = 24
)

// DeriveKey is a convenience wrapper around DeriveKeys for callers that only
// need the encryption key.
func DeriveKey(password, salt []byte) []byte {
	encKey, _ := DeriveKeys(password, salt)
	return encKey
}

// DeriveKeys derives two independent 32-byte keys from a single Argon2id run.
// This implementation must perfectly match the original to ensure compatibility.
func DeriveKeys(password, salt []byte) (encKey, macKey []byte) {
	raw := argon2.IDKey(
		password,
		salt,
		Argon2Time,
		Argon2Memory,
		Argon2Threads,
		64,
	)
	encKey, macKey = raw[:32], raw[32:]
	MlockBytes(encKey)
	MlockBytes(macKey)
	return encKey, macKey
}

// GenerateSalt creates a random salt for the KDF.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateNonce creates a random nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, XNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// GenerateSecurePassword generates a cryptographically secure, random password.
func GenerateSecurePassword(length int, pool string) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	limit := big.NewInt(int64(len(pool)))
	finalLen := length + length/5
	password := make([]byte, 0, finalLen)

	for i := 0; i < length; i++ {
		if i > 0 && i%5 == 0 {
			password = append(password, '-')
		}
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to read random byte: %w", err)
		}
		password = append(password, pool[n.Int64()])
	}

	MlockBytes(password)
	return password, nil
}

// ZeroBytes overwrites the given byte slice with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
