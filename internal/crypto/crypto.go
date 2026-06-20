// Package crypto provides cryptographic primitives for Cipherforge: key
// derivation (Argon2id + HKDF), random generation, and sensitive-memory
// management.
//
// # Memory Security Limitations
//
// This package makes a best-effort attempt to protect key material in memory
// via mlock (to prevent swapping) and ZeroBytes (to overwrite secrets after
// use). However, Go's garbage collector may copy heap-allocated byte slices
// during compaction, leaving residual copies in freed memory that cannot be
// zeroed by application code. Callers requiring stronger memory-residency
// guarantees should consider a C or Rust implementation where allocations
// can be pinned and page-protected.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/vilshansen/cipherforge-go/internal/format"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// RandReader returns the source of cryptographically secure random bytes.
func RandReader() io.Reader {
	return rand.Reader
}

const (
	SaltSize   = 16
	XNonceSize = 24
)

// DeriveMasterKey derives a master key from password using Argon2id.
// This is called once per password, then file-specific keys are derived from
// the master key using DeriveKeysFromMaster for better performance in batch encryption.
func DeriveMasterKey(password []byte, params format.Argon2Params) []byte {
	masterKey := argon2.IDKey(
		password,
		[]byte(format.MasterKeySalt),
		params.Time,
		params.Memory,
		params.Threads,
		32,
	)
	MlockBytes(masterKey)
	return masterKey
}

// DeriveKeysFromMaster derives two independent 32-byte keys from a master key
// and file-specific salt using HKDF. This is fast and should be called per file.
func DeriveKeysFromMaster(masterKey, fileSalt []byte) (encKey, macKey []byte) {
	r := hkdf.New(sha256.New, masterKey, fileSalt, []byte(format.FileKeyContext))
	raw := make([]byte, 64)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, nil
	}
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(encKey, raw[:32])
	copy(macKey, raw[32:])
	ZeroBytes(raw)
	MlockBytes(encKey)
	MlockBytes(macKey)
	return encKey, macKey
}

// DeriveKey is a convenience wrapper around DeriveKeys for callers that only
// need the encryption key.
func DeriveKey(password, salt []byte, params format.Argon2Params) []byte {
	encKey, _ := DeriveKeys(password, salt, params)
	return encKey
}

// DeriveKeys derives two independent 32-byte keys from a single Argon2id run.
// This is the legacy v2 approach; v3+ uses DeriveMasterKey + DeriveKeysFromMaster.
func DeriveKeys(password, salt []byte, params format.Argon2Params) (encKey, macKey []byte) {
	raw := argon2.IDKey(
		password,
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		64,
	)
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(encKey, raw[:32])
	copy(macKey, raw[32:])
	ZeroBytes(raw)
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
	password := make([]byte, 0, length)

	for i := 0; i < length; i++ {
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
