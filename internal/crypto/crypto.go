// Package crypto provides cryptographic primitives for Cipherforge: key
// derivation (HKDF), random generation, and sensitive-memory
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
	"golang.org/x/crypto/hkdf"
)

// RandReader returns the source of cryptographically secure random bytes.
func RandReader() io.Reader {
	return rand.Reader
}

const (
	SaltSize = 16 // 128-bit salt

	// CharacterPool is the set of unambiguous characters for secret generation:
	// digits 1-9 (no 0), uppercase A-Z minus I/L/O, lowercase a-z minus l.
	// 57 characters total; 45 chars × log₂(57) ≈ 262.5 bits ≥ 256-bit strength.
	CharacterPool = "123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// SecretLength is the number of random characters in a generated secret. It
	// is the smallest multiple of SecretGroupSize whose keyspace still clears
	// 256 bits: 45 × log₂(57) ≈ 262.5 bits, while 40 × log₂(57) ≈ 233 bits.
	SecretLength = 45

	// SecretGroupSize is the number of characters between separators in a
	// generated secret. Grouping is for readability only.
	SecretGroupSize = 5

	// SecretSeparator separates the character groups of a generated secret. It is
	// part of the secret string: a secret is used exactly as displayed, so the
	// separators must not be stripped.
	SecretSeparator = '-'

	// SecretDisplayLength is the length of a generated secret as displayed:
	// SecretLength characters plus one separator per completed group.
	SecretDisplayLength = SecretLength + SecretLength/SecretGroupSize - 1
)

// DeriveKeys derives two independent 32-byte keys directly from the generated
// secret and file-specific salt using HKDF-SHA256 (RFC 5869). HKDF's domain
// separation via the info parameter ensures encKey and macKey are
// computationally independent.
func DeriveKeys(secret, fileSalt []byte) (encKey, macKey []byte) {
	r := hkdf.New(sha256.New, secret, fileSalt, []byte(format.FileKeyContext))
	raw := make([]byte, 64)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, nil
	}
	return splitKeyPair(raw)
}

// splitKeyPair splits a 64-byte raw key into two independent 32-byte keys
// and wipes the intermediate buffer. encKey and macKey are mlock'd.
func splitKeyPair(raw []byte) (encKey, macKey []byte) {
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(encKey, raw[:32])
	copy(macKey, raw[32:])
	ZeroBytes(raw)
	MlockBytes(encKey)
	MlockBytes(macKey)
	return
}

// GenerateSalt creates a 16-byte random salt for the KDF using crypto/rand.
func GenerateSalt() ([]byte, error) { return randRead(SaltSize) }

// GenerateSecret generates a new encryption secret: SecretLength random
// characters from CharacterPool, grouped by GroupSecret for readability.
//
// The returned slice is the secret in full — separators included — and is ready
// to be used as key material. The caller owns it and must zero it with
// ZeroBytes when done.
func GenerateSecret() ([]byte, error) {
	raw, err := GenerateSecurePassword(SecretLength, CharacterPool)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(raw)

	secret := GroupSecret(raw)
	MlockBytes(secret)
	return secret, nil
}

// GroupSecret inserts SecretSeparator between every SecretGroupSize characters
// of secret, so a long secret can be read aloud or transcribed without losing
// one's place. The separators become part of the returned secret: callers use
// exactly what they display, so the grouping and the key material never diverge.
func GroupSecret(secret []byte) []byte {
	if len(secret) <= SecretGroupSize {
		return secret
	}

	grouped := make([]byte, 0, len(secret)+len(secret)/SecretGroupSize)
	for i, c := range secret {
		if i > 0 && i%SecretGroupSize == 0 {
			grouped = append(grouped, SecretSeparator)
		}
		grouped = append(grouped, c)
	}
	return grouped
}

// randRead reads n cryptographically secure random bytes.
func randRead(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateSecurePassword generates a cryptographically secure, random password
// from the given character pool using rejection sampling via crypto/rand.Int
// to avoid modulo bias. The password is returned as []byte so it can be zeroed
// after use.
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
//
// `runtime.KeepAlive(b)` prevents the compiler from optimizing the zeroing
// loop away as a dead store, since `b` is never read afterwards.
//
// Even with KeepAlive, Go's garbage collector may have already copied the
// underlying array during compaction, leaving residual secrets in old memory
// regions. This is a known limitation — see the package doc.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
