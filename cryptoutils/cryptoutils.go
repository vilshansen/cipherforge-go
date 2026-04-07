// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"strings"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/argon2"
)

// DeriveKey uses Argon2id to turn a password and salt into a 32-byte
// encryption key. It is a convenience wrapper around DeriveKeys for callers
// that do not need the header MAC key.
func DeriveKey(password, salt []byte) []byte {
	encKey, _ := DeriveKeys(password, salt)
	return encKey
}

// DeriveKeys derives two independent 32-byte keys from a single Argon2id run:
//
//   - encKey  (bytes  0–31): XChaCha20-Poly1305 encryption key.
//   - macKey  (bytes 32–63): HMAC-SHA256 key used to authenticate the file
//     header and segment count in the trailer.
//
// Producing both keys from one KDF invocation avoids paying the Argon2id cost
// twice while still keeping the two keys domain-separated: they are independent
// 256-bit outputs of the same PRF, derived from the same password/salt pair but
// used for entirely different cryptographic operations.
//
// Both derived key slices are mlocked immediately after derivation to prevent
// the OS from paging them to disk.
func DeriveKeys(password, salt []byte) (encKey, macKey []byte) {
	raw := argon2.IDKey(
		password,
		salt,
		constants.Argon2Time,
		constants.Argon2Memory,
		constants.Argon2Threads,
		64, // 64 bytes: two independent 256-bit keys
	)
	encKey, macKey = raw[:32], raw[32:]
	MlockBytes(encKey)
	MlockBytes(macKey)
	return encKey, macKey
}

// GenerateSalt creates a random salt for the KDF.
// The salt ensures that identical passwords result in different keys,
// defeating rainbow table attacks.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateNonce creates a random nonce for use in encryption.
// For XChaCha20, a 192-bit (24-byte) nonce is large enough to be
// randomly generated without risk of collision.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, constants.XNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// GenerateSecurePassword generates a cryptographically secure, random password.
// It uses rejection sampling to ensure every character in the pool has
// a perfectly equal probability of being selected.
func GenerateSecurePassword(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	pool := constants.CharacterPool
	poolLen := len(pool)

	// Pre-allocate buffer to avoid repeated memory reallocations.
	finalLen := length + length/5
	password := make([]byte, 0, finalLen)

	for i := 0; i < length; {
		if i > 0 && i%5 == 0 {
			password = append(password, '-')
		}

		var b [1]byte
		_, err := rand.Read(b[:])
		if err != nil {
			return nil, fmt.Errorf("failed to read random byte: %w", err)
		}

		// Rejection Sampling to eliminate Modulo Bias:
		// Simply using 'b[0] % poolLen' would favor characters at the start
		// of the pool if 256 is not perfectly divisible by poolLen.
		// We discard "leftover" values to maintain uniform distribution.
		if int(b[0]) >= 256-(256%poolLen) {
			continue
		}

		password = append(password, pool[b[0]%byte(poolLen)])
		i++
	}

	MlockBytes(password)
	return password, nil
}

// RunProgressBar renders a terminal-based progress indicator.
// It uses a carriage return (\r) to overwrite the current line in the console.
func RunProgressBar(prefix string, percent int) {
	const barWidth = 20

	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := (percent * barWidth) / 100

	// low-intensity ASCII bar: subtle but readable
	bar := strings.Repeat("#", filled) + strings.Repeat(".", barWidth-filled)

	// Fixed-width prefix column prevents the bar from jittering on long filenames.
	fmt.Printf("\r%-40s [%s] %3d%%", prefix, bar, percent)
}

// ZeroBytes overwrites the given byte slice with zeros to mitigate cold-boot
// attacks and minimise the time sensitive material resides in the process heap.
//
// runtime.KeepAlive ensures the compiler cannot eliminate the zeroing loop as a
// dead-store optimisation: it proves to the compiler that b is still "live"
// after the loop completes, so the writes must not be removed.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}