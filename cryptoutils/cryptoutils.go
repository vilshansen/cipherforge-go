// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt" // You'll need to go get this
	"strings"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/argon2"
)

// DeriveKey uses Argon2id to turn a password and salt into a 32-byte key.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		constants.Argon2Time,
		constants.Argon2Memory,
		constants.Argon2Threads,
		32, // XChaCha20-Poly1305 requires 32 bytes
	)
}

// GenerateSalt creates a random salt for the KDF.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateSecurePassword generates a cryptographically secure, random password
// of the specified length from the predefined character pool.
func GenerateSecurePassword(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}

	pool := constants.CharacterPool
	poolLen := len(pool)

	finalLen := length + length/5 // space for dashes
	password := make([]byte, 0, finalLen)

	for i := 0; i < length; {
		// Insert dash every 5 characters
		if i > 0 && i%5 == 0 {
			password = append(password, '-')
		}

		var b [1]byte
		_, err := rand.Read(b[:])
		if err != nil {
			return nil, fmt.Errorf("failed to read random byte: %w", err)
		}

		// The trick: if your character pool is ≤ 256 characters, each random byte
		// from crypto/rand can be mapped safely. We just discard bytes outside
		// the range to avoid modulo bias. In this case that means rejecting
		// bytes 252...255.
		if int(b[0]) >= 256-(256%poolLen) {
			// Reject to avoid modulo bias
			continue
		}

		password = append(password, pool[b[0]%byte(poolLen)])
		i++
	}

	return password, nil
}

func RunProgressBar(prefix string, percent int) {
	const barWidth = 30

	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := (percent * barWidth) / 100
	// Restored your original characters: █ and -
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// Restored your specific formatting: %s... [%s] %3d%%
	fmt.Printf("\r%s... [%s] %3d%%", prefix, bar, percent)
}

// ZeroBytes overwrites the given byte slice with zeros.
// This is used to securely wipe sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
