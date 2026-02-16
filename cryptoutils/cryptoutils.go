// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/argon2"
)

// DeriveKey uses Argon2id to turn a password and salt into a 32-byte key.
// Argon2id is preferred over Argon2i or Argon2d as it provides the best
// resistance against both side-channel attacks and GPU-based cracking.
func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(
		password,
		salt,
		constants.Argon2Time,    // Iterations: trade-off between speed and hardware cost
		constants.Argon2Memory,  // RAM usage: makes ASIC/FPGA attacks prohibitively expensive
		constants.Argon2Threads, // Parallelism: bound to CPU cores
		32,                      // XChaCha20-Poly1305 requires a 256-bit key
	)
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

	return password, nil
}

// RunProgressBar renders a terminal-based progress indicator.
// It uses a carriage return (\r) to overwrite the current line in the console.
func RunProgressBar(prefix string, percent int) {
	const barWidth = 30

	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := (percent * barWidth) / 100
	// █ (Full Block) and ░ (Light Shade) provide a high-contrast modern UI look.
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	// %3d used to keep the percentage label width constant (prevents "jitter").
	fmt.Printf("\r%s... [%s] %3d%%", prefix, bar, percent)
}

// ZeroBytes overwrites the given byte slice with zeros.
// This is used to mitigate "cold boot" attacks and minimize the time
// sensitive material (like the master key) resides in the process heap.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
