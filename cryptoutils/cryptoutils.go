// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/scrypt"
)

// GenerateSecurePassword generates a cryptographically secure, random password
// of the specified length from the predefined character pool.
func GenerateSecurePassword(length int) ([]byte, error) {
	fmt.Println("Genererating secure, random password for encryption...")

	poolLen := big.NewInt(int64(len(constants.CharacterPool)))

	// Generate the required number of random characters
	charsNeeded := length
	randomChars := make([]byte, charsNeeded)

	for i := 0; i < charsNeeded; i++ {
		idx, err := rand.Int(rand.Reader, poolLen)
		if err != nil {
			return nil, fmt.Errorf("error generating secure, random index: %w", err)
		}
		randomChars[i] = constants.CharacterPool[idx.Int64()]
	}

	fmt.Printf("Generated password: %s\n", randomChars)

	return randomChars, nil
}

// DeriveKeyScrypt uses the scrypt algorithm to derive a cryptographic key
// from a password and salt using the given parameters N, R, and P.
func DeriveKeyScrypt(password []byte, salt []byte, N int, R int, P int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) != constants.SaltLength {
		return nil, fmt.Errorf("invalid salt length")
	}

	if N <= 1 || (N&(N-1)) != 0 {
		return nil, fmt.Errorf("scrypt N must be a power of 2 greater than 1, got %d", N)
	}

	if R <= 0 || P <= 0 {
		return nil, fmt.Errorf("scrypt R and P must be positive")
	}

	if int64(R)*int64(P) >= (1 << 30) {
		return nil, fmt.Errorf("scrypt R * P must be less than 2^30")
	}

	key, err := scrypt.Key(
		password,
		salt,
		N,
		R,
		P,
		constants.KeySize,
	)

	if err != nil {
		return nil, fmt.Errorf("scrypt derivation failed: %w", err)
	}

	return key, nil
}

// GenerateSalt generates a cryptographically secure, random salt
// with the length defined by constants.SaltLength.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// ZeroBytes overwrites the given byte slice with zeros.
// This is used to securely wipe sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
