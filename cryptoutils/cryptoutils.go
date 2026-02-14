// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/scrypt"
)

// GenerateSecurePassword generates a cryptographically secure, random password
// of the specified length from the predefined character pool.
func GenerateSecurePassword(length int) ([]byte, error) {
	fmt.Println("Generating secure, random password for encryption...")

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

	return randomChars, nil
}

func RunSimpleSpinner(prefix string, done <-chan struct{}) {
	spinners := []string{"⣷", "⣯", "⣟", "⡿", "⢿", "⣻", "⣽", "⣾"}
	i := 0

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			// Stop signal received
			fmt.Printf("\r%s... Done.          \n", prefix)
			return

		case <-ticker.C:
			fmt.Printf("\r%s... %s", prefix, spinners[i])
			i = (i + 1) % len(spinners)
		}
	}
}

func RunProgressBar(prefix string, progressChan <-chan int) {
	const barWidth = 50

	for percent := range progressChan {
		if percent < 0 {
			percent = 0
		}
		if percent > 100 {
			percent = 100
		}

		filled := (percent * barWidth) / 100
		bar := strings.Repeat("█", filled) + strings.Repeat("-", barWidth-filled)

		fmt.Printf("\r%s... [%s] %3d%%", prefix, bar, percent)

		if percent == 100 {
			fmt.Println()
			return
		}
	}
}

func DeriveKeyScrypt(password []byte, salt []byte) ([]byte, error) {

	done := make(chan struct{})
	go RunSimpleSpinner("Deriving key using scrypt", done)
	defer close(done)

	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) != constants.SaltLength {
		return nil, fmt.Errorf("invalid salt length")
	}

	key, err := scrypt.Key(
		password,
		salt,
		constants.ScryptN,
		constants.ScryptR,
		constants.ScryptP,
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
