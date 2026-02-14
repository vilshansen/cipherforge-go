// Package cryptoutils provides utility functions for cryptographic operations,
// including password generation, key derivation, and salt generation.
package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/vilshansen/cipherforge-go/constants"
)

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

func RunSimpleSpinner(prefix string, done <-chan struct{}) {
	//spinners := []string{"⣷", "⣯", "⣟", "⡿", "⢿", "⣻", "⣽", "⣾"}
	//spinners := []string{"-", "\\", "|", "/"}
	spinners := []string{".    ", "..   ", "...  ", ".... ", "....."}

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
			fmt.Printf("\r%s%s\t", prefix, spinners[i])
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

// ZeroBytes overwrites the given byte slice with zeros.
// This is used to securely wipe sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
