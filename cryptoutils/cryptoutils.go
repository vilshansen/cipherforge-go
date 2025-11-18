package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/scrypt"
)

func GenerateSecurePassword(length int) ([]byte, error) {
	poolLen := big.NewInt(int64(len(constants.CharacterPool)))

	// Generate the required number of random characters
	charsNeeded := length
	randomChars := make([]byte, charsNeeded)

	for i := 0; i < charsNeeded; i++ {
		idx, err := rand.Int(rand.Reader, poolLen)
		if err != nil {
			return nil, fmt.Errorf("Error generating secure, random index: %v", err)
		}
		randomChars[i] = constants.CharacterPool[idx.Int64()]
	}

	// Insert hyphens every 5 characters
	var result []byte
	for i := 0; i < charsNeeded; i++ {
		result = append(result, randomChars[i])
	}

	return result, nil
}

func DeriveKeyScrypt(password []byte, salt []byte, N int, R int, P int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) != constants.SaltLength {
		return nil, fmt.Errorf("invalid salt length")
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

// Generates a secure salt for encryption
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
