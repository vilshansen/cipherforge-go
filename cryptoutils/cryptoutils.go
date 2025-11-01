package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/argon2"
)

func GenerateSecurePassword(length int) ([]byte, error) {
	poolLen := big.NewInt(int64(len(constants.CharacterPool)))

	// Generate the required number of random characters
	charsNeeded := length
	randomChars := make([]byte, charsNeeded)

	for i := 0; i < charsNeeded; i++ {
		idx, err := rand.Int(rand.Reader, poolLen)
		if err != nil {
			return nil, fmt.Errorf("fejl ved generering af sikkert, tilfældigt indeks: %v", err)
		}
		randomChars[i] = constants.CharacterPool[idx.Int64()]
	}

	// Insert hyphens every 5 characters
	var result []byte
	for i := 0; i < charsNeeded; i++ {
		if i > 0 && i%5 == 0 {
			result = append(result, '-')
		}
		result = append(result, randomChars[i])
	}

	return result, nil
}

func DeriveKeyArgon2id(password []byte, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) != constants.ArgonSaltLength {
		return nil, fmt.Errorf("invalid salt length")
	}

	key := argon2.IDKey(
		password,
		salt,
		constants.ArgonIterations,
		constants.ArgonMemory,
		constants.ArgonThreads,
		constants.KeySize,
	)

	return key, nil
}

// Generates a secure salt for encryption
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.ArgonSaltLength)
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
