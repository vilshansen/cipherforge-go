package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/argon2"
)

func GenerateSecurePassword(length int) string {
	poolLen := big.NewInt(int64(len(constants.CharacterPool)))
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, poolLen)
		if err != nil {
			log.Fatalf("Fejl ved generering af sikkert, tilfældigt indeks: %v", err)
		}
		result[i] = constants.CharacterPool[idx.Int64()]
	}

	return string(result)
}

func DeriveKeyArgon2id(password []byte, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) != constants.ArgonSaltSize {
		return nil, fmt.Errorf("invalid salt length")
	}

	key := argon2.IDKey(
		password,
		salt,
		constants.ArgonTime,
		constants.ArgonMemory,
		constants.ArgonThreads,
		constants.KeySize,
	)

	return key, nil
}

// Generates a secure salt for encryption
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, constants.ArgonSaltSize)
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
