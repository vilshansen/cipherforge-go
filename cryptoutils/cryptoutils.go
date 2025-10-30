package cryptoutils

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	"github.com/vilshansen/cipherforge-go/constants"
	"golang.org/x/crypto/scrypt"
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

func DeriveKey(password string, salt []byte, N, R, P int) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("kodeord må ikke være tomt")
	}
	fmt.Println("Udleder sikker krypteringsnøgle fra kodeord via scrypt...")
	key, err := scrypt.Key([]byte(password), salt, N, R, P, constants.KeySize)
	if err != nil {
		return nil, fmt.Errorf("scrypt nøgleafledning mislykkedes: %w", err)
	}

	return key, nil
}
