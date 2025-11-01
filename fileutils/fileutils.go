package fileutils

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"github.com/vilshansen/cipherforge-go/headers"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

func EncryptFile(inputFile string, outputFile string, userPassword string) error {
	salt, err := getRandomBytes(constants.ArgonSaltLength)
	if err != nil {
		return fmt.Errorf("fejl ved generering af salt: %w", err)
	}
	defer cryptoutils.ZeroBytes(salt)

	nonce, err := getRandomBytes(constants.XNonceSize)
	if err != nil {
		return fmt.Errorf("fejl ved generering af nonce: %w", err)
	}
	defer cryptoutils.ZeroBytes(nonce)

	var passwordBytes []byte
	if userPassword != "" {
		fmt.Println("Anvender bruger-angivet kodeord til kryptering.")
		passwordBytes = []byte(userPassword)
	} else {
		fmt.Println("Genererer tilfældigt, sikkert kodeord til kryptering...")
		if passwordBytes, err = cryptoutils.GenerateSecurePassword(constants.PasswordLength); err != nil {
			return fmt.Errorf("fejl ved generering af tilfældigt kodeord: %w", err)
		}
		fmt.Printf("Tilfældigt kodeord er genereret: %s\n", string(passwordBytes))
	}

	fmt.Printf("Afleder sikker krypteringsnøgle med Argon2id ud fra kodeord...\n")

	key, err := cryptoutils.DeriveKeyArgon2id(passwordBytes, salt)
	if err != nil {
		return fmt.Errorf("fejl i nøgleafledning: %w", err)
	}
	defer cryptoutils.ZeroBytes(passwordBytes)
	defer cryptoutils.ZeroBytes(key)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	header := headers.FileHeader{
		MagicMarker: constants.MagicMarker, Argon2Salt: salt, XChaChaNonce: nonce, FileName: filepath.Base(inputFile),
	}

	if err := headers.WriteFileHeader(header, outFile); err != nil {
		return fmt.Errorf("fejl ved skrivning af header: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("kunne ikke initialisere XChaCha20-Poly1305: %w", err)
	}

	fmt.Println("Læser inputfil ind i hukommelsen til kryptering...")

	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("fejl ved læsning af inputfil: %w", err)
	}
	defer cryptoutils.ZeroBytes(plaintext)

	fmt.Printf("Krypterer fil med XChaCha20-Poly1305...\n")

	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, headers.GetFileHeaderBytes(header))
	if _, err := outFile.Write(ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved skrivning af krypteret data: %w", err)
	}
	fmt.Printf("Kryptering fuldført.\n")

	return nil
}

func DecryptFile(inputFile, outputFile, userPassword string) error {
	var passwordChars []byte
	var err error

	passwordChars = []byte(userPassword)
	if len(passwordChars) == 0 {
		fmt.Println("Indtast dit kodeord til dekryptering:")
		passwordChars, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("kunne ikke læse kodeord fra terminalen: %w", err)
		}
	}
	defer cryptoutils.ZeroBytes(passwordChars)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	stat, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("kunne ikke læse filstørrelse: %w", err)
	}
	fileSize := stat.Size()

	header, err := headers.ReadFileHeader(inFile)
	if err != nil {
		return fmt.Errorf("fejl ved læsning af header: %w", err)
	}

	fmt.Printf("Afleder sikker krypteringsnøgle med Argon2id ud fra kodeord...\n")

	// Læs: Søg 0 bytes væk fra nuværende position for at få den aktuelle offset
	currentPos, err := inFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("fejl ved læsning af nuværende position: %w", err)
	}

	headerLen := currentPos
	key, err := cryptoutils.DeriveKeyArgon2id(passwordChars, header.Argon2Salt)
	if err != nil {
		return fmt.Errorf("fejl i nøgleafledning: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("kunne ikke initialisere XChaCha20-Poly1305: %w", err)
	}

	ciphertextWithTagLen := fileSize - headerLen
	ciphertextWithTag := make([]byte, ciphertextWithTagLen)

	fmt.Println("Læser inputfil ind i hukommelsen til dekryptering...")

	if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved læsning af krypteret data: %w", err)
	}

	fmt.Println("Dekrypterer og autentificerer filen...")

	aad := headers.GetFileHeaderBytes(header)

	fmt.Printf("Dekrypterer fil med XChaCha20-Poly1305...\n")

	plaintext, err := aead.Open(nil, header.XChaChaNonce, ciphertextWithTag, aad)
	if err != nil {
		return fmt.Errorf("autentificering mislykkedes pga. forkert kodeord eller fejl i inputfil: %w", err)
	}
	defer cryptoutils.ZeroBytes(plaintext)

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(plaintext); err != nil {
		return fmt.Errorf("fejl ved skrivning af dekrypteret data: %w", err)
	}

	fmt.Println("Dekryptering fuldført.")
	return nil
}

func getRandomBytes(howManyBytes int) ([]byte, error) {
	randomBytes := make([]byte, howManyBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("kunne ikke generere tilfældige bytes: %w", err)
	}
	return randomBytes, nil
}
