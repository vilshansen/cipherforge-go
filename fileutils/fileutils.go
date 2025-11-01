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
	salt := make([]byte, constants.ArgonSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("kunne ikke generere tilfældigt salt: %w", err)
	}

	nonce := make([]byte, constants.XNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("kunne ikke generere tilfældigt nonce: %w", err)
	}
	password := userPassword
	if password == "" {
		password = cryptoutils.GenerateSecurePassword(constants.PasswordLength)
		fmt.Printf("Tilfældigt kodeord er genereret: %s\n", password)
	}
	key, err := cryptoutils.DeriveKeyArgon2id([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("fejl i nøgleafledning: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

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
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()
	header := headers.FileHeader{
		MagicMarker: constants.MagicMarker, Argon2Salt: salt, XChaChaNonce: nonce, FileName: filepath.Base(inputFile),
	}
	headerLen, err := headers.WriteFileHeader(header, outFile)
	if err != nil {
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

	fmt.Printf("Krypterer %.2f MB fil med XChaCha20-Poly1305...\n", float64(fileSize)/(1024*1024))
	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, headers.GetFileHeaderBytes(header))
	if _, err := outFile.Write(ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved skrivning af krypteret data: %w", err)
	}
	fmt.Printf("Kryptering fuldført. Output filstørrelse: %.2f MB\n", float64(headerLen+int64(len(ciphertextWithTag)))/(1024*1024))

	return nil
}

func DecryptFile(inputFile, outputFile, userPassword string) error {
	var passwordChars []byte
	var err error

	password := userPassword

	if password == "" {
		fmt.Println("Indtast dit kodeord til dekryptering:")
		passwordChars, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("kunne ikke læse kodeord fra terminalen: %w", err)
		}
		password = string(passwordChars)
		defer cryptoutils.ZeroBytes(passwordChars)
	}

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

	// Læs: Søg 0 bytes væk fra nuværende position for at få den aktuelle offset
	currentPos, _ := inFile.Seek(0, io.SeekCurrent)
	headerLen := currentPos
	key, err := cryptoutils.DeriveKeyArgon2id([]byte(password), header.Argon2Salt)
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

	if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved læsning af krypteret data: %w", err)
	}

	fmt.Println("Dekrypterer og autentificerer filen...")

	aad := headers.GetFileHeaderBytes(header)

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
