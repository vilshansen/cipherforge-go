package fileutils

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"github.com/vilshansen/cipherforge-go/headers"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

func EncryptFile(inputFile string, outputFile string, userPassword string) error {
	var err error
	var passwordBytes []byte = []byte(userPassword)
	if len(passwordBytes) == 0 {
		fmt.Println("Enter your password for encryption, or press enter to generate a strong password:")
		passwordBytes, err = readPasswordFromTerminal()
		if err != nil {
			return err
		}
		if len(passwordBytes) > 0 {
			fmt.Println("Confirm your password for encryption: ")
			passwordBytesVerify, err := readPasswordFromTerminal()
			if err != nil {
				return err
			}
			if !bytes.Equal(passwordBytes, passwordBytesVerify) {
				return fmt.Errorf("The two passwords entered do not match")
			}
		}
		if passwordBytes == nil {
			fmt.Println("No password entered...")
			passwordBytes, err = generateSecurePassword(passwordBytes, err)
		}
		if err != nil {
			return err
		}
	} else {
		passwordBytes = []byte(userPassword)
		if err != nil {
			return err
		}
	}

	salt, err := getRandomBytes(constants.SaltLength)
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}
	defer cryptoutils.ZeroBytes(salt)

	key, err := cryptoutils.DeriveKeyScrypt(passwordBytes, salt, constants.ScryptN, constants.ScryptR, constants.ScryptP)
	if err != nil {
		return fmt.Errorf("error during key derivation: %w", err)
	}
	defer cryptoutils.ZeroBytes(passwordBytes)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to open output file: %w", err)
	}
	defer outFile.Close()

	nonce, err := getRandomBytes(constants.XNonceSize)
	if err != nil {
		return fmt.Errorf("error generating nonce: %w", err)
	}
	defer cryptoutils.ZeroBytes(nonce)

	header := headers.FileHeader{
		MagicMarker: constants.MagicMarker, ScryptSalt: salt, ScryptN: constants.ScryptN, ScryptR: constants.ScryptR, ScryptP: constants.ScryptP, XChaChaNonce: nonce,
	}

	if err := headers.WriteFileHeader(header, outFile); err != nil {
		return fmt.Errorf("error writing header: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}
	defer cryptoutils.ZeroBytes(plaintext)

	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, headers.GetFileHeaderBytes(header))
	if _, err := outFile.Write(ciphertextWithTag); err != nil {
		return fmt.Errorf("error writing encrypted data: %w", err)
	}

	return nil
}

func readPasswordFromTerminal() ([]byte, error) {
	var passwordBytes, err = term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("could not read password from the terminal: %w", err)
	}
	return passwordBytes, nil
}

func generateSecurePassword(passwordBytes []byte, err error) ([]byte, error) {
	fmt.Println("Genererating secure, random password for encryption...")
	if passwordBytes, err = cryptoutils.GenerateSecurePassword(constants.PasswordLength); err != nil {
		return nil, fmt.Errorf("error generating secure password: %w", err)
	}
	fmt.Printf("Generated password: %s\n", string(passwordBytes))
	return passwordBytes, nil
}

func DecryptFile(inputFile, outputFile, userPassword string) error {
	var passwordChars []byte
	var err error

	passwordChars = []byte(userPassword)
	if len(passwordChars) == 0 {
		fmt.Println("Enter password for decryption:")
		passwordChars, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("unable to read password from the terminal: %w", err)
		}
	}
	defer cryptoutils.ZeroBytes(passwordChars)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	stat, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("unable to read file size: %w", err)
	}
	fileSize := stat.Size()

	header, err := headers.ReadFileHeader(inFile)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}

	// Læs: Søg 0 bytes væk fra nuværende position for at få den aktuelle offset
	currentPos, err := inFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("error reading current file position: %w", err)
	}

	headerLen := currentPos
	key, err := cryptoutils.DeriveKeyScrypt(passwordChars, header.ScryptSalt, header.ScryptN, header.ScryptR, header.ScryptP)
	if err != nil {
		return fmt.Errorf("error during key derivation: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	ciphertextWithTagLen := fileSize - headerLen
	ciphertextWithTag := make([]byte, ciphertextWithTagLen)

	if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
		return fmt.Errorf("error reading encrypted data: %w", err)
	}

	aad := headers.GetFileHeaderBytes(header)

	plaintext, err := aead.Open(nil, header.XChaChaNonce, ciphertextWithTag, aad)
	if err != nil {
		return fmt.Errorf("Authentication failed due to incorrect password or error in input file: %w", err)
	}
	defer cryptoutils.ZeroBytes(plaintext)

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(plaintext); err != nil {
		return fmt.Errorf("error writing decrypted data: %w", err)
	}

	return nil
}

func getRandomBytes(howManyBytes int) ([]byte, error) {
	randomBytes := make([]byte, howManyBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("unable to generate random bytes: %w", err)
	}
	return randomBytes, nil
}

// expandInputPath tager en sti eller et wildcard-mønster og returnerer en liste af matchende filer.
func ExpandInputPath(inputPattern string) ([]string, error) {
	// 1. Tjek om inputPattern er et gyldigt wildcard-mønster
	if !strings.ContainsAny(inputPattern, "*?[]") {
		// Hvis det ikke er et wildcard, behandl det som en enkelt fil
		_, err := os.Stat(inputPattern)
		if err != nil {
			return nil, fmt.Errorf("input file does not exist: %w", err)
		}
		return []string{inputPattern}, nil
	}

	// 2. Udfør wildcard-ekspansion
	matches, err := filepath.Glob(inputPattern)
	if err != nil {
		return nil, fmt.Errorf("error during expansion of wildcard pattern: %w", err)
	}

	// 3. Tjek for match
	if len(matches) == 0 {
		return nil, fmt.Errorf("no match found for pattern: %s", inputPattern)
	}

	return matches, nil
}
