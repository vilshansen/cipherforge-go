package fileutils

import (
	"bytes"
	"compress/gzip" // <-- NECESSARY CHANGE: Add GZIP import
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
		fmt.Println("Enter your password for encryption, or press enter for at generere et stærkt kodeord:")
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

	// --- NECESSARY CHANGE START: STAGE 1 - COMPRESSION TO TEMP FILE ---

	// Generate a unique name for the temporary file
	randomSuffix, err := getRandomBytes(8)
	if err != nil {
		return fmt.Errorf("fejl ved generering af sikkert, tilfældigt indeks: %w", err)
	}
	tempFilePath := fmt.Sprintf("%s.cfo_temp_compressed.%x", inputFile, randomSuffix)
	defer os.Remove(tempFilePath) // Cleanup the temp file

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	tempFile, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("unable to create temporary file: %w", err)
	}

	// Stream compression: Read from inFile -> GZIP Writer -> Write to tempFile
	gzipWriter := gzip.NewWriter(tempFile)

	if _, err := io.Copy(gzipWriter, inFile); err != nil {
		tempFile.Close() // Close before returning error
		return fmt.Errorf("error during gzip compression: %w", err)
	}

	// Close both the GZIP writer (to flush the footer) and the file handle
	if err := gzipWriter.Close(); err != nil {
		tempFile.Close()
		return fmt.Errorf("error closing gzip writer: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("error closing temporary file handle: %w", err)
	}

	// --- STAGE 2: READ COMPRESSED TEMP FILE FOR ENCRYPTION ---

	// Re-open the temporary file for reading the compressed data
	compressedFile, err := os.Open(tempFilePath)
	if err != nil {
		return fmt.Errorf("unable to open compressed temp file: %w", err)
	}
	defer compressedFile.Close()

	// Read all compressed data into memory for AEAD encryption
	compressedPlaintext, err := io.ReadAll(compressedFile)
	if err != nil {
		return fmt.Errorf("error reading compressed data from temp file: %w", err)
	}
	defer cryptoutils.ZeroBytes(compressedPlaintext)

	// --- NECESSARY CHANGE END: STREAMING TO TEMP FILE ---

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

	// The old 'plaintext' variable is replaced by 'compressedPlaintext'
	aad := headers.GetFileHeaderBytes(header)
	ciphertextWithTag := aead.Seal(nil, nonce, compressedPlaintext, aad)

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

	// Decrypt the data (output is the compressed data)
	compressedPlaintext, err := aead.Open(nil, header.XChaChaNonce, ciphertextWithTag, aad)
	if err != nil {
		return fmt.Errorf("Authentication failed due to incorrect password or error in input file: %w", err)
	}
	defer cryptoutils.ZeroBytes(compressedPlaintext) // Zero compressed data after use

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	// Create a GZIP reader that reads from the decrypted data buffer
	gzipReader, gzErr := gzip.NewReader(bytes.NewReader(compressedPlaintext))
	if gzErr != nil {
		return fmt.Errorf("error initializing gzip reader (data corrupt?): %w", gzErr)
	}
	defer gzipReader.Close()

	// Stream decompression: Read from gzipReader -> Write to outFile
	if _, err := io.Copy(outFile, gzipReader); err != nil {
		return fmt.Errorf("error during decompression and writing: %w", err)
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
