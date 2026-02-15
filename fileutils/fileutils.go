package fileutils

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptFile encrypts a file using XChaCha20-Poly1305 with an Argon2id derived key.
func EncryptFile(inputFile, outputFile string, userPassword []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	salt, err := cryptoutils.GenerateSalt()
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("error writing salt header: %w", err)
	}

	key := cryptoutils.DeriveKey(userPassword, salt)
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	fileInfo, _ := inFile.Stat()
	totalBytes := fileInfo.Size()
	prefix := "Encrypting file"

	plaintextBuf := make([]byte, constants.SegmentSize)
	var segmentCounter uint64
	var bytesDone uint64

	for {
		n, readErr := inFile.Read(plaintextBuf)
		if n == 0 {
			break
		}

		nonce := make([]byte, constants.XNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("error generating segment nonce: %w", err)
		}

		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(n))

		ciphertext := aead.Seal(nil, nonce, plaintextBuf[:n], aad)

		if _, err := outFile.Write(nonce); err != nil {
			return fmt.Errorf("error writing nonce: %w", err)
		}
		if err := binary.Write(outFile, binary.BigEndian, uint64(len(ciphertext))); err != nil {
			return fmt.Errorf("error writing segment length: %w", err)
		}
		if _, err := outFile.Write(ciphertext); err != nil {
			return fmt.Errorf("error writing ciphertext: %w", err)
		}

		segmentCounter++
		bytesDone += uint64(n)

		// Direct UI Update
		if totalBytes > 0 {
			cryptoutils.RunProgressBar(prefix, int((bytesDone*100)/uint64(totalBytes)))
		}

		if readErr == io.EOF {
			break
		}
	}

	// Final 100% call and Newline
	cryptoutils.RunProgressBar(prefix, 100)
	fmt.Println()

	return nil
}

// DecryptFile decrypts a file, verifying authenticity and integrity.
func DecryptFile(inputFile, outputFile string, userPassword []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	salt := make([]byte, constants.SaltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("error reading salt: %w", err)
	}

	key := cryptoutils.DeriveKey(userPassword, salt)
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	fileInfo, _ := inFile.Stat()
	totalBytes := uint64(fileInfo.Size())
	prefix := "Decrypting file"

	var segmentCounter uint64
	var bytesRead uint64 // For progress, we track read position in the encrypted file
	bytesRead += uint64(constants.SaltSize)

	sizeBuf := make([]byte, 8)
	nonceBuf := make([]byte, constants.XNonceSize)

	for {
		if _, err := io.ReadFull(inFile, nonceBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading nonce: %w", err)
		}
		bytesRead += uint64(constants.XNonceSize)

		if _, err := io.ReadFull(inFile, sizeBuf); err != nil {
			return fmt.Errorf("error reading segment length: %w", err)
		}
		bytesRead += 8

		segmentLen := binary.BigEndian.Uint64(sizeBuf)
		ciphertext := make([]byte, segmentLen)

		if _, err := io.ReadFull(inFile, ciphertext); err != nil {
			return fmt.Errorf("error reading ciphertext: %w", err)
		}
		bytesRead += segmentLen

		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(len(ciphertext)-aead.Overhead()))

		plaintextSegment, err := aead.Open(nil, nonceBuf, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("authentication failed: possible tampering or wrong password")
		}

		if _, err := outFile.Write(plaintextSegment); err != nil {
			return fmt.Errorf("error writing plaintext: %w", err)
		}

		segmentCounter++

		// Direct UI Update based on read progress of the total file
		if totalBytes > 0 {
			cryptoutils.RunProgressBar(prefix, int((bytesRead*100)/totalBytes))
		}
	}

	// Final 100% call and Newline
	cryptoutils.RunProgressBar(prefix, 100)
	fmt.Println()

	return nil
}

// ExpandInputPath takes a path or a wildcard pattern and returns matching files.
func ExpandInputPath(inputPattern string) ([]string, error) {
	if !strings.ContainsAny(inputPattern, "*?[]") {
		_, err := os.Stat(inputPattern)
		if err != nil {
			return nil, fmt.Errorf("input file does not exist: %w", err)
		}
		return []string{inputPattern}, nil
	}

	matches, err := filepath.Glob(inputPattern)
	if err != nil {
		return nil, fmt.Errorf("error during expansion of wildcard pattern: %w", err)
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("no match found for pattern: %s", inputPattern)
	}

	return matches, nil
}
