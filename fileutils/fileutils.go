package fileutils

import (
	"crypto/rand"
	"crypto/sha256"
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

func EncryptFile(inputFile, outputFile, userPassword string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	key := sha256.Sum256([]byte(userPassword))
	defer cryptoutils.ZeroBytes(key[:])

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	fileInfo, _ := inFile.Stat()
	totalBytes := fileInfo.Size()

	progress := make(chan int, 1)

	go cryptoutils.RunProgressBar("Encrypting file", progress)
	defer func() { progress <- 100; close(progress) }()

	plaintextBuf := make([]byte, constants.SegmentSize)

	var prevCiphertext []byte
	var segmentCounter uint64
	var bytesDone uint64

	for {
		n, readErr := inFile.Read(plaintextBuf)
		if n == 0 {
			break
		}
		plaintextSegment := make([]byte, n)
		copy(plaintextSegment, plaintextBuf[:n])

		// CBC-style XOR with previous ciphertext
		if prevCiphertext != nil {
			for i := 0; i < n; i++ {
				plaintextSegment[i] ^= prevCiphertext[i]
			}
		}

		// Generate a unique nonce per segment
		nonce := make([]byte, constants.XNonceSize)
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("error generating segment nonce: %w", err)
		}

		// AAD includes segment counter and plaintext length
		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(len(plaintextSegment)))

		ciphertext := aead.Seal(nil, nonce, plaintextSegment, aad)

		// Write nonce + ciphertext length + ciphertext
		if _, err := outFile.Write(nonce); err != nil {
			return fmt.Errorf("error writing nonce: %w", err)
		}
		if err := binary.Write(outFile, binary.BigEndian, uint64(len(ciphertext))); err != nil {
			return fmt.Errorf("error writing segment length: %w", err)
		}
		if _, err := outFile.Write(ciphertext); err != nil {
			return fmt.Errorf("error writing ciphertext: %w", err)
		}

		// Prepare for next segment
		prevCiphertext = ciphertext
		segmentCounter++
		bytesDone += uint64(len(plaintextSegment)) // actual segment length
		progress <- int((bytesDone * 100) / uint64(totalBytes))

		if readErr == io.EOF {
			break
		}
	}

	return nil
}

func DecryptFile(inputFile, outputFile, userPassword string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	fileInfo, _ := inFile.Stat()
	totalBytes := fileInfo.Size()

	key := sha256.Sum256([]byte(userPassword))
	defer cryptoutils.ZeroBytes(key[:])

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	progress := make(chan int, 1)

	go cryptoutils.RunProgressBar("Decrypting file", progress)
	defer func() { progress <- 100; close(progress) }()

	var prevCiphertext []byte
	var segmentCounter uint64
	var bytesDone uint64

	sizeBuf := make([]byte, 8)
	nonceBuf := make([]byte, constants.XNonceSize)

	for {
		if _, err := io.ReadFull(inFile, nonceBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading nonce: %w", err)
		}

		if _, err := io.ReadFull(inFile, sizeBuf); err != nil {
			return fmt.Errorf("error reading segment length: %w", err)
		}

		segmentLen := binary.BigEndian.Uint64(sizeBuf)
		ciphertext := make([]byte, segmentLen)

		if _, err := io.ReadFull(inFile, ciphertext); err != nil {
			return fmt.Errorf("error reading ciphertext: %w", err)
		}

		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(len(ciphertext)-aead.Overhead()))

		plaintextSegment, err := aead.Open(nil, nonceBuf, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		// Reverse CBC XOR
		if prevCiphertext != nil {
			for i := 0; i < len(plaintextSegment); i++ {
				plaintextSegment[i] ^= prevCiphertext[i]
			}
		}

		if _, err := outFile.Write(plaintextSegment); err != nil {
			return fmt.Errorf("error writing plaintext: %w", err)
		}

		prevCiphertext = ciphertext
		segmentCounter++
		bytesDone += uint64(len(plaintextSegment)) // actual segment length
		progress <- int((bytesDone * 100) / uint64(totalBytes))
	}

	return nil
}

// ExpandInputPath takes a path or a wildcard pattern and returns a list of matching files.
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
