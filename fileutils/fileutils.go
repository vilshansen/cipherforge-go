package fileutils

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptFile reads a plaintext file and writes an encrypted version in segments.
func EncryptFile(inputFile, outputFile string, userPassword []byte) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer inFile.Close()

	// 0600 ensures only the current user can read/write the encrypted file.
	outFile, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	salt, err := cryptoutils.GenerateSalt()
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}

	// Write salt first for key derivation.
	if _, err := outFile.Write(salt); err != nil {
		return fmt.Errorf("error writing salt header: %w", err)
	}

	// Generate a Master Nonce for this file.
	masterNonce, err := cryptoutils.GenerateNonce()
	if err != nil {
		return fmt.Errorf("error generating master nonce: %w", err)
	}

	// Write the Master Nonce to the file header.
	if _, err := outFile.Write(masterNonce); err != nil {
		return fmt.Errorf("error writing nonce header: %w", err)
	}

	key := cryptoutils.DeriveKey(userPassword, salt)
	defer cryptoutils.ZeroBytes(key) // Wipe key from RAM after use.

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	fileInfo, _ := inFile.Stat()
	totalBytes := fileInfo.Size()
	prefix := fmt.Sprintf("Encrypting %s", filepath.Base(inputFile))

	plaintextBuf := make([]byte, constants.SegmentSize)
	var segmentCounter uint64
	var bytesDone int64

	for {
		n, readErr := inFile.Read(plaintextBuf)
		if n == 0 {
			break
		}

		// Derive a unique nonce for this segment by XORing the master nonce with the counter.
		// This ensures every 1MB block has a unique keystream.
		nonce := make([]byte, constants.XNonceSize)
		copy(nonce, masterNonce)
		currentNonceVal := binary.BigEndian.Uint64(nonce[constants.XNonceSize-8:])
		binary.BigEndian.PutUint64(nonce[constants.XNonceSize-8:], currentNonceVal^segmentCounter)

		// AAD binds segment index and length to the ciphertext to prevent tampering.
		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(n))

		ciphertext := aead.Seal(nil, nonce, plaintextBuf[:n], aad)

		// Write Segment Structure: [Length (8B)][Ciphertext + Tag]
		if err := binary.Write(outFile, binary.BigEndian, uint64(len(ciphertext))); err != nil {
			return fmt.Errorf("error writing segment length: %w", err)
		}
		if _, err := outFile.Write(ciphertext); err != nil {
			return fmt.Errorf("error writing ciphertext: %w", err)
		}

		segmentCounter++
		bytesDone += int64(n)

		if totalBytes > 0 {
			cryptoutils.RunProgressBar(prefix, int((bytesDone*100)/totalBytes))
		}

		if readErr == io.EOF {
			break
		}
	}

	cryptoutils.RunProgressBar(prefix, 100)
	fmt.Println()
	return nil
}

// DecryptFile reads an encrypted file and restores the original plaintext.
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

	// 1. Read Salt
	salt := make([]byte, constants.SaltSize)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return fmt.Errorf("error reading salt: %w", err)
	}

	// 2. Read Master Nonce
	masterNonce := make([]byte, constants.XNonceSize)
	if _, err := io.ReadFull(inFile, masterNonce); err != nil {
		return fmt.Errorf("error reading master nonce: %w", err)
	}

	key := cryptoutils.DeriveKey(userPassword, salt)
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	fileInfo, _ := inFile.Stat()
	totalBytes := uint64(fileInfo.Size())
	prefix := fmt.Sprintf("Decrypting %s", filepath.Base(inputFile))

	var segmentCounter uint64
	var bytesRead uint64
	bytesRead += uint64(constants.SaltSize + constants.XNonceSize)

	sizeBuf := make([]byte, 8)

	for {
		// 3. Read segment length
		if _, err := io.ReadFull(inFile, sizeBuf); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading segment length: %w", err)
		}
		bytesRead += 8

		segmentLen := binary.BigEndian.Uint64(sizeBuf)

		// SECURITY FIX: Prevent OOM attacks by validating segment length.
		maxAllowed := uint64(constants.SegmentSize + aead.Overhead())
		if segmentLen > maxAllowed {
			return fmt.Errorf("security error: segment size %d exceeds limit", segmentLen)
		}

		ciphertext := make([]byte, segmentLen)
		if _, err := io.ReadFull(inFile, ciphertext); err != nil {
			return fmt.Errorf("error reading ciphertext: %w", err)
		}
		bytesRead += segmentLen

		// 4. Derive unique nonce for this segment
		nonce := make([]byte, constants.XNonceSize)
		copy(nonce, masterNonce)
		currentNonceVal := binary.BigEndian.Uint64(nonce[constants.XNonceSize-8:])
		binary.BigEndian.PutUint64(nonce[constants.XNonceSize-8:], currentNonceVal^segmentCounter)

		// 5. Reconstruct AAD for authentication
		aad := make([]byte, 16)
		binary.BigEndian.PutUint64(aad[:8], segmentCounter)
		binary.BigEndian.PutUint64(aad[8:], uint64(len(ciphertext)-aead.Overhead()))

		plaintextSegment, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			return fmt.Errorf("authentication failed: tampering detected or wrong password")
		}

		if _, err := outFile.Write(plaintextSegment); err != nil {
			return fmt.Errorf("error writing plaintext: %w", err)
		}

		segmentCounter++

		if totalBytes > 0 {
			cryptoutils.RunProgressBar(prefix, int((bytesRead*100)/totalBytes))
		}
	}

	cryptoutils.RunProgressBar(prefix, 100)
	fmt.Println()
	return nil
}

// ExpandInputPath resolves wildcards and filters out directories.
func ExpandInputPath(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no files match the pattern: %s", pattern)
	}

	var files []string
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			files = append(files, match)
		}
	}
	return files, nil
}
