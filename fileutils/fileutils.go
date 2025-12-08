package fileutils

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
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
	passwordBytes, err := handlePasswordInput(userPassword)
	if err != nil {
		return fmt.Errorf("error handling password input: %w", err)
	}
	defer cryptoutils.ZeroBytes(passwordBytes)

	salt, err := getRandomBytes(constants.SaltLength)
	if err != nil {
		return fmt.Errorf("error generating salt: %w", err)
	}
	defer cryptoutils.ZeroBytes(salt)

	key, err := cryptoutils.DeriveKeyScrypt(passwordBytes, salt)
	if err != nil {
		return fmt.Errorf("error during key derivation: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

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

	// The full 24-byte nonce is stored in the header, with the last 8 bytes being 0 (counter start)
	noncePrefix, err := getNoncePrefix()
	if err != nil {
		return fmt.Errorf("error generating nonce prefix: %w", err)
	}
	defer cryptoutils.ZeroBytes(noncePrefix)

	fullNonce, err := getFullNonce(noncePrefix)
	if err != nil {
		return fmt.Errorf("error generating full nonce: %w", err)
	}
	defer cryptoutils.ZeroBytes(fullNonce)

	header := getFileHeader(salt, fullNonce)
	headerData := headers.GetFileHeaderBytes(*header)
	if err := headers.WriteFileHeader(headerData, outFile); err != nil {
		return fmt.Errorf("error writing header: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

	file, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}
	defer file.Close()

	fileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %w", err)
	}
	totalBytes := fileInfo.Size()

	plaintextBuf := make([]byte, constants.ChunkSize)
	var segmentCounter uint64 = 0
	sizeBuf := make([]byte, constants.CounterLength) // 8-byte buffer to write segment length

	// The encryption loop now reads from the pipeReader.
	for {
		n, readErr := io.ReadFull(file, plaintextBuf)
		if (readErr != nil && readErr != io.EOF) && n == 0 {
			return fmt.Errorf("error reading input file: %w", readErr)
		}

		// The segment is only the part that was successfully read
		plaintextSegment := plaintextBuf[:n]

		if n > 0 {
			// 1. Get segment nonce (noncePrefix + counter)
			segmentNonce, nErr := getSegmentNonce(noncePrefix, segmentCounter)
			if nErr != nil {
				return fmt.Errorf("error getting segment nonce: %w", nErr)
			}

			// 2. Encrypt segment
			ciphertextWithTag := aead.Seal(nil, segmentNonce, plaintextSegment, headerData)

			// 3. Write segment length (8 bytes)
			segmentLen := uint64(len(ciphertextWithTag))
			binary.LittleEndian.PutUint64(sizeBuf, segmentLen)

			if _, err := outFile.Write(sizeBuf); err != nil {
				return fmt.Errorf("error writing segment length: %w", err)
			}

			// 4. Write ciphertext segment with tag
			if _, err := outFile.Write(ciphertextWithTag); err != nil {
				return fmt.Errorf("error writing encrypted data segment: %w", err)
			}

			fmt.Printf("\rEncrypting... %.1f%%                                ", float64(segmentCounter*segmentLen)*100/float64(totalBytes))

			segmentCounter++
		}

		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				fmt.Print("\r                                                        ")
				break // Done reading from the input file
			}
		}
	}

	return nil
}

func DecryptFile(inputFile, outputFile, userPassword string) error {
	passwordChars := []byte(userPassword)
	var err error

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

	fileInfo, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("error getting file info: %w", err)
	}
	totalBytes := fileInfo.Size()

	header, err := headers.ReadFileHeader(inFile)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}

	key, err := cryptoutils.DeriveKeyScrypt(passwordChars, header.ScryptSalt)
	if err != nil {
		return fmt.Errorf("error during key derivation: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}

	aad := headers.GetFileHeaderBytes(header)
	// Use the first 16 bytes of the header nonce as the fixed prefix
	noncePrefix := header.XChaChaNonce[:constants.NoncePrefixLength]

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("unable to create output file: %w", err)
	}
	defer outFile.Close()

	if err != nil {
		return fmt.Errorf("unable to open input file: %w", err)
	}

	sizeBuf := make([]byte, constants.CounterLength) // 8-byte buffer to read segment length
	var segmentCounter uint64 = 0

	for {
		var err error
		// 1. Read segment length (8 bytes)
		if _, err = io.ReadFull(inFile, sizeBuf); err != nil {
			if err == io.EOF {
				break // Normal EOF, all segments read
			}
			return fmt.Errorf("error reading input file: %w", err)
		}

		segmentLen := binary.LittleEndian.Uint64(sizeBuf)

		// 2. Read the full ciphertext segment
		ciphertextWithTag := make([]byte, segmentLen)
		if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
			return fmt.Errorf("error reading ciphertext segment: %w", err)
		}

		// 3. Get segment nonce
		segmentNonce, nErr := getSegmentNonce(noncePrefix, segmentCounter)
		if nErr != nil {
			return fmt.Errorf("error generating segment nonce: %w", nErr)
		}

		// 4. Decrypt the data
		plaintextSegment, dErr := aead.Open(nil, segmentNonce, ciphertextWithTag, aad)
		// Zero the ciphertext memory immediately after decryption attempt
		cryptoutils.ZeroBytes(ciphertextWithTag)

		if dErr != nil {
			return fmt.Errorf("authentication failed due to incorrect password or error in input file: %w", dErr)
		}

		// 5. Write the decrypted segment to output file
		if _, err := outFile.Write(plaintextSegment); err != nil {
			return fmt.Errorf("error writing decrypted segment to output file: %w", err)
		}

		// Security: Zero plaintext segment after use
		cryptoutils.ZeroBytes(plaintextSegment)

		fmt.Printf("\rDecrypting... %.1f%%                                ", float64(segmentCounter*segmentLen)*100/float64(totalBytes))

		segmentCounter++

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			fmt.Print("\r                                                        ")
			break // Done reading from the input file
		}
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

// ExpandInputPath takes a path or a wildcard pattern and returns a list of matching files.
func ExpandInputPath(inputPattern string) ([]string, error) {
	// 1. Check if inputPattern contains a wildcard pattern
	if !strings.ContainsAny(inputPattern, "*?[]") {
		// If it is not a wildcard, treat it as a single file
		_, err := os.Stat(inputPattern)
		if err != nil {
			return nil, fmt.Errorf("input file does not exist: %w", err)
		}
		return []string{inputPattern}, nil
	}

	// 2. Perform wildcard expansion
	matches, err := filepath.Glob(inputPattern)
	if err != nil {
		return nil, fmt.Errorf("error during expansion of wildcard pattern: %w", err)
	}

	// 3. Check for matches
	if len(matches) == 0 {
		return nil, fmt.Errorf("no match found for pattern: %s", inputPattern)
	}

	return matches, nil
}

// getSegmentNonce constructs a unique 24-byte nonce for a data segment.
// It uses the first 16 bytes as a fixed prefix (from the file header)
// and appends an 8-byte counter to ensure uniqueness for every segment.
func getSegmentNonce(noncePrefix []byte, counter uint64) ([]byte, error) {
	if len(noncePrefix) != constants.NoncePrefixLength {
		return nil, fmt.Errorf("nonce prefix must be %d bytes, got %d", constants.NoncePrefixLength, len(noncePrefix))
	}

	// The full XChaCha nonce is 24 bytes
	nonce := make([]byte, constants.NoncePrefixLength+constants.CounterLength)
	copy(nonce, noncePrefix)

	// Append counter in little-endian format, to ensure  the counter bytes
	// are arranged in the order expected by the Go crypto library's
	// implementation of XChaCha20-Poly1305
	binary.LittleEndian.PutUint64(nonce[constants.NoncePrefixLength:], counter)
	return nonce, nil
}

func getNoncePrefix() ([]byte, error) {
	noncePrefix, err := getRandomBytes(constants.NoncePrefixLength)
	if err != nil {
		return nil, fmt.Errorf("error generating random bytes: %w", err)
	}
	defer cryptoutils.ZeroBytes(noncePrefix)
	return noncePrefix, nil
}

func getFullNonce(noncePrefix []byte) ([]byte, error) {
	fullNonce := make([]byte, constants.NoncePrefixLength+constants.CounterLength)
	copy(fullNonce, noncePrefix)
	return fullNonce, nil
}

func getFileHeader(salt []byte, fullNonce []byte) *headers.FileHeader {
	return &headers.FileHeader{
		MagicMarker: constants.MagicMarker, ScryptSalt: salt, ScryptN: constants.ScryptN, ScryptR: constants.ScryptR, ScryptP: constants.ScryptP, XChaChaNonce: fullNonce,
	}
}

func handlePasswordInput(userPassword string) ([]byte, error) {
	passwordBytes := []byte(userPassword)
	if len(passwordBytes) == 0 {
		fmt.Println("Enter password for encryption, or press enter to have one generated for you: ")
		passwordBytes, err := readPasswordFromTerminal()
		if err != nil {
			return nil, err
		}

		if len(passwordBytes) > 0 {
			fmt.Println("Confirm your password for encryption: ")
			passwordBytesVerify, err := readPasswordFromTerminal()
			if err != nil {
				cryptoutils.ZeroBytes(passwordBytes)
				return nil, err
			}
			if !bytes.Equal(passwordBytes, passwordBytesVerify) {
				cryptoutils.ZeroBytes(passwordBytes)
				cryptoutils.ZeroBytes(passwordBytesVerify)
				return nil, fmt.Errorf("the two passwords entered do not match")
			}
			cryptoutils.ZeroBytes(passwordBytesVerify)
		} else {
			fmt.Println("No password entered. Generating secure password...")
			if passwordBytes, err = cryptoutils.GenerateSecurePassword(constants.PasswordLength); err != nil {
				return nil, fmt.Errorf("error generating secure password: %w", err)
			}
		}
	}
	return passwordBytes, nil
}

func readPasswordFromTerminal() ([]byte, error) {
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("could not read password from the terminal: %w", err)
	}
	return passwordBytes, nil
}
