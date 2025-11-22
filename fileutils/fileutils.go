package fileutils

import (
	"bytes"
	"compress/gzip"
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

// EncryptFile encrypts the specified file using XChaCha20-Poly1305, streaming
// the data through GZIP compression and then chunked encryption in a single pass.
func EncryptFile(inputFile string, outputFile string, userPassword string) error {
	passwordBytes := []byte(userPassword)
	var err error

	// --- 1. Password Handling and Key Derivation (KDF) ---

	if len(passwordBytes) == 0 {
		fmt.Println("Enter password for encryption, or press enter to have one generated for you: ")
		passwordBytes, err = readPasswordFromTerminal()
		if err != nil {
			return err
		}

		if len(passwordBytes) > 0 {
			fmt.Println("Confirm your password for encryption: ")
			passwordBytesVerify, err := readPasswordFromTerminal()
			if err != nil {
				cryptoutils.ZeroBytes(passwordBytes)
				return err
			}
			if !bytes.Equal(passwordBytes, passwordBytesVerify) {
				cryptoutils.ZeroBytes(passwordBytes)
				cryptoutils.ZeroBytes(passwordBytesVerify)
				return fmt.Errorf("the two passwords entered do not match")
			}
			cryptoutils.ZeroBytes(passwordBytesVerify)
		} else {
			fmt.Println("No password entered. Generating secure password...")
			if passwordBytes, err = cryptoutils.GenerateSecurePassword(constants.PasswordLength); err != nil {
				return fmt.Errorf("error generating secure password: %w", err)
			}
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
	// Zero password memory immediately after key derivation
	defer cryptoutils.ZeroBytes(passwordBytes)

	// --- 2. File Setup and Header ---

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

	// Generate a 16-byte nonce prefix for streaming mode
	noncePrefix, err := getRandomBytes(constants.NoncePrefixLength)
	if err != nil {
		return fmt.Errorf("error generating nonce prefix: %w", err)
	}
	defer cryptoutils.ZeroBytes(noncePrefix)

	// The full 24-byte nonce is stored in the header, with the last 8 bytes being 0 (counter start)
	fullNonce := make([]byte, constants.NoncePrefixLength+constants.CounterLength)
	copy(fullNonce, noncePrefix)
	defer cryptoutils.ZeroBytes(fullNonce)

	header := headers.FileHeader{
		MagicMarker: constants.MagicMarker, ScryptSalt: salt, ScryptN: constants.ScryptN, ScryptR: constants.ScryptR, ScryptP: constants.ScryptP, XChaChaNonce: fullNonce,
	}

	if err := headers.WriteFileHeader(header, outFile); err != nil {
		return fmt.Errorf("error writing header: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("unable to initialise XChaCha20-Poly1305: %w", err)
	}
	defer cryptoutils.ZeroBytes(key)

	aad := headers.GetFileHeaderBytes(header)

	// --- 3. Single-Pass Streaming Setup (Compression -> Encryption) ---

	// Create a pipe to connect the GZIP writer (Compression) to the encryption loop (Reader).
	pipeReader, pipeWriter := io.Pipe()

	// Channel to signal when the GZIP compression goroutine is finished or returns an error.
	compressionDone := make(chan error, 1)

	// Start the Compression Goroutine: reads from inFile, compresses, and writes to pipeWriter
	go func() {
		// CRITICAL: Close the writer when done to signal EOF to the reader (encryption loop).
		// Use CloseWithError if an error occurs during compression.
		defer pipeWriter.Close()

		gzipWriter := gzip.NewWriter(pipeWriter)

		// Copy plaintext from the input file into the gzip writer, which streams
		// the compressed data into the pipeWriter.
		_, copyErr := io.Copy(gzipWriter, inFile)

		if copyErr != nil {
			// If copy failed, close the pipe with the error
			pipeWriter.CloseWithError(fmt.Errorf("error streaming compression: %w", copyErr))
			compressionDone <- copyErr
			return
		}

		// Close the gzip writer to flush any buffered data and write the GZIP footer.
		if gzCloseErr := gzipWriter.Close(); gzCloseErr != nil {
			pipeWriter.CloseWithError(fmt.Errorf("error closing gzip stream: %w", gzCloseErr))
			compressionDone <- gzCloseErr
			return
		}

		// Compression successful (pipeWriter.Close() called by defer)
		compressionDone <- nil
	}()

	// --- 4. Encryption Loop (Reads from Pipe) ---

	plaintextBuf := make([]byte, constants.ChunkSize)
	var segmentCounter uint64 = 0
	sizeBuf := make([]byte, constants.CounterLength) // 8-byte buffer to write segment length

	// The encryption loop now reads from the pipeReader.
	for {
		// Read compressed data from the pipe, which is being written concurrently by the goroutine.
		n, readErr := io.ReadFull(pipeReader, plaintextBuf)

		// The segment is only the part that was successfully read
		plaintextSegment := plaintextBuf[:n]

		if n > 0 {
			// 1. Get segment nonce (noncePrefix + counter)
			segmentNonce, nErr := getSegmentNonce(noncePrefix, segmentCounter)
			if nErr != nil {
				// Close the reader immediately upon error
				pipeReader.CloseWithError(fmt.Errorf("error generating segment nonce: %w", nErr))
				return nErr
			}

			// 2. Encrypt segment
			ciphertextWithTag := aead.Seal(nil, segmentNonce, plaintextSegment, aad)

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

			segmentCounter++
		}

		// Check read error *after* processing any bytes read
		if readErr != nil {
			if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
				break // Done reading from the pipe (compression stream finished)
			}
			// If the error came from the compression goroutine, it will be wrapped in the pipeReader's error
			return fmt.Errorf("error reading compressed data stream from pipe: %w", readErr)
		}
	}

	// Check if the compression goroutine finished without an error
	if compressionErr := <-compressionDone; compressionErr != nil {
		return fmt.Errorf("compression goroutine failed: %w", compressionErr)
	}

	return nil
}

func readPasswordFromTerminal() ([]byte, error) {
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, fmt.Errorf("could not read password from the terminal: %w", err)
	}
	return passwordBytes, nil
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

	header, err := headers.ReadFileHeader(inFile)
	if err != nil {
		return fmt.Errorf("error reading header: %w", err)
	}

	key, err := cryptoutils.DeriveKeyScrypt(passwordChars, header.ScryptSalt, header.ScryptN, header.ScryptR, header.ScryptP)
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

	// --- 1. DECOMPRESSION GOROUTINE SETUP ---
	// Create a pipe to stream decrypted chunks (compressed data) into the GZIP reader.
	pipeReader, pipeWriter := io.Pipe()

	// Start the decompression goroutine. This will block until pipeWriter is closed (EOF)
	// or until an error occurs.
	decompressionDone := make(chan error, 1)
	go func() {
		defer pipeReader.Close()

		gzipReader, gzErr := gzip.NewReader(pipeReader)
		if gzErr != nil {
			decompressionDone <- fmt.Errorf("error initializing gzip reader (data corrupt?): %w", gzErr)
			return
		}
		defer gzipReader.Close()

		// io.Copy reads decompressed data from gzipReader and writes to outFile
		_, copyErr := io.Copy(outFile, gzipReader)
		decompressionDone <- copyErr
	}()
	// --- END GOROUTINE SETUP ---

	// --- 2. DECRYPTION STREAMING LOOP ---
	// The pipeWriter must be closed after the loop to signal EOF to the gzipReader.
	// We use a local closure to ensure it's called once upon any exit.
	defer func() {
		if r := recover(); r != nil {
			pipeWriter.Close()
			panic(r)
		}
	}()
	var loopErr error

	func() {
		defer pipeWriter.Close() // CRITICAL: This ensures EOF is sent to the reader (preventing deadlock)

		sizeBuf := make([]byte, constants.CounterLength) // 8-byte buffer to read segment length
		var segmentCounter uint64 = 0

		for {
			// 1. Read segment length (8 bytes)
			if _, err := io.ReadFull(inFile, sizeBuf); err != nil {
				if err == io.EOF {
					break // Normal EOF, all segments read
				}
				loopErr = fmt.Errorf("error reading segment length: %w", err)
				return // Exit loop and close pipeWriter
			}

			segmentLen := binary.LittleEndian.Uint64(sizeBuf)

			// 2. Read the full ciphertext segment
			ciphertextWithTag := make([]byte, segmentLen)
			if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
				loopErr = fmt.Errorf("error reading encrypted data segment: %w", err)
				return // Exit loop and close pipeWriter
			}

			// 3. Get segment nonce
			segmentNonce, nErr := getSegmentNonce(noncePrefix, segmentCounter)
			if nErr != nil {
				loopErr = fmt.Errorf("error generating segment nonce: %w", nErr)
				return // Exit loop and close pipeWriter
			}

			// 4. Decrypt the data
			plaintextSegment, dErr := aead.Open(nil, segmentNonce, ciphertextWithTag, aad)
			// Zero the ciphertext memory immediately after decryption attempt
			cryptoutils.ZeroBytes(ciphertextWithTag)

			if dErr != nil {
				loopErr = fmt.Errorf("authentication failed due to incorrect password or error in input file: %w", dErr)
				return // Exit loop and close pipeWriter
			}

			// 5. Write the decrypted segment (compressed data) to the pipe
			if _, err := pipeWriter.Write(plaintextSegment); err != nil {
				loopErr = fmt.Errorf("error writing decrypted segment to pipe: %w", err)
				return // Exit loop and close pipeWriter
			}

			// Security: Zero plaintext segment after use
			cryptoutils.ZeroBytes(plaintextSegment)

			segmentCounter++
		}
	}()
	// --- END DECRYPTION STREAMING LOOP ---

	// If the loop returned an error (loopErr is not nil), return it immediately.
	if loopErr != nil {
		// Note: pipeWriter.Close() was already called by the inner defer.
		// The decompression goroutine will receive EOF/error and stop.
		// We still need to wait for it to clean up.
		<-decompressionDone
		return loopErr
	}

	// If the loop finished successfully, wait for the decompression goroutine to complete.
	if copyErr := <-decompressionDone; copyErr != nil {
		return fmt.Errorf("error during decompression and writing: %w", copyErr)
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

	// Append counter in little-endian format
	binary.LittleEndian.PutUint64(nonce[constants.NoncePrefixLength:], counter)
	return nonce, nil
}
