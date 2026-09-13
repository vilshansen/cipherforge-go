// Package cipherforge provides the high-level Encrypter and Decrypter types
// that implement the .cfo file format using the primitives from internal/crypto
// and internal/format.
//
// # Go Language Notes for Java Developers
//
// This file demonstrates several Go patterns that differ from Java:
//
//   - Methods on structs: `func (e *Encrypter) Encrypt(...)` defines a method
//     on *Encrypter. The `(e *Encrypter)` is the "receiver" — like Java's
//     `this`, but explicitly named. `*Encrypter` means pointer receiver
//     (can modify the struct). `Encrypter` (without *) would be a value
//     receiver (operates on a copy). Pointer receivers are the most common.
//
//   - Constructor convention: Go has no constructors. The convention is a
//     `NewT()` function that returns `*T`. Multiple constructors get
//     different names: `NewEncrypter`, `NewEncrypterWithParams`,
//     `NewEncrypterWithMasterKey`. There's no overloading.
//
//   - `bufio.NewReaderSize(r, size)` wraps an io.Reader with a buffer,
//     like Java's `new BufferedInputStream(in, size)`. The buffered reader
//     reduces system calls by reading in larger chunks. Similarly,
//     `bufio.NewWriterSize` wraps an io.Writer — like Java's
//     `new BufferedOutputStream(out, size)`.
//
//   - `defer` statements run in LIFO order when the function returns.
//     `defer bufOut.Flush()` ensures the buffered writer is flushed even
//     if the function returns early due to an error.
//
//   - Slice tricks:
//     `ciphertextBuf[:0]` — slice with length 0 but same backing array.
//     Used to "reset" a buffer for reuse without reallocation.
//     `ciphertextBuf[:segmentLen]` — slice limited to first segmentLen bytes.
//     `plaintextBuf[:n]` — slice limited to n bytes (the actual read size).
//
//   - The `for { ... }` loop without condition is an infinite loop (like
//     Java's `while (true) { ... }`). Break out with `break` or `return`.
//
//   - Functions as values: `progress func(int64)` is a callback function
//     parameter (like Java's `Consumer<Long>` or a lambda). If nil, no
//     progress reporting happens.
package cipherforge

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
)

// Encrypter handles the encryption of a stream into .cfo format segments.
//
// The Encrypter is stateful only in that it holds the password and KDF
// parameters. Each call to Encrypt() generates a fresh random salt and
// Segment Seed, so the same Encrypter can safely encrypt multiple files
// with independent keys.
//
// Go note: unexported fields (lowercase `password`, `params`, `masterKey`)
// are package-private — only accessible within the `cipherforge` package.
// Java equivalent: `private byte[] password;` with package-private access.
type Encrypter struct {
	password []byte // The generated secret
}

// NewEncrypter creates an Encrypter with the given password and production-
// hardened Argon2id parameters (5 passes, 256 MiB, 4 threads).
//
// This is the "default constructor" — like Java's `new Encrypter(password)`.
// The returned `*Encrypter` is a pointer (heap-allocated by default, though
// Go's escape analysis may put it on the stack if it doesn't escape).
//
// Important: the password byte slice is NOT copied. The caller still owns it
// and is responsible for zeroing it via `defer crypto.ZeroBytes(password)`.
func NewEncrypter(password []byte) *Encrypter {
	return &Encrypter{password: password}
}

// NewEncrypterWithParams is retained as a source-compatible no-op for callers
// migrating from v6. v7 has no configurable password KDF parameters.
func NewEncrypterWithParams(password []byte, _ any) *Encrypter {
	return NewEncrypter(password)
}

// Encrypt reads plaintext from r, encrypts it in 1 MiB segments using
// AES-256-GCM, and writes the complete .cfo file (header + segments
// + trailer) to w.
//
// Parameters:
//   - r: io.Reader — the plaintext source (like Java's InputStream).
//     Can be *os.File, *bytes.Buffer, *strings.Reader, etc.
//   - w: io.Writer — the ciphertext destination (like Java's OutputStream).
//   - progress: func(int64) — optional callback for progress reporting.
//     Called after each segment with the cumulative number of plaintext
//     bytes processed. Pass nil if you don't need progress updates.
//
// The method returns an error if any cryptographic or I/O operation fails.
// On error the partial output already written to w must be discarded and never
// published — the CLI stages encryption output in a temporary file for exactly
// that reason.
//
// File layout produced:
//
//	[Header: 35 bytes]
//	  Magic (9) | Version (4) | Suite (1) | Flags (1) | Salt (16) |
//	  NoncePrefix (4)
//	[Payload: variable]
//	  For each segment:
//	    [segmentLen: 8 bytes] [ciphertext || GCM tag: variable]
//	[Trailer: 72 bytes]
//	  [segmentCount: 8 bytes] [HMAC-SHA256: 32 bytes] [KeyCommitTag: 32 bytes]
func (e *Encrypter) Encrypt(r io.Reader, w io.Writer, progress func(int64)) error {
	// Step 1: Generate per-file random values.
	// crypto.GenerateSalt() returns ([]byte, error) — the salt goes in the
	// file header and is used as the HKDF salt for file-specific key derivation.
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	// noncePrefix is public nonce material. Each segment nonce is this prefix
	// followed by its unique big-endian segment counter.
	noncePrefix := make([]byte, format.NoncePrefixSize)
	if _, err := io.ReadFull(crypto.RandReader(), noncePrefix); err != nil {
		return err
	}

	// Step 2: Key derivation.
	// encKey: 32 bytes for AES-256-GCM encryption
	// macKey: 32 bytes for HMAC-SHA256 trailer authentication
	encKey, macKey := crypto.DeriveKeys(e.password, salt)
	defer crypto.ZeroBytes(encKey) // encKey is always locally derived, always zeroed

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Step 3: Set up buffered I/O.
	//
	// bufIn wraps the plaintext reader with a 1 MiB buffer — this means
	// io.ReadFull(bufIn, plaintextBuf) reads exactly one segment at a time
	// from the underlying reader. The buffer reduces the number of system
	// calls vs. reading 1 MiB directly from a file.
	//
	// bufOut wraps the output writer with a buffer sized for one segment
	// plus overhead (length prefix + AEAD tag + 8 for the length field).
	// Flush is deferred to ensure all buffered data is written on return.
	bufIn := bufio.NewReaderSize(r, format.SegmentSize)
	bufOut := bufio.NewWriterSize(w, format.SegmentSize+aead.Overhead()+8)
	defer bufOut.Flush() // Flush the buffered writer when done (even on error)

	// Step 4: Write the v7 header.
	if err := writeHeader(bufOut, salt, noncePrefix); err != nil {
		return err
	}

	// Step 5: Encrypt segments.
	segmentCount, err := encryptSegments(bufIn, bufOut, aead, noncePrefix, progress)
	if err != nil {
		return err
	}

	// Step 6: Write the trailer.
	if err := format.WriteUint64(bufOut, segmentCount); err != nil {
		return err
	}

	trailerHMAC := computeTrailerHMAC(macKey, salt, noncePrefix, segmentCount)
	if _, err := bufOut.Write(trailerHMAC); err != nil {
		return err
	}

	// v6: write the key-commitment tag.
	// HMAC-SHA256(encKey, "cipherforge-commitment-v1" || fileSalt)
	// This proves that the file was encrypted with a specific encKey,
	// preventing an attacker from crafting a ciphertext that decrypts
	// under two different passwords. The tag requires a full 32-byte
	// HMAC-SHA256 output (no truncation) to maintain 128-bit collision
	// resistance under Grover's algorithm.
	keyCommitTag := computeKeyCommitTag(encKey, salt)
	crypto.ZeroBytes(encKey)
	crypto.ZeroBytes(macKey)
	if _, err := bufOut.Write(keyCommitTag); err != nil {
		return err
	}

	return nil
}

// encryptSegments reads plaintext from r, encrypts it in 1 MiB segments,
// writeHeader writes the 35-byte v7 .cfo header to w.
func writeHeader(w io.Writer, salt, noncePrefix []byte) error {
	if _, err := w.Write([]byte(format.Magic)); err != nil {
		return err
	}
	if err := format.WriteUint32(w, format.FileVersion); err != nil {
		return err
	}
	if _, err := w.Write([]byte{format.AESGCM256Suite, 0}); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(noncePrefix); err != nil {
		return err
	}
	return nil
}

// encryptSegments reads plaintext from r, encrypts it in 1 MiB segments,
// and writes the payload to w. Returns the total segment count.
func encryptSegments(r io.Reader, w io.Writer, aead cipher.AEAD, noncePrefix []byte, progress func(int64)) (uint64, error) {
	plaintextBuf := make([]byte, format.SegmentSize)
	ciphertextBuf := make([]byte, 0, format.SegmentSize+aead.Overhead())
	aad := make([]byte, 16)
	var segmentCount uint64
	var bytesDone int64

	for {
		n, err := io.ReadFull(r, plaintextBuf)
		if n > 0 {
			nonce := deriveSegmentNonce(noncePrefix, segmentCount)
			buildAAD(aad, segmentCount, uint64(n))
			ciphertextBuf = aead.Seal(ciphertextBuf[:0], nonce, plaintextBuf[:n], aad)
			if werr := format.WriteUint64(w, uint64(len(ciphertextBuf))); werr != nil {
				return 0, werr
			}
			if _, werr := w.Write(ciphertextBuf); werr != nil {
				return 0, werr
			}
			segmentCount++
			bytesDone += int64(n)
			if progress != nil {
				progress(bytesDone)
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return segmentCount, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// Decrypter handles the decryption of a .cfo stream in segments.
//
// Unlike Encrypter, the Decrypter reads the file salt and nonce prefix from the
// .cfo header so it can reproduce the file-specific keys for that exact file.
type Decrypter struct {
	password []byte
}

// NewDecrypter creates a Decrypter for the given password.
func NewDecrypter(password []byte) *Decrypter {
	return &Decrypter{password: password}
}

// Decrypt reads a .cfo file from r (which MUST be seekable), authenticates
// it via the trailer HMAC and key-commitment tag, and if valid, decrypts
// all segments to w.
//
// Parameters:
//   - r: io.ReadSeeker — the .cfo file source. Must support seeking because
//     the trailer at EOF must be verified BEFORE any plaintext is written.
//     io.ReadSeeker combines io.Reader + io.Seeker (like Java's
//     SeekableByteChannel or RandomAccessFile).
//   - w: io.Writer — the plaintext destination.
//   - progress: func(int64) — optional progress callback (plaintext bytes).
//
// Only v7 AES-GCM files are accepted. The v7 trailer carries a suite
// identifier and a 32-byte key-commitment tag after the HMAC.
//
// Verification order:
//  1. Read and validate magic signature (9 bytes)
//  2. Read and validate format version and encryption suite
//  3. Read salt and nonce prefix from the header
//  4. Derive encKey and macKey from the generated secret and the file salt
//  5. Seek to the trailer, read segment count + HMAC + key-commitment tag
//  6. Compute the expected HMAC and compare it in constant time
//  7. Compute the expected key commitment and compare it in constant time
//  8. If any check fails: return error — no plaintext written
//  9. Seek back to payload start and decrypt segments
//
// The trailer is verified BEFORE any plaintext is produced, so a wrong secret,
// a tampered header, or a truncated file is rejected up front rather than after
// writing gigabytes of garbage.
//
// Note that the trailer authenticates file metadata, not the individual segment
// ciphertexts — those carry their own AES-GCM tags. Segments are decrypted and
// written in order, so a failure on a later segment happens after earlier
// plaintext has already been written to w. Callers that publish output to a
// consumer (for example stdout) must therefore stage it and release it only
// after Decrypt returns nil.
func (d *Decrypter) Decrypt(r io.ReadSeeker, w io.Writer, progress func(int64)) error {
	// Step 1: Validate magic signature.
	// This is a cheap check — no point spending ~1 second on Argon2id if
	// the file isn't even a .cfo file.
	magic := make([]byte, format.MagicSize)
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != format.Magic {
		return fmt.Errorf("not a valid .cfo file")
	}

	// Step 2: Read and validate version and suite.
	version, err := format.ReadUint32(r)
	if err != nil {
		return err
	}
	if version != format.FileVersion {
		return fmt.Errorf("unsupported file version %d (v%d required)", version, format.FileVersion)
	}
	suite := make([]byte, format.SuiteSize)
	if _, err := io.ReadFull(r, suite); err != nil {
		return err
	}
	if suite[0] != format.AESGCM256Suite {
		return fmt.Errorf("unsupported encryption suite %d", suite[0])
	}
	flags := make([]byte, format.FlagsSize)
	if _, err := io.ReadFull(r, flags); err != nil {
		return err
	}
	if flags[0] != 0 {
		return fmt.Errorf("unsupported format flags 0x%02x", flags[0])
	}

	// Step 3: Read the remaining header fields.
	salt := make([]byte, format.SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return err
	}

	noncePrefix := make([]byte, format.NoncePrefixSize)
	if _, err := io.ReadFull(r, noncePrefix); err != nil {
		return err
	}

	// Step 4: Derive file-specific encryption and MAC keys directly from the
	// generated secret and the per-file salt.
	encKey, macKey := crypto.DeriveKeys(d.password, salt)
	defer crypto.ZeroBytes(encKey)

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Step 6: Seek to the trailer and verify the file-level HMAC and
	// key-commitment tag.
	//
	// Go's io.ReadSeeker supports:
	//   - Seek(offset, whence): like Java's RandomAccessFile.seek()
	//     whence constants: io.SeekStart (0), io.SeekCurrent (1), io.SeekEnd (2)
	fileSize, err := r.Seek(0, io.SeekEnd) // Seek to end to get file size
	if err != nil {
		return err
	}
	if fileSize < int64(format.TrailerSize) {
		return fmt.Errorf("file too small to be a .cfo file")
	}

	// Seek to trailer start: file_size - 72 bytes
	trailerOffset := fileSize - int64(format.TrailerSize)
	if _, err := r.Seek(trailerOffset, io.SeekStart); err != nil {
		return err
	}

	// Read the 72-byte v6 trailer: [segmentCount: 8] [HMAC: 32] [keyCommit: 32]
	trailerBuf := make([]byte, format.TrailerSize)
	if _, err := io.ReadFull(r, trailerBuf); err != nil {
		return err
	}

	// Parse trailer fields.
	segmentCount := binary.BigEndian.Uint64(trailerBuf[:8])
	storedHMAC := trailerBuf[8:40]
	storedKeyCommit := trailerBuf[40:72]

	// Compute the expected HMAC and compare in constant time.
	expectedHMAC := computeTrailerHMAC(macKey, salt, noncePrefix, segmentCount)
	if !hmac.Equal(storedHMAC, expectedHMAC) {
		crypto.ZeroBytes(macKey)
		return ErrAuthenticationFailed
	}

	// Verify the key-commitment tag.
	expectedKeyCommit := computeKeyCommitTag(encKey, salt)
	if !hmac.Equal(storedKeyCommit, expectedKeyCommit) {
		crypto.ZeroBytes(macKey)
		return ErrKeyCommitmentFailed
	}

	// MAC key zeroed immediately after use — it's not needed for per-segment
	// decryption (per-segment authentication uses GCM tags from the AEAD).
	crypto.ZeroBytes(macKey)

	// Step 7: Seek back to payload start and decrypt segments.
	payloadOffset := format.HeaderSize
	if _, err := r.Seek(int64(payloadOffset), io.SeekStart); err != nil {
		return err
	}

	// Limit the payload reader to the authenticated trailer boundary. This
	// rejects extra payload bytes and segment counts that stop early.
	payloadLen := trailerOffset - int64(format.HeaderSize)
	if payloadLen < 0 {
		return fmt.Errorf("file too small to be a .cfo file")
	}
	limitedPayload := io.LimitReader(r, payloadLen)

	// Buffered I/O for segment-by-segment reading.
	// bufIn buffer sized for one segment + overhead (length field + AEAD tag).
	bufIn := bufio.NewReaderSize(limitedPayload, format.SegmentSize+aead.Overhead()+8)
	bufOut := bufio.NewWriterSize(w, format.SegmentSize)
	defer bufOut.Flush()

	var bytesRead int64
	ciphertextBuf := make([]byte, format.SegmentSize+aead.Overhead())
	aad := make([]byte, 16)

	// Decrypt segments sequentially.
	// `for i := uint64(0); i < segmentCount; i++` — standard for loop.
	// Go's for is the only looping construct; there's no `while` keyword.
	for i := uint64(0); i < segmentCount; i++ {
		// Read segment length prefix (8 bytes, big-endian).
		segmentLen, err := format.ReadUint64(bufIn)
		if err != nil {
			return err
		}

		// Bounds check: segment length must fit within expected range.
		// Upper bound: 1 MiB + 16 bytes (AEAD tag) = 1,048,592
		// This prevents a crafted file from causing a massive allocation.
		if segmentLen > uint64(format.SegmentSize+aead.Overhead()) {
			return fmt.Errorf("corrupt segment")
		}

		// Read the ciphertext + GCM tag for this segment.
		// ciphertextBuf[:segmentLen] creates a slice view of exactly the
		// right size.
		if _, err := io.ReadFull(bufIn, ciphertextBuf[:segmentLen]); err != nil {
			return err
		}

		// Derive this segment's unique nonce from the per-file prefix and
		// segment index.
		nonce := deriveSegmentNonce(noncePrefix, i)

		// Lower bound: segment must contain at least the AEAD tag (16 bytes).
		if segmentLen < uint64(aead.Overhead()) {
			return fmt.Errorf("corrupt segment")
		}
		// Compute plaintext length (total segment minus the GCM tag).
		plaintextLen := segmentLen - uint64(aead.Overhead())

		// Build AAD identically to encryption: [segmentIndex || plaintextLength].
		// This MUST match the encryption-side AAD exactly, or the tag will
		// not verify.
		buildAAD(aad, i, plaintextLen)

		// aead.Open decrypts and authenticates in one step.
		// `ciphertextBuf[:0]` reuses the buffer for the plaintext output.
		// Returns an error if the GCM tag doesn't verify (tampered data).
		plaintext, err := aead.Open(ciphertextBuf[:0], nonce, ciphertextBuf[:segmentLen], aad)
		if err != nil {
			return err
		}

		// Write the decrypted plaintext segment.
		if _, err := bufOut.Write(plaintext); err != nil {
			return err
		}

		bytesRead += int64(len(plaintext))
		if progress != nil {
			progress(bytesRead)
		}
	}
	if _, err := bufIn.ReadByte(); err != io.EOF {
		return fmt.Errorf("corrupt payload")
	}

	return nil
}

// Internal helpers below — unexported (lowercase), package-private.
// These are like Java's private static methods.

// buildAAD constructs the 16-byte Additional Authenticated Data for a segment.
//
// Layout:
//
//	dst[0:8]  = segmentIndex (uint64 big-endian)
//	dst[8:16] = plaintextLength (uint64 big-endian)
//
// This is written into the provided dst slice in-place (no allocation).
// The AAD binds the AEAD authentication tag to both the segment's position
// in the file (preventing segment reordering) and the actual plaintext
// length (preventing length manipulation).
func buildAAD(dst []byte, segmentIndex, plaintextLen uint64) {
	binary.BigEndian.PutUint64(dst[:8], segmentIndex)
	binary.BigEndian.PutUint64(dst[8:], plaintextLen)
}

// deriveSegmentNonce constructs the 12-byte AES-GCM nonce from a random
// per-file prefix and the unique big-endian segment counter.
func deriveSegmentNonce(noncePrefix []byte, segmentCounter uint64) []byte {
	nonce := make([]byte, format.NoncePrefixSize+8)
	copy(nonce, noncePrefix)
	binary.BigEndian.PutUint64(nonce[format.NoncePrefixSize:], segmentCounter)
	return nonce
}

// ErrAuthenticationFailed is returned when the trailer HMAC does not match,
// indicating wrong password, tampered header, or corrupted file.
var ErrAuthenticationFailed = fmt.Errorf("authentication failed")

// ErrKeyCommitmentFailed is returned when the key-commitment tag does not
// match. This indicates a v6 file whose trailer HMAC passed (correct
// password) but whose key-commitment tag is inconsistent — typically a
// crafted file attempting to exploit the lack of key commitment.
var ErrKeyCommitmentFailed = fmt.Errorf("key commitment verification failed")

// computeTrailerHMAC computes the HMAC-SHA256 authentication tag for the
// .cfo file trailer.
func computeTrailerHMAC(macKey, salt, noncePrefix []byte, segmentCount uint64) []byte {
	h := hmac.New(sha256.New, macKey)

	h.Write([]byte(format.TrailerHMACContext))
	h.Write([]byte{format.AESGCM256Suite, 0})
	h.Write(salt)
	h.Write(noncePrefix)

	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], segmentCount)
	h.Write(countBuf[:])

	return h.Sum(nil)
}

// computeKeyCommitTag computes the v6 key-commitment tag:
//
//	HMAC-SHA256(encKey, "cipherforge-commitment-v1" || fileSalt)
//
// This tag proves that the file was encrypted with a specific encKey.
// An attacker who wants a file to decrypt under two different passwords
// would need to find a collision in HMAC-SHA256 with different keys on
// the same message — a 2^128 work factor.
//
// The full 32-byte output is used (no truncation) to maintain 128-bit
// post-quantum collision resistance under Grover's algorithm.
func computeKeyCommitTag(encKey, fileSalt []byte) []byte {
	h := hmac.New(sha256.New, encKey)
	h.Write([]byte(format.KeyCommitContext))
	h.Write(fileSalt)
	return h.Sum(nil)
}
