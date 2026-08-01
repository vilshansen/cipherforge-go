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
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
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
	password  []byte              // The user's password (or auto-generated)
	params    format.Argon2Params // KDF parameters (defaults: 5 passes, 256 MiB)
	masterKey []byte              // Pre-derived master key for batch optimization (nil = derive on demand)
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
	return &Encrypter{
		password: password,
		params:   format.DefaultArgon2Params(),
	}
}

// NewEncrypterWithParams creates an Encrypter with custom Argon2id parameters.
// This is primarily used in tests (to use fastParams for speed) but could also
// be used to increase or decrease the KDF cost for specific use cases.
func NewEncrypterWithParams(password []byte, params format.Argon2Params) *Encrypter {
	return &Encrypter{password: password, params: params}
}

// NewEncrypterWithMasterKey creates an Encrypter with a pre-derived master
// key for batch encryption. This skips the expensive Argon2id derivation
// inside Encrypt(), making encryption of multiple files much faster.
//
// When masterKey is provided, Encrypt() uses HKDF-SHA256 directly from the
// master key with a per-file random salt to derive file-specific keys.
// The master key itself must have been derived via crypto.DeriveMasterKey().
func NewEncrypterWithMasterKey(password []byte, masterKey []byte) *Encrypter {
	return &Encrypter{
		password:  password,
		params:    format.DefaultArgon2Params(),
		masterKey: masterKey,
	}
}

// Encrypt reads plaintext from r, encrypts it in 1 MiB segments using
// XChaCha20-Poly1305, and writes the complete .cfo file (header + segments
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
// On error, the partial output in w should be discarded (the caller in
// main.go deletes failed output files).
//
// File layout produced:
//
//	[Header: 65 bytes]
//	  Magic (9) | Version (4) | Salt (16) | SegmentSeed (24) | Argon2Params (12)
//	[Payload: variable]
//	  For each segment:
//	    [segmentLen: 8 bytes] [ciphertext || Poly1305 tag: variable]
//	[Trailer: 40 bytes]
//	  [segmentCount: 8 bytes] [HMAC-SHA256: 32 bytes]
func (e *Encrypter) Encrypt(r io.Reader, w io.Writer, progress func(int64)) error {
	// Step 1: Generate per-file random values.
	// crypto.GenerateSalt() returns ([]byte, error) — the salt goes in the
	// file header and is used as the HKDF salt for file-specific key derivation.
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	// segmentSeed is the HKDF IKM for per-segment nonce derivation.
	// 24 bytes = 192 bits, the same size as an XChaCha20 nonce.
	// It's stored in plaintext in the header, but since nonces are not secret,
	// this is fine. An attacker who reads it still can't decrypt without the key.
	segmentSeed := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(crypto.RandReader(), segmentSeed); err != nil {
		return err
	}

	// Step 2: Key derivation (two-tier for v4).
	//
	// If a pre-derived master key was provided (batch mode), use it directly.
	// Otherwise, derive the master key from the password using Argon2id.
	// The shouldZeroMasterKey flag prevents zeroing a shared master key
	// that might be reused for subsequent files in batch mode.
	//
	// Go note: `:=` inside an if/else creates variables scoped to that block.
	// The `var masterKey []byte` declaration at the top of this block ensures
	// both branches assign to the same outer-scope variable.
	var masterKey []byte
	var shouldZeroMasterKey bool
	if e.masterKey != nil {
		// Use pre-derived master key (batch encryption optimization).
		// Don't zero it — the caller owns it and may reuse it.
		masterKey = e.masterKey
		shouldZeroMasterKey = false
	} else {
		// Derive master key on demand (single-file mode).
		masterKey = crypto.DeriveMasterKey(e.password, e.params)
		shouldZeroMasterKey = true
	}
	// defer runs when Encrypt() returns, regardless of error/success.
	// In Go, you can conditionally set up defers — this one only fires
	// if we derived the key ourselves.
	if shouldZeroMasterKey {
		defer crypto.ZeroBytes(masterKey)
	}

	// Derive file-specific keys from the master key + per-file salt.
	// encKey: 32 bytes for XChaCha20-Poly1305 encryption
	// macKey: 32 bytes for HMAC-SHA256 trailer authentication
	encKey, macKey := crypto.DeriveKeysFromMaster(masterKey, salt)
	defer crypto.ZeroBytes(encKey) // encKey is always locally derived, always zeroed

	// Create the AEAD cipher. XChaCha20-Poly1305 uses a 192-bit nonce.
	// `aead` is an interface with Seal() and Open() methods.
	// NewX returns (AEAD, error) — the X variant is the extended-nonce version.
	aead, err := chacha20poly1305.NewX(encKey)
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

	// Step 4: Write the 65-byte v4 header.
	if err := writeHeader(bufOut, salt, segmentSeed, e.params); err != nil {
		return err
	}

	// Step 5: Encrypt segments.
	segmentCount, err := encryptSegments(bufIn, bufOut, aead, segmentSeed, progress)
	if err != nil {
		return err
	}

	// Step 6: Write the trailer.
	if err := format.WriteUint64(bufOut, segmentCount); err != nil {
		return err
	}

	trailer := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount, e.params)
	crypto.ZeroBytes(macKey)
	if _, err := bufOut.Write(trailer); err != nil {
		return err
	}

	return nil
}

// writeHeader writes the 65-byte v4 .cfo header to w.
func writeHeader(w io.Writer, salt, segmentSeed []byte, params format.Argon2Params) error {
	if _, err := w.Write([]byte(format.Magic)); err != nil {
		return err
	}
	if err := format.WriteUint32(w, format.FileVersion); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(segmentSeed); err != nil {
		return err
	}
	return format.WriteArgon2Params(w, params)
}

// encryptSegments reads plaintext from r, encrypts it in 1 MiB segments,
// and writes the payload to w. Returns the total segment count.
func encryptSegments(r io.Reader, w io.Writer, aead cipher.AEAD, segmentSeed []byte, progress func(int64)) (uint64, error) {
	plaintextBuf := make([]byte, format.SegmentSize)
	ciphertextBuf := make([]byte, 0, format.SegmentSize+aead.Overhead())
	aad := make([]byte, 16)
	var segmentCount uint64
	var bytesDone int64

	for {
		n, err := io.ReadFull(r, plaintextBuf)
		if n > 0 {
			nonce, derr := deriveSegmentNonce(segmentSeed, segmentCount)
			if derr != nil {
				return 0, derr
			}
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
// Unlike Encrypter, the Decrypter has no KDF parameters — they are read from
// the .cfo file header. This ensures the decryptor always uses the correct
// parameters for that specific file.
type Decrypter struct {
	password []byte
}

// NewDecrypter creates a Decrypter for the given password.
func NewDecrypter(password []byte) *Decrypter {
	return &Decrypter{password: password}
}

// Decrypt reads a .cfo file from r (which MUST be seekable), authenticates
// it via the trailer HMAC, and if valid, decrypts all segments to w.
//
// Parameters:
//   - r: io.ReadSeeker — the .cfo file source. Must support seeking because
//     the trailer HMAC at EOF-40 must be verified BEFORE any plaintext is
//     written. io.ReadSeeker combines io.Reader + io.Seeker (like Java's
//     SeekableByteChannel or RandomAccessFile).
//   - w: io.Writer — the plaintext destination.
//   - progress: func(int64) — optional progress callback (plaintext bytes).
//
// Verification order:
//  1. Read and validate magic signature (9 bytes)
//  2. Read and validate format version (must equal v4)
//  3. Read salt, Segment Seed, and Argon2 parameters from header
//  4. Validate Argon2 parameters against safety limits
//  5. Derive master key via Argon2id
//  6. Derive file-specific keys via HKDF
//  7. Seek to EOF-40, read trailer (segment count + HMAC)
//  8. Compute expected HMAC and compare in constant time
//  9. If HMAC matches: seek back to payload start and decrypt segments
//  10. If HMAC fails: return "authentication failed" — no plaintext written
//
// This ordering is critical: the HMAC is verified BEFORE any plaintext
// touches disk. A wrong password, tampered header, or truncated file is
// detected immediately, not after writing gigabytes of garbage.
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

	// Step 2: Read and validate version. v4 is the only supported format.
	version, err := format.ReadUint32(r)
	if err != nil {
		return err
	}
	if version != format.FileVersion {
		return fmt.Errorf("unsupported file version %d (v%d required)", version, format.FileVersion)
	}

	// Step 3: Read the remaining header fields.
	salt := make([]byte, format.SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return err
	}

	segmentSeed := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(r, segmentSeed); err != nil {
		return err
	}

	// Step 4: Read and validate Argon2 parameters.
	// ReadArgon2Params enforces safety limits (max 10 passes, max 16 GiB memory)
	// to prevent resource exhaustion from maliciously crafted files.
	// This happens BEFORE key derivation — the HMAC can't protect us here
	// because the HMAC key itself hasn't been derived yet.
	params, err := format.ReadArgon2Params(r)
	if err != nil {
		return err
	}

	// Step 5: Key derivation (two-tier v4).
	// Derive the master key from the password using the file's embedded
	// Argon2id parameters. This ensures files remain decryptable if
	// default parameters change in future versions.
	masterKey := crypto.DeriveMasterKey(d.password, params)
	defer crypto.ZeroBytes(masterKey)

	// Derive file-specific encryption and MAC keys.
	encKey, macKey := crypto.DeriveKeysFromMaster(masterKey, salt)
	defer crypto.ZeroBytes(encKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	// Step 6: Seek to the trailer and verify the file-level HMAC.
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

	// Seek to trailer start: file_size - 40 bytes
	trailerOffset := fileSize - int64(format.TrailerSize)
	if _, err := r.Seek(trailerOffset, io.SeekStart); err != nil {
		return err
	}

	// Read the 40-byte trailer: [segmentCount: 8] [HMAC: 32]
	trailerBuf := make([]byte, format.TrailerSize)
	if _, err := io.ReadFull(r, trailerBuf); err != nil {
		return err
	}

	// Parse trailer fields.
	// `binary.BigEndian.Uint64` is like Java's ByteBuffer.getLong().
	// `trailerBuf[:8]` gets the first 8 bytes as a slice.
	// `trailerBuf[8:]` gets bytes 8 through end.
	segmentCount := binary.BigEndian.Uint64(trailerBuf[:8])
	storedHMAC := trailerBuf[8:]

	// Compute the expected HMAC and compare in constant time.
	// hmac.Equal is like Java's MessageDigest.isEqual() — no early exit
	// on first mismatched byte, preventing timing side-channel attacks.
	expectedHMAC := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount, params)
	if !hmac.Equal(storedHMAC, expectedHMAC) {
		crypto.ZeroBytes(macKey)
		return ErrAuthenticationFailed
	}
	// MAC key zeroed immediately after use — it's not needed for per-segment
	// decryption (per-segment authentication uses Poly1305 tags from the AEAD).
	crypto.ZeroBytes(macKey)

	// Step 7: Seek back to payload start and decrypt segments.
	payloadOffset := format.HeaderSize
	if _, err := r.Seek(int64(payloadOffset), io.SeekStart); err != nil {
		return err
	}

	// Buffered I/O for segment-by-segment reading.
	// bufIn buffer sized for one segment + overhead (length field + AEAD tag).
	bufIn := bufio.NewReaderSize(r, format.SegmentSize+aead.Overhead()+8)
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

		// Read the ciphertext + Poly1305 tag for this segment.
		// ciphertextBuf[:segmentLen] creates a slice view of exactly the
		// right size.
		if _, err := io.ReadFull(bufIn, ciphertextBuf[:segmentLen]); err != nil {
			return err
		}

		// Derive this segment's nonce from the Segment Seed + segment index.
		// This is the same HKDF-SHA256 construction used during encryption.
		nonce, err := deriveSegmentNonce(segmentSeed, i)
		if err != nil {
			return err
		}

		// Lower bound: segment must contain at least the AEAD tag (16 bytes).
		if segmentLen < uint64(aead.Overhead()) {
			return fmt.Errorf("corrupt segment")
		}
		// Compute plaintext length (total segment minus the Poly1305 tag).
		plaintextLen := segmentLen - uint64(aead.Overhead())

		// Build AAD identically to encryption: [segmentIndex || plaintextLength].
		// This MUST match the encryption-side AAD exactly, or the tag will
		// not verify.
		buildAAD(aad, i, plaintextLen)

		// aead.Open decrypts and authenticates in one step.
		// `ciphertextBuf[:0]` reuses the buffer for the plaintext output.
		// Returns an error if the Poly1305 tag doesn't verify (tampered data).
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

// deriveSegmentNonce derives a 24-byte XChaCha20 nonce from the Segment Seed
// and the segment counter using HKDF-SHA256 (RFC 5869).
//
// Construction:
//
//	nonce = HKDF-SHA256(
//	    ikm  = segmentSeed,                         // 24-byte random seed
//	    salt = nil,                                  // safe: IKM is uniformly random
//	    info = "cipherforge-segment-nonce-v1" || uint64_be(counter)
//	)
//
// Why HKDF rather than simpler approaches:
//
//   - XOR-based (seed XOR counter): "identity at zero" — nonce[0] == seed.
//     Knowing any two (counter, nonce) pairs reveals the seed via XOR.
//
//   - HKDF: one-way pseudorandom function. Given derived nonces, the seed
//     remains computationally hidden. No identity at zero. Domain-separated
//     via the info string + counter.
//
// The `nil` HKDF salt is safe because the IKM (segmentSeed) is already
// uniformly random from crypto/rand. RFC 5869 permits this.
func deriveSegmentNonce(segmentSeed []byte, segmentCounter uint64) ([]byte, error) {
	contextBytes := []byte(format.SegmentNonceContext)
	// info = context string || big-endian segment counter
	// This construction avoids boundary ambiguity: the context string is
	// fixed-length (28 bytes), and the counter is fixed-length (8 bytes).
	info := make([]byte, len(contextBytes)+8)
	copy(info, contextBytes)
	binary.BigEndian.PutUint64(info[len(contextBytes):], segmentCounter)

	// hkdf.New creates an io.Reader that produces key material.
	// Read exactly 24 bytes (192 bits) for the XChaCha20 nonce.
	r := hkdf.New(sha256.New, segmentSeed, nil, info)
	nonce := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ErrAuthenticationFailed is returned when the trailer HMAC does not match,
// indicating wrong password, tampered header, or corrupted file.
var ErrAuthenticationFailed = fmt.Errorf("authentication failed")

// computeTrailerHMAC computes the HMAC-SHA256 authentication tag for the
// .cfo file trailer.
func computeTrailerHMAC(macKey, salt, segmentSeed []byte, segmentCount uint64, params format.Argon2Params) []byte {
	h := hmac.New(sha256.New, macKey)

	h.Write([]byte(format.TrailerHMACContext))
	h.Write(salt)
	h.Write(segmentSeed)

	var buf [8]byte
	binary.BigEndian.PutUint32(buf[0:4], params.Time)
	binary.BigEndian.PutUint32(buf[4:8], params.Memory)
	h.Write(buf[:])
	h.Write([]byte{params.Threads, 0, 0, 0})

	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], segmentCount)
	h.Write(countBuf[:])

	return h.Sum(nil)
}
