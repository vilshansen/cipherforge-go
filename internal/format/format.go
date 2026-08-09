// Package format defines the on-disk layout of .cfo files and provides
// serialization/deserialization helpers for the binary format.
//
// # Go Language Notes for Java Developers
//
//   - Go structs are like Java records or POJOs — value types that group
//     named fields. Unlike Java, Go structs are value types (copied on
//     assignment), not reference types. Use `&T{}` for a pointer, like
//     Java's `new T()`.
//
//   - Go interfaces (io.Reader, io.Writer) are satisfied implicitly.
//     Any type with a `Read([]byte) (int, error)` method is an io.Reader.
//     This is like Java's `implements` but without declaring it.
//     Both *os.File and *bytes.Buffer satisfy io.Reader and io.Writer.
//
//   - `const` in Go can declare multiple constants in a block. The type
//     is inferred from usage (untyped constants) or explicitly stated.
//
//   - Go arrays are fixed-size: `[8]byte` is an 8-byte array (value type).
//     Slices are dynamic: `[]byte` is a view into an array (reference type).
//     To get a slice from an array: `arr[:]` — creates a slice over the
//     entire array.
//
//   - `binary.BigEndian.PutUint64(buf[:], v)` writes a uint64 in big-endian
//     byte order (like Java's ByteBuffer.putLong() with BIG_ENDIAN order).
//     The `buf[:]` converts the fixed-size array to a slice.
//
//   - Error wrapping: `fmt.Errorf("...: %w", err)` wraps an existing error
//     with additional context. Callers can use `errors.Is()` or
//     `errors.As()` to unwrap (like Java's `getCause()` on exceptions,
//     but checked at the call site).
//
//   - Go has no enums. Constants are the closest equivalent, but they are
//     just integer or string literals — no type safety. The format version
//     constants and context strings in this file are examples of this pattern.
package format

import (
	"encoding/binary" // Like Java's ByteBuffer for byte-order-aware I/O
	"fmt"
	"io"
)

// File format constants. In Go, constants in a `const` block can be typed
// or untyped. Untyped constants (like Magic) have unlimited precision and
// can be assigned to any compatible type. Typed constants (like FileVersion
// with uint32) restrict usage.
const (
	// Magic is the 9-byte file signature: "\xC1PHRF0RGE" — "Cipherforge"
	// with a non-ASCII leading byte to avoid false positives.
	// Go strings can contain arbitrary bytes, including \x00.
	Magic     = "\xC1\x50\x48\x52\x46\x30\x52\x47\x45"
	MagicSize = 9

	// FileVersion is the current format version (v5). Stored as uint32
	// big-endian in the file header. v5 adds a 32-byte key-commitment tag
	// to the trailer (see KeyCommitSize and KeyCommitContext).
	FileVersion = uint32(5)

	VersionSize = 4  // uint32 = 4 bytes
	XNonceSize  = 24 // XChaCha20 nonce = 192 bits
	SaltSize    = 16 // HKDF salt = 128 bits
	HMACSize    = 32 // HMAC-SHA256 output = 256 bits

	// KeyCommitSize is the size of the key-commitment tag appended to the
	// trailer in v5. The tag is HMAC-SHA256(encKey, context || fileSalt).
	KeyCommitSize = 32

	// Argon2ParamSize is the on-disk size of the serialised Argon2Params struct:
	// 4 (time) + 4 (memory) + 1 (threads) + 3 (reserved).
	Argon2ParamSize = 12

	// Maximum acceptable Argon2id parameters when reading from a file header.
	// These ceilings prevent a crafted file from causing resource exhaustion
	// during key derivation. Note: KDF happens BEFORE HMAC verification
	// (because the HMAC key itself is derived from the KDF), so the HMAC
	// cannot protect against parameter inflation — these safety limits are
	// the ONLY defense against resource-exhaustion attacks.
	MaxArgon2Time   = 10               // Max passes
	MaxArgon2Memory = 16 * 1024 * 1024 // 16 GiB in KiB (generous ceiling)

	// TrailerSize is the v5 trailer size: segmentCount (8) + HMAC (32) +
	// keyCommitTag (32) = 72 bytes.
	TrailerSize = 8 + HMACSize + KeyCommitSize

	SegmentSize = 1048576 // 1 MiB (2^20 bytes)

	// HeaderSize is the full v5 header size:
	//   magic(9) + version(4) + salt(16) + seed(24) + argon2params(12)
	HeaderSize = MagicSize + VersionSize + SaltSize + XNonceSize + Argon2ParamSize // 65

	// HKDF and HMAC context strings for domain separation.
	// These are ASCII strings used as info/salt parameters in HKDF and as
	// HMAC message prefixes.
	//
	// Java note: Go strings are UTF-8 encoded and immutable (like Java strings).
	// Converting a string to []byte allocates a new byte slice.
	SegmentNonceContext = "cipherforge-segment-nonce-v1"
	TrailerHMACContext  = "cipherforge-trailer-hmac-v5"
	MasterKeySalt       = "cipherforge-master-key-v1"
	FileKeyContext      = "cipherforge-file-key-v1"
	KeyCommitContext    = "cipherforge-commitment-v1"
)

// Argon2Params holds the tunable parameters for the Argon2id KDF.
//
// Go struct field tags (backtick strings after the type) are metadata,
// like Java annotations but simpler. They're accessible via the reflect
// package. This struct has no tags because it's only used in-memory,
// not serialized via encoding/json or similar.
//
// Memory is stored in KiB (not bytes) to match Argon2's API convention.
// Time is the number of passes (iterations, like PBKDF2 iterations).
// Threads is the degree of parallelism (Argon2 lanes).
type Argon2Params struct {
	Time    uint32 // Number of passes over memory
	Memory  uint32 // Memory cost in KiB (256 * 1024 = 256 MiB for production)
	Threads uint8  // Parallelism degree (lanes)
}

// DefaultArgon2Params returns the production-hardened defaults (5 passes,
// 256 MiB memory, 4 threads). These are used when decrypting v1 files that
// carry no embedded parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    5,
		Memory:  256 * 1024, // 256 MiB in KiB
		Threads: 4,
	}
}

// FastTestParams returns lightweight Argon2id parameters suitable for tests
// (1 pass, 64 MiB, single-threaded). Never use for production data.
func FastTestParams() Argon2Params {
	return Argon2Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
	}
}

// WriteArgon2Params serialises p to w in big-endian format followed by
// three reserved zero bytes for forward compatibility.
//
// Java equivalent:
//
//	var buf = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
//	buf.putInt(p.getTime());
//	buf.putInt(p.getMemory());
//	buf.put(p.getThreads());
//	buf.put(new byte[3]);  // reserved
//	w.write(buf.array());
//
// The `w io.Writer` parameter is an interface — any type that implements
// Write([]byte) (int, error) works. This includes *os.File, *bytes.Buffer,
// net.Conn, etc. This is dependency injection without a framework.
func WriteArgon2Params(w io.Writer, p Argon2Params) error {
	if err := WriteUint32(w, p.Time); err != nil {
		return fmt.Errorf("argon2 params time: %w", err)
	}
	if err := WriteUint32(w, p.Memory); err != nil {
		return fmt.Errorf("argon2 params memory: %w", err)
	}
	// var tail [4]byte allocates a 4-byte array on the stack (zero-initialized).
	// This is like `byte[] tail = new byte[4];` in Java, but on the stack.
	var tail [4]byte
	tail[0] = p.Threads
	// bytes 1-3 stay zero (reserved for future use)
	// tail[:] converts the array to a slice for w.Write()
	if _, err := w.Write(tail[:]); err != nil {
		return fmt.Errorf("argon2 params threads+reserved: %w", err)
	}
	return nil
}

// ReadArgon2Params deserialises an Argon2Params from r. The three
// reserved bytes are read and discarded.
//
// Validation rules enforced:
//  1. Time, Memory, Threads must all be non-zero (prevents degenerate KDF)
//  2. Time <= MaxArgon2Time (prevents CPU exhaustion from crafted files)
//  3. Memory <= MaxArgon2Memory (prevents RAM exhaustion from crafted files)
//
// These checks run BEFORE key derivation on the decode path — they are the
// only defense against maliciously crafted headers since the HMAC key hasn't
// been derived yet.
func ReadArgon2Params(r io.Reader) (Argon2Params, error) {
	// `var p Argon2Params` declares a zero-valued struct (all fields = 0).
	// This is like Java's `Argon2Params p = new Argon2Params();` with
	// default field values. Go structs always have a zero value.
	var p Argon2Params
	time, err := ReadUint32(r)
	if err != nil {
		return p, fmt.Errorf("argon2 params time: %w", err)
	}
	mem, err := ReadUint32(r)
	if err != nil {
		return p, fmt.Errorf("argon2 params memory: %w", err)
	}
	var tail [4]byte
	// io.ReadFull reads exactly len(tail) bytes or returns an error.
	// This is like Java's DataInputStream.readFully().
	if _, err := io.ReadFull(r, tail[:]); err != nil {
		return p, fmt.Errorf("argon2 params threads+reserved: %w", err)
	}
	p.Time = time
	p.Memory = mem
	p.Threads = tail[0]
	// Validation — must happen before any KDF work.
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 {
		return p, fmt.Errorf("argon2 params must be non-zero: time=%d memory=%d threads=%d",
			p.Time, p.Memory, p.Threads)
	}
	if p.Time > MaxArgon2Time || p.Memory > MaxArgon2Memory {
		return p, fmt.Errorf("argon2 params exceed safety limits: time=%d (max %d) memory=%d KiB (max %d KiB)",
			p.Time, MaxArgon2Time, p.Memory, MaxArgon2Memory)
	}
	return p, nil
}

// WriteUint64 writes a 64-bit unsigned integer in big-endian byte order.
//
// Java equivalent:
//
//	var buf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN);
//	buf.putLong(v);
//	w.write(buf.array());
//
// The `var buf [8]byte` allocates on the stack (fixed-size array).
// `buf[:]` creates a slice view over the entire array.
// `binary.BigEndian.PutUint64` is like Java's ByteBuffer.putLong().
func WriteUint64(w io.Writer, v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write uint64: %w", err)
	}
	return nil
}

// WriteUint32 writes a 32-bit unsigned integer in big-endian byte order.
func WriteUint32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write uint32: %w", err)
	}
	return nil
}

// ReadUint64 reads a 64-bit unsigned integer in big-endian byte order.
func ReadUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read uint64: %w", err)
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

// ReadUint32 reads a 32-bit unsigned integer in big-endian byte order.
func ReadUint32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, fmt.Errorf("read uint32: %w", err)
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}
