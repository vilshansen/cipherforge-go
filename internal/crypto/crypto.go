// Package crypto provides cryptographic primitives for Cipherforge: key
// derivation (Argon2id + HKDF), random generation, and sensitive-memory
// management.
//
// # Go Language Notes for Java Developers
//
// This file demonstrates several Go idioms that differ from Java:
//
//   - Go has no classes. Methods are functions with a "receiver" parameter
//     before the function name (e.g., `func (e *Encrypter) Encrypt(...)`).
//
//   - Visibility is controlled by capitalization:
//     `DeriveMasterKey` is exported (public),
//     `deriveSegmentNonce` would be unexported (package-private).
//     There is no `public`/`private` keyword.
//
//   - Slices (`[]byte`) are reference types — like a Java array but with
//     dynamic length. They are views into an underlying array.
//     `make([]byte, 32)` allocates a 32-byte slice (like `new byte[32]`).
//     `make([]byte, 0, 32)` allocates zero-length with 32 bytes of capacity.
//
//   - Multiple return values replace exceptions for expected error cases.
//     Functions return `(result, error)` and callers check `if err != nil`.
//     This is idiomatic Go — no try/catch.
//
//   - `defer` schedules a function to run when the enclosing function returns,
//     similar to Java's try-finally or try-with-resources, but more flexible.
//     Deferred calls run in LIFO order (stack).
//
//   - `:=` declares and initializes a variable with type inference (like
//     Java's `var` since Java 10). `var x Type` declares with explicit type.
//
//   - The blank identifier `_` discards a return value (e.g., `v, _ := f()`
//     ignores the error). Use sparingly — only when the value is truly irrelevant.
//
//   - Go has pointers (`*Type`) like Java references, but they are explicit
//     and support arithmetic only via the `unsafe` package (avoid it).
//     `&x` takes the address (like Java's implicit reference for objects).
//
// # Memory Security Limitations
//
// This package makes a best-effort attempt to protect key material in memory
// via mlock (to prevent swapping) and ZeroBytes (to overwrite secrets after
// use). However, Go's garbage collector may copy heap-allocated byte slices
// during compaction, leaving residual copies in freed memory that cannot be
// zeroed by application code. Callers requiring stronger memory-residency
// guarantees should consider a C or Rust implementation where allocations
// can be pinned and page-protected.
package crypto

import (
	// "crypto/rand" is Go's CSPRNG — like Java's SecureRandom.
	// rand.Reader is a global io.Reader backed by the OS entropy source
	// (/dev/urandom on Linux, CNG on Windows).
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math/big"
	"runtime"

	"github.com/vilshansen/cipherforge-go/internal/format"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// RandReader returns the source of cryptographically secure random bytes.
// In Go, io.Reader is an interface with a single method:
//
//	Read(p []byte) (n int, err error)
//
// This is analogous to Java's InputStream.read(byte[]), but Go interfaces
// are satisfied implicitly — any type with a Read([]byte) (int, error) method
// implements io.Reader automatically. No `implements` keyword needed.
func RandReader() io.Reader {
	return rand.Reader
}

// Go constants are declared with `const` (like Java's static final).
// They can be typed or untyped. Untyped constants have arbitrary precision
// until assigned to a typed variable.
const (
	SaltSize   = 16 // 128-bit salt
	XNonceSize = 24 // 192-bit nonce for XChaCha20
)

// DeriveMasterKey derives a master key from password using Argon2id.
//
// The password is a `[]byte` (byte slice), NOT a Go `string`. This matters:
// Go strings are immutable and interned — once created, the runtime may hold
// copies in memory forever with no way to zero them (like Java's String pool,
// but even harder to clear). Byte slices give us control: we can overwrite
// them with ZeroBytes() after use.
//
// This is called once per password, then file-specific keys are derived from
// the master key using DeriveKeysFromMaster for better performance in batch
// encryption. The fixed salt "cipherforge-master-key-v1" means the master key
// is deterministic for a given (password, params) pair — the per-file
// uniqueness comes from the HKDF salt in DeriveKeysFromMaster.
func DeriveMasterKey(password []byte, params format.Argon2Params) []byte {
	// argon2.IDKey is the Argon2id variant (hybrid of Argon2i + Argon2d).
	// Parameters: password, salt, time (passes), memory (KiB), threads,
	// output length in bytes.
	masterKey := argon2.IDKey(
		password,
		[]byte(format.MasterKeySalt), // Convert string to []byte (not free — allocates)
		params.Time,
		params.Memory,
		params.Threads,
		32, // 256-bit key
	)
	// Attempt to lock the key in physical RAM so it cannot be swapped to disk.
	// Failure is non-fatal — see mlock_unix.go / mlock_windows.go.
	MlockBytes(masterKey)
	return masterKey
}

// DeriveKeysFromMaster derives two independent 32-byte keys from a master key
// and file-specific salt using HKDF-SHA256 (RFC 5869).
//
// In Java terms, this is like:
//
//	var hkdf = new HKDFBytesGenerator(new SHA256Digest());
//	hkdf.init(new HKDFParameters(masterKey, fileSalt, contextInfo));
//	byte[] raw = new byte[64];
//	hkdf.generateBytes(raw, 0, 64);
//
// Go's HKDF implements io.Reader — you read from it like a stream.
// `io.ReadFull(r, raw)` reads exactly len(raw) bytes, erroring on short read.
// This is like Java's DataInputStream.readFully().
//
// The 64-byte output is split into two 32-byte halves: encKey and macKey.
// These serve entirely different cryptographic purposes and are never used
// interchangeably. HKDF's domain separation via the info parameter ensures
// they are computationally independent.
//
// Named return values: `(encKey, macKey []byte)` names the return variables.
// A bare `return` returns the current values of those named variables.
// This function uses explicit `return encKey, macKey` for clarity.
func DeriveKeysFromMaster(masterKey, fileSalt []byte) (encKey, macKey []byte) {
	// hkdf.New creates an HKDF reader. Parameters:
	//   - hash function (sha256.New returns a hash.Hash, which is a factory)
	//   - ikm (input keying material — the master key)
	//   - salt (per-file random salt for domain separation)
	//   - info (context string — domain separation tag)
	r := hkdf.New(sha256.New, masterKey, fileSalt, []byte(format.FileKeyContext))
	raw := make([]byte, 64)
	if _, err := io.ReadFull(r, raw); err != nil {
		// HKDF-SHA256 should never fail for 64 bytes of output, but we
		// handle the error to satisfy the io.Reader contract.
		return nil, nil
	}
	// In Go, `make([]byte, 32)` allocates a 32-byte slice initialized to zero.
	// This is like `new byte[32]` in Java.
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	// copy() is Go's System.arraycopy(). It copies min(len(dst), len(src)) bytes.
	copy(encKey, raw[:32]) // raw[:32] is a slice view of the first 32 bytes
	copy(macKey, raw[32:]) // raw[32:] is a slice view from byte 32 to end
	ZeroBytes(raw)         // Wipe the intermediate buffer immediately
	MlockBytes(encKey)
	MlockBytes(macKey)
	return encKey, macKey
}

// DeriveKey is a convenience wrapper around DeriveKeys for callers that only
// need the encryption key. The underscore `_` discards the macKey — Go's way
// of saying "I know this function returns two values; I only want the first."
func DeriveKey(password, salt []byte, params format.Argon2Params) []byte {
	encKey, _ := DeriveKeys(password, salt, params)
	return encKey
}

// DeriveKeys derives two independent 32-byte keys from a single Argon2id run.
// This is the legacy v2 approach — one Argon2id call produces 64 bytes split
// into two keys. v3+ uses the two-tier approach: DeriveMasterKey (one expensive
// Argon2id call per password) + DeriveKeysFromMaster (fast HKDF per file).
//
// Go note: functions with the same name but different parameters are NOT
// allowed in Go (no method overloading). However, this package exports both
// DeriveKey (singular) and DeriveKeys (plural) as distinct functions.
func DeriveKeys(password, salt []byte, params format.Argon2Params) (encKey, macKey []byte) {
	raw := argon2.IDKey(
		password,
		salt,
		params.Time,
		params.Memory,
		params.Threads,
		64, // Double output for two 32-byte keys
	)
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(encKey, raw[:32])
	copy(macKey, raw[32:])
	ZeroBytes(raw)
	MlockBytes(encKey)
	MlockBytes(macKey)
	return encKey, macKey
}

// GenerateSalt creates a 16-byte random salt for the KDF using crypto/rand.
//
// Go error handling idiom:
//
//	salt, err := GenerateSalt()
//	if err != nil {
//	    // handle error — return, log, or panic (reserved for unrecoverable errors)
//	    return err
//	}
//	// use salt...
//
// This is Go's equivalent of:
//
//	try {
//	    byte[] salt = GenerateSalt();
//	} catch (Exception e) {
//	    // handle...
//	}
//
// Go chooses explicit error returns over exceptions for all "expected" error
// conditions (I/O failures, invalid input, etc.). True panics are only for
// programmer errors (nil pointer dereference, out-of-bounds, etc.) and are
// NOT caught in idiomatic Go outside of process boundaries.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err // nil is Go's null
	}
	return salt, nil
}

// GenerateNonce creates a random 24-byte (192-bit) nonce using crypto/rand.
// This is used directly in the legacy v1/v2 path; v3 uses HKDF-derived nonces
// from the Segment Seed instead.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, XNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// GenerateSecurePassword generates a cryptographically secure, random password
// from the given character pool.
//
// Uses rejection sampling via crypto/rand.Int to avoid modulo bias:
//   - crypto/rand.Int(reader, limit) returns a uniform random integer in [0, limit)
//   - This is like Java's SecureRandom.nextInt(limit) but with cryptographic
//     guarantees (Java's nextInt(int) is NOT guaranteed to be
//     cryptographically uniform).
//
// The password is returned as []byte, not string — same rationale as the key
// material: byte slices can be zeroed after use. A string would be permanently
// stuck in memory.
func GenerateSecurePassword(length int, pool string) ([]byte, error) {
	if length <= 0 {
		// fmt.Errorf creates an error value (like `new Exception(msg)`).
		// The %w verb wraps another error — see fmt.Errorf("...: %w", err)
		// for the equivalent of Java's `new Exception("...", cause)`.
		return nil, fmt.Errorf("length must be positive")
	}

	// Go's big.Int is like Java's BigInteger.
	limit := big.NewInt(int64(len(pool)))
	// make([]byte, 0, length): zero-length slice with `length` bytes of
	// pre-allocated capacity. This avoids reallocations during append().
	password := make([]byte, 0, length)

	// Go's for loop: `for init; condition; post { }` — same as Java.
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to read random byte: %w", err)
		}
		// append() adds to a slice, growing it if needed.
		// pool[n.Int64()] indexes the string — Go strings are UTF-8 encoded
		// byte sequences, but for ASCII pools, indexing gives the byte directly.
		password = append(password, pool[n.Int64()])
	}

	MlockBytes(password)
	return password, nil
}

// ZeroBytes overwrites the given byte slice with zeros.
//
// Java equivalent:
//
//	Arrays.fill(b, (byte) 0);
//
// BUT — critically — Go adds `runtime.KeepAlive(b)` at the end. Without this,
// the Go compiler might detect that `b` is never read after the zeroing loop
// and optimize the entire loop away as a "dead store." `runtime.KeepAlive`
// marks `b` as "still live" at that point, preventing this optimization.
// Java has a similar problem: the JIT may eliminate `Arrays.fill()` calls
// on arrays that are about to be garbage collected.
//
// Even with KeepAlive, Go's garbage collector may have already copied the
// underlying array during compaction, leaving residual secrets in old memory
// regions. This is a known limitation — see the package doc.
func ZeroBytes(b []byte) {
	// `for i := range b` iterates over indices (not values). This is like:
	//   for (int i = 0; i < b.length; i++) { b[i] = 0; }
	// To iterate over values: `for _, v := range b` (v is a copy of each element).
	// To iterate over both: `for i, v := range b`.
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
