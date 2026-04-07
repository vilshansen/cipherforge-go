package constants

// Version and GitCommit are typically set during the build process
// using -ldflags="-X '...'" to provide traceability for the binary.
var GitCommit, Version = "unknown", "unknown"

const (
	// Magic is an 8-byte file signature that identifies a Cipherforge
	// encrypted file. The value 0xC1PHRF0RGE is encoded as ASCII bytes.
	// It allows tools and the decoder to quickly reject non-.cfo files
	// before attempting key derivation.
	Magic = "\xC1\x50\x48\x52\x46\x30\x52\x47" // 0xC1 P H R F 0 R G

	// MagicSize is the length of the magic header in bytes.
	MagicSize = 8

	// FileVersion is a 4-byte big-endian version field written immediately
	// after the magic bytes. Version 1 (0x00000001) is the initial format.
	// Incrementing this value in future releases allows the decoder to
	// detect and reject (or handle) files written by a different format
	// revision without silently producing garbage output.
	FileVersion = uint32(1)

	// VersionSize is the length of the version field in bytes.
	VersionSize = 4

	// XNonceSize is 24 bytes (192 bits). This is large enough that
	// random nonces can be generated for every segment without
	// risk of collision, unlike standard ChaCha20's 96-bit nonce.
	XNonceSize = 24

	// PasswordLength is set to 55. With a 32-character pool (5 bits/char),
	// this provides ~275 bits of raw password entropy. However, the effective
	// security is bounded by the 256-bit Argon2id output key, so any length
	// above ~52 characters (~260 bits) yields no additional cryptographic
	// benefit. 55 is kept for a comfortable margin and human usability.
	PasswordLength = 55

	// CharacterPool uses Base32 (0-9, A-Z excluding confusing chars).
	// This makes generated passwords human-readable and easy to type.
	CharacterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// SegmentSize is 1MiB. This balance ensures high performance
	// on modern CPUs while keeping the memory footprint low.
	SegmentSize = 1048576

	FileExtension = ".cfo"

	// HMACSize is 32 bytes — the output size of HMAC-SHA256.
	HMACSize = 32

	// TrailerSize is the fixed size of the file trailer written after all
	// encrypted segments. It holds the segment count (8 bytes) followed by
	// the HMAC-SHA256 that authenticates the file header (salt + master nonce)
	// and the total segment count, binding them cryptographically to the payload.
	// Storing the segment count explicitly in the trailer eliminates the need
	// for a pre-decryption scanning pass to discover it.
	TrailerSize = 8 + HMACSize

	// SaltSize is 16 bytes (128 bits), the standard recommendation
	// for Argon2id to ensure unique keys for identical passwords.
	SaltSize = 16
)

// Argon2id parameters are declared as variables rather than constants so that
// tests can substitute minimal values (t=1, m=64KiB) to avoid allocating 1 GiB
// per DeriveKeys call. Production binaries always start with the hardened
// defaults below; the values are never mutated outside of test setup.
//
// Hardened defaults:
//   - Time:    4 passes
//   - Memory:  1 GiB  — makes GPU/ASIC brute-forcing very expensive
//   - Threads: 4      — utilises multi-core parallelism
var (
	Argon2Time    uint32 = 4
	Argon2Memory  uint32 = 1024 * 1024
	Argon2Threads uint8  = 4
)

const HelpTextShort = `Cipherforge v%s (commit: %s)`

const HelpText = HelpTextShort + `
Secure File Encryption & Decryption
Copyright (c) 2026 Peter Vils Hansen

Cipherforge is a utility for encrypting and decrypting files using strong,
modern cryptographic standards (XChaCha20-Poly1305 and Argon2id).
It is designed to be simple, secure, and cross-platform, with a
focus on usability and security best practices. Files are encrypted in 1MB
segments to support large files without loading them entirely into memory.

CRYPTOGRAPHIC DESIGN

  Algorithm: XChaCha20-Poly1305 is an Authenticated Encryption with
  Associated Data (AEAD) cipher providing both confidentiality and
  integrity. The 192-bit (24-byte) nonce makes random-per-segment nonce
  generation safe without risk of collision, unlike the 96-bit nonce of
  standard ChaCha20-Poly1305.

  Key Derivation: Argon2id (RFC 9106) is used to derive all key material.
  It is a memory-hard function that makes brute-force attacks expensive by
  requiring large amounts of RAM (1GiB) in addition to computation time.
  Parameters are set well above current OWASP minimum recommendations: time=4,
  memory=1GiB, threads=4.

  Password Generation: Passwords are generated using cryptographically
  secure random bytes (crypto/rand) with rejection sampling to eliminate
  modulo bias, ensuring every character in the 32-character pool has an
  exactly equal probability of selection. At 55 characters from a
  32-character Base32 pool (~5 bits per character), each password carries
  approximately 275 bits of raw entropy — bounded in practice by the
  256-bit key. Passwords are formatted in groups of five separated by
  hyphens for readability.

  Key Separation: A single Argon2id invocation produces 64 bytes of key
  material. Bytes 0–31 serve as the XChaCha20-Poly1305 encryption key;
  bytes 32–63 serve as the HMAC-SHA256 trailer key. The two keys are
  non-overlapping outputs of the same PRF and are never used for the same
  cryptographic operation, providing domain separation while paying the
  Argon2id cost only once.

  Nonce Derivation: Per-segment nonces are derived via HKDF-SHA256
  (RFC 5869, NIST SP 800-56C) using the Master Nonce as input key
  material and the 64-bit segment counter as the info field. HKDF is
  a one-way function: given any number of derived nonces and their
  counters, the Master Nonce remains computationally hidden. It also
  carries no identity-at-zero property (counter=0 does not yield the
  raw Master Nonce), unlike XOR-based derivation.

  Post-Quantum Security: The symmetric primitives used (XChaCha20-Poly1305,
  HMAC-SHA256, Argon2id) are not vulnerable to quantum attacks in the same
  way as public-key cryptography. Against Grover's algorithm, a 256-bit
  key provides approximately 128 bits of post-quantum security, which is
  considered sufficient by current cryptographic guidance (NIST SP 800-57).

  Memory Safety: Sensitive material (passwords, derived keys) is stored in
  byte slices rather than Go strings to prevent interning on the heap.
  All such slices are explicitly zeroed via runtime.KeepAlive-guarded loops
  immediately after use, mitigating cold-boot and memory-scraping attacks.

USAGE

  cipherforge [options]

OPTIONS

  -e <path>    Encrypt a file or a pattern of files (e.g., "data/*.txt").
  -d <path>    Decrypt a .cfo file or a pattern of .cfo files.
  -p [value]   Supply a password instead of using the auto-generated one.
               If a value is given on the command line (e.g., -p mypass),
               it is used directly. If omitted, an interactive prompt is
               shown; input is masked with '*' characters and, for
               encryption, the password must be entered twice to confirm.
               WARNING: passing the password on the command line may expose
               it via shell history or process listings. Prefer the
               interactive form for sensitive use.

EXAMPLES

  Encrypt a single file (auto-generated password):
    cipherforge -e document.pdf

  Encrypt with an interactively entered password (starred input, confirmed):
    cipherforge -e document.pdf -p

  Encrypt with a password supplied directly on the command line:
    cipherforge -e document.pdf -p "my-passphrase"

  Encrypt all jpg files in a folder:
    cipherforge -e "images/*.jpg"

  Decrypt an encrypted file (silent password prompt):
    cipherforge -d document.pdf.cfo

  Decrypt with an interactively entered password (starred input):
    cipherforge -d document.pdf.cfo -p

  Decrypt with a password supplied directly on the command line:
    cipherforge -d document.pdf.cfo -p "my-passphrase"

ENCRYPTION PROCESS

  Key Derivation: A 16-byte random salt is generated and stored at the
  beginning of the file. The auto-generated password is processed using
  the Argon2id key derivation function with hardened parameters (Time: 4,
  Memory: 1GiB, Threads: 4) to produce 64 bytes of key material. The
  first 32 bytes are used as the XChaCha20-Poly1305 encryption key; the
  remaining 32 bytes are used as a separate HMAC-SHA256 key for the file
  trailer. Deriving both keys from a single Argon2id invocation avoids
  paying the KDF cost twice while keeping the two keys fully independent.

  Nonce Management: A 24-byte Master Nonce is generated randomly and stored
  once in the file header. Each 1MB segment derives its own unique nonce via
  HKDF-SHA256 (RFC 5869), using the Master Nonce as the IKM and the 64-bit
  segment counter as the info field. This is cryptographically stronger than
  XOR-based derivation: it is a one-way function with no identity-at-zero
  property (counter=0 does not yield the raw Master Nonce) and is
  standardised by NIST SP 800-56C for exactly this purpose. Storing the
  Master Nonce once in the header rather than repeating a full nonce per
  segment saves 24 bytes per 1MiB of ciphertext.

  Segmentation: To handle large files efficiently, the input is divided
  into segments of up to 1MB (1,048,576 bytes). The payload region of the
  file consists of repeating [Length (8 bytes) + Ciphertext + Poly1305 Tag]
  triplets from the start of the payload until the trailer begins 40 bytes
  before EOF. This streaming approach allows for a constant and predictable
  memory footprint regardless of the total file size.

  Authentication & Integrity: Each segment is protected by a 16-byte
  Poly1305 Authentication Tag. The Additional Authenticated Data (AAD)
  cryptographically binds the segment counter and the plaintext segment
  length to the ciphertext. This prevents attackers from reordering,
  truncating, or deleting individual segments without detection.

  File-Level Authentication: After all segments are written, a 40-byte
  trailer is appended containing the segment count (8 bytes) followed by
  HMAC-SHA256(macKey, salt || masterNonce || segmentCount). This binds the
  header fields and total segment count to the payload, preventing header
  substitution (swapping the salt or nonce from another file), file
  truncation, and segment appending — all attacks that per-segment AEAD
  cannot detect. On decryption, the trailer is read and verified before any
  plaintext is written to disk. A wrong password is also detected here
  immediately, without streaming the entire file. Storing the segment count
  explicitly in the trailer also eliminates the need for a pre-decryption
  scanning pass, making decryption a single sequential read.

  OOM Safeguards: During decryption, the system validates the 8-byte
  segment length field before memory allocation. If a length exceeds
  the maximum allowed (1MB + overhead), the process aborts to prevent
  memory-exhaustion attacks.

  Partial Output Cleanup: If encryption or decryption fails at any point,
  the incomplete output file is automatically removed. This prevents
  truncated ciphertext or partial plaintext from being left on disk.

LONG-TERM ARCHIVAL CONSIDERATIONS

  Cipherforge is designed with long-term recoverability in mind. It is
  written in Go, which compiles to self-contained static binaries with no
  runtime dependencies, maximising the chance that a binary built today
  will execute on future operating systems without modification. The Go
  toolchain's backwards-compatibility guarantee further ensures that the
  source code can be recompiled years from now against a current compiler.

  All cryptographic primitives (XChaCha20-Poly1305, Argon2id, HMAC-SHA256,
  HKDF-SHA256) are published IETF or NIST standards. Should the compiled
  binary become unavailable on a future platform, the file format is fully
  specified below and can be reimplemented from first principles using any
  standards-conformant cryptographic library.

  Note: The output filename is derived from the input filename
  (e.g., document.pdf → document.pdf.cfo), which means the original
  filename and extension remain visible in the filesystem. Consider this
  when storing encrypted archives in shared or cloud-hosted locations.

ENCODED BINARY FILE FORMAT

  The encrypted file is a binary structure consisting of a fixed-size
  header containing the Argon2id salt, followed immediately by the
  encrypted payload. All multi-byte values (lengths and parameters)
  are written using big-endian byte order. XChaCha20 counter is
  represented in big-endian format.

DIAGRAM OF BINARY LAYOUT

+------------------------------------------------------------------------+
|                           FILE HEADER (ONCE)                           |
+-------------------+---------------------+-----------+------------------+
| Field Name        | Data Type           | Length    | Value            |
+-------------------+---------------------+-----------+------------------+
| Magic             | byte array          | 8 bytes   | 0xC1PHRF0RGE     |
| Version           | uint32 (big-endian) | 4 bytes   | 0x00000001       |
| Salt              | byte array          | 16 bytes  | Argon2id Salt    |
| Master Nonce      | byte array          | 24 bytes  | XChaCha20 Nonce  |
+-------------------+---------------------+-----------+------------------+
|              ENCRYPTED PAYLOAD DETAILS (REPEAT UNTIL EOF-32)           |
+-------------------+---------------------+-----------+------------------+
| Field Name        | Data Type           | Length    | Value/Purpose    |
+-------------------+---------------------+-----------+------------------+
| Segment Length    | uint64              | 8 bytes   | Ciphertext+Tag   |
| Ciphertext        | byte array          | <= 1 MiB  | Encrypted data   |
| Poly1305 Tag      | byte array          | 16 bytes  | Auth tag         |
+-------------------+---------------------+-----------+------------------+
|                          FILE TRAILER (ONCE)                           |
+-------------------+---------------------+-----------+------------------+
| Field Name        | Data Type           | Length    | Value/Purpose    |
+-------------------+---------------------+-----------+------------------+
| Segment Count     | uint64              | 8 bytes   | Total segments   |
| Trailer HMAC      | byte array          | 32 bytes  | HMAC-SHA256      |
+-------------------+---------------------+-----------+------------------+
`