package constants

// Version and GitCommit are typically set during the build process
// using -ldflags="-X '...'" to provide traceability for the binary.
var GitCommit, Version = "unknown", "unknown"

const (
	// XNonceSize is 24 bytes (192 bits). This is large enough that
	// random nonces can be generated for every segment without
	// risk of collision, unlike standard ChaCha20's 96-bit nonce.
	XNonceSize = 24

	// PasswordLength is set to 55. With a 32-character pool (5 bits/char),
	// this provides ~275 bits of entropy, perfectly saturating the
	// 256-bit XChaCha20 key even with slight overhead.
	PasswordLength = 55

	// CharacterPool uses Base32 (0-9, A-Z excluding confusing chars).
	// This makes generated passwords human-readable and easy to type.
	CharacterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// SegmentSize is 1MiB. This balance ensures high performance
	// on modern CPUs while keeping the memory footprint low.
	SegmentSize = 1048576

	FileExtension = ".cfo"

	// SaltSize is 16 bytes (128 bits), the standard recommendation
	// for Argon2id to ensure unique keys for identical passwords.
	SaltSize = 16

	// Argon2id parameters (Hardened):
	// Time: 3 passes for strong memory-hard processing.
	// Memory: 256MiB of RAM to make GPU/ASIC brute-forcing
	// significantly more expensive than the original 64MB.
	// Threads: 4 to utilize multi-core parallelism.
	Argon2Time    = 3
	Argon2Memory  = 256 * 1024
	Argon2Threads = 4
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

USAGE

  cipherforge [options]

OPTIONS

  -e <path>    Encrypt a file or a pattern of files (e.g., "data/*.txt").
  -d <path>    Decrypt a .cfo file or a pattern of .cfo files.

EXAMPLES

  Encrypt a single file:
    cipherforge -e document.pdf

  Encrypt all jpg files in a folder:
    cipherforge -e "images/*.jpg"

  Decrypt an encrypted file:
    cipherforge -d document.pdf.cfo

ENCRYPTION PROCESS

  Key Derivation: A 16-byte random salt is generated and stored at the 
  beginning of the file. The auto-generated password is processed using 
  the Argon2id key derivation function with hardened parameters (Time: 3,
  Memory: 256MB, Threads: 4) to produce a 32-byte cryptographic key.
  This ensures high resistance against GPU and ASIC-based brute-force
  attempts.

  Nonce Management: A 24-byte Master Nonce is generated randomly and stored
  in the file header. To maintain unique keystreams without per-segment
  overhead, each 1MB segment derives its own unique nonce by XORing the
  Master Nonce with the current 64-bit segment counter.

  Segmentation: To handle large files efficiently, the input is divided
  into segments of up to 1MB (1,048,576 bytes). This streaming approach
  allows for a constant and predictable memory footprint regardless of
  the total file size.

  Authentication & Integrity: Each segment is protected by a 16-byte
  Poly1305 Authentication Tag. The Additional Authenticated Data (AAD)
  cryptographically binds the segment counter and the segment length to
  the ciphertext. This prevents attackers from reordering, truncating, or
  deleting individual segments without detection.

  OOM Safeguards: During decryption, the system validates the 8-byte
  segment length field before memory allocation. If a length exceeds
  the maximum allowed (1MB + overhead), the process aborts to prevent
  memory-exhaustion attacks.

ENCODED BINARY FILE FORMAT

  The encrypted file is a binary structure consisting of a fixed-size header
  containing the Argon2id salt, followed immediately by the encrypted payload. 
  All multi-byte values (lengths and parameters) are written using big-endian 
  byte order. XChaCha20 counter is represented in big-endian format.

DIAGRAM OF BINARY LAYOUT

+--------------------------------------------------------------------+
|                         FILE HEADER (ONCE)                         |
+------------------+--------------------+----------+-----------------+
| Field Name       | Data Type          | Length   | Value           |
|------------------+--------------------+----------+-----------------|
| Salt             | byte array         | 16 bytes | Argon2id Salt   |
| Master Nonce     | byte array         | 24 bytes | XChaCha20 Nonce |
+------------------+--------------------+----------+-----------------+
|            ENCRYPTED PAYLOAD DETAILS (REPEAT UNTIL EOF)            |
+------------------+--------------------+----------+-----------------+
| Field Name       | Data Type          | Length   | Value/Purpose   |
|------------------+--------------------+----------+-----------------|
| Segment Length   | uint64             | 8 bytes  | Ciphertext+Tag  |
| Ciphertext       | byte array         | <= 1 MiB | Encrypted data  |
| Poly1305 Tag     | byte array         | 16 bytes | Auth tag        |
|------------------+--------------------+----------+-----------------|
|                              NOTES                                 |
|------------------+--------------------+----------+-----------------|
|                                                                    |
| 1. Nonce Derivation: Every segment derives a unique nonce by       |
|    XORing the Master Nonce with the 64-bit Segment Counter.        |
| 2. Authenticated Integrity: Segment Counter and Segment Length are |
|    included in the Additional Authenticated Data (AAD) to prevent  |
|    reordering, truncation, or segment substitution attacks.        |
| 3. Efficiency: The Master Nonce is written once in the header,     |
|    saving 24 bytes per 1 MiB segment vs. per-segment nonce.        |
| 4. OOM Protection: Segment Length is validated against the maximum |
|    allowed size (1 MiB + overhead) before memory is allocated.     |
| 5. Batch Processing: The structure repeats the [Length +           |
|    Ciphertext + Tag] sequence until the end of the file (EOF).     |
+--------------------------------------------------------------------+
`
