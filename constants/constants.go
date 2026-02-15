package constants

var GitCommit, Version = "unknown", "unknown"

const (
	XNonceSize     = 24
	PasswordLength = 55
	CharacterPool  = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	SegmentSize    = 1048576 // 1 MiB
	FileExtension  = ".cfo"
	SaltSize       = 16

	// Argon2id parameters
	Argon2Time    = 3
	Argon2Memory  = 64 * 1024
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
  the Argon2id key derivation function (Time: 3, Memory: 64MB,
  Threads: 4) to produce a 32-byte cryptographic key.

  Segmentation: To handle large files efficiently, the input is divided 
  into segments of up to 1MB. Each segment is encrypted independently
  using a unique 24-byte random nonce.

  Authentication: Each segment is protected by a 16-byte Poly1305 
  Authentication Tag. The Additional Authenticated Data (AAD) includes 
  a 64-bit segment counter and the segment length to prevent reordering,
  truncation, or deletion attacks. Each encrypted segment (the encrypted 
  data and a 16-byte Poly1305 Authentication Tag) is prefixed with an 
  8-byte length field before being written to the file.

ENCODED BINARY FILE FORMAT

  The encrypted file is a binary structure consisting of a fixed-size header
  containing the Argon2id salt, followed immediately by the encrypted payload. 
  All multi-byte values (lengths and parameters) are written using big-endian 
  byte order. XChaCha20 counter is represented in big-endian format.

DIAGRAM OF BINARY LAYOUT

  +----------------------- FILE HEADER (ONCE) -------------------------+
  | Field Name       | Data Type          | Length   | Value           |
  |------------------+--------------------+----------+-----------------|
  | Salt             | byte array         | 16 bytes | Argon2id Salt   |
  +------------------+--------------------+----------+-----------------+
  |                                                                    |
  +----------- ENCRYPTED PAYLOAD DETAILS (VARIABLE LENGTH) ------------+
  | Field Name       | Data Type          | Length   | Value/Purpose   |
  |------------------+--------------------+----------+-----------------|
  | XChaCha Nonce    | byte array         | 24 bytes | 24-byte nonce   |
  | Segment Length   | uint64             | 8 bytes  | Ciphertext+Tag  |
  | Ciphertext       | byte array         | <= 1 MB  | Encrypted data  |
  | Poly1305 tag     | byte array         | 16 bytes | Auth tag        |
  |------------------+--------------------+----------+-----------------|
  | All segment-specific metadata (Counter and Segment Length) is      |
  | included in the XChaCha20 Additional Authenticated Data (AAD).     |
  | This cryptographically binds each segment to its position.         |
  | Repeat Nonce + Length + Ciphertext + Tag structure until EOF.      |
  | Decrypted segments contain the original plaintext data.            |
  +--------------------------------------------------------------------+
`
