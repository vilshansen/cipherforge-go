package constants

var GitCommit string = "unknown"
var Version string = "unknown"

const (
	// "If Argon2id is not available, use scrypt with a minimum CPU/memory
	// cost parameter of (2^17), a minimum block size of 8 (1024 bytes),
	// and a parallelization parameter of 1."
	// Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	MagicMarker    = "CIPHERFORGE"
	KeySize        = 32 // 256-bit XChaCha20 key
	XNonceSize     = 24 // 192-bit XChaCha20 Nonce (Extended Nonce)
	TagSize        = 16 // 128-bit Poly1305 authentication tag
	PasswordLength = 55 // Standard length for random password. log2(32) = 5 => 55 * 5 = ~275 bits of entropy.
	// Crockford Base32 character set (omits 0, O, I, L for better readability)
	CharacterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	// ChunkSize defines the maximum size of a data chunk to be encrypted/decrypted.
	ChunkSize = 1048576 // 1 MiB
	// CounterLength is the size of the counter appended to the nonce prefix.
	CounterLength = 8 // uint64 counter
	// NoncePrefixLength is the fixed, random prefix of the 24-byte XChaCha nonce.
	// 24 bytes (XNonceSize) - 8 bytes (Counter) = 16 bytes (Prefix)
	NoncePrefixLength = 16
)

const HelpTextShort = `Cipherforge v%s (commit: %s)`

// HelpText contains the full, formatted help guide for the CLI tool.
const HelpText = HelpTextShort + `
Secure File Encryption & Decryption
Copyright (c) 2026 Peter Vils Hansen

Cipherforge is a utility for encrypting and decrypting files using strong,
modern cryptographic standards (XChaCha20-Poly1305 and strong, random
passwords). It is designed to be simple, secure, and cross-platform, with a
focus on usability and security best practices.

USAGE

  cipherforge [COMMAND] <input_file>

COMMANDS

  -e                      Encrypt the specified input file(s).
  -d                      Decrypt the specified input file(s).
                          
During encryption, a random, strong password is generated and displayed to
ensure cryptographic strength at all times. This also removes the necessity
of key derivation, because the generated passwords are already of sufficient
length and complexity to be used as cryptographic keys directly.

EXAMPLES

  # Encrypt file using an auto-generated password:
  cipherforge -e secrets.txt
  
  # Decrypt file (prompts for password):
  cipherforge -d secrets.cfo

SOURCE CODE

  Full source code is available at:
  https://github.com/vilshansen/cipherforge-go/

TECHNICAL SPECIFICATION AND FORMAT

  CipherForge is written in Go (Golang) and distributed as a static, cross-
  platform executable supporting major operating systems, including Linux,
  Windows, and macOS (Darwin), on both amd64 and arm64 architectures.

ENCRYPTION PROCESS

  The encryption process involves the following key steps:
  
  Key Derivation: A 55-character random password is generated first. This
  password is designed to have high entropy (approximately 275 bits) and is
  created using a secure random number generator. The password is displayed
  to the user at the time of encryption, and it is crucial that the user
  saves this password securely, as it is required for decryption. This
  password is then hashed using SHA-256 to produce a 32-byte key suitable
  for XChaCha20 encryption.

  A 16-byte fixed nonce prefix (initialization vector) is now generated and
  stored in the file header, followed by an 8-byte zero counter, resulting
  in the required 24-byte nonce for XChaCha20-Poly1305. For each data segment,
  the 8-byte counter is incremented, ensuring a unique, non-repeating 24-byte
  nonce is used for every encrypted chunk. This entire file header is included
  in the Additional Authenticated Data (AAD).

  The data is then encrypted in segments of up to 1 MB. Each segment's
  resulting ciphertext (which includes a 16-byte Poly1305 Authentication Tag)
  is prefixed with an 8-byte length field before being written to the file.

ENCODED BINARY FILE FORMAT

  The encrypted file is a binary structure consisting of a fixed-size header
  followed immediately by the encrypted payload. All multi-byte values (lengths
  and parameters) are written using big-endian byte order. XChaCha20 counter is
  represented in little-endian format, as specified in RFC 8439.

DIAGRAM OF BINARY LAYOUT

  +------------------- HEADER (AAD FIELD) DETAILS (67 Bytes) ------------------+
  | Field Name       | Data Type          | Length   | Value/Purpose           |
  |------------------+--------------------+----------+-------------------------+
  | Magic Marker     | string/byte array  | 11 bytes | "CIPHERFORGE"           |
  | Nonce Length     | uint32             | 4 bytes  | XChaCha nonce length    |
  | XChaCha Nonce    | byte array         | 24 bytes | 16-byte fixed prefix +  |
  |                  |                    |          | 8-byte zero counter     |
  +---------------- ENCRYPTED PAYLOAD DETAILS (VARIABLE LENGTH) ---------------+
  | Field Name       | Data Type          | Length   | Value/Purpose           |
  |------------------+--------------------+----------+-------------------------+
  | Segment Length   | uint64             | 8 bytes  | Length Ciphertext + Tag |
  | Ciphertext       | byte array         | <= 1 MB  | Encrypted data block    |
  | Poly1305 tag     | byte array         | 16 bytes | Authentication tag      |
  |------------------+--------------------+----------+-------------------------+
  | All header fields are included in the XChaCha20 Additional Authenticated   |
  | data for complete data integrity. Repeat Segment Length + Ciphertext + Tag |
  | structure until EOF. Decrypted segments contain the plaintext data.        |
  +----------------------------------------------------------------------------+
`
