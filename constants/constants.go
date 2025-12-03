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
	PasswordLength = 45 // Standard length for random password.
	CharacterPool  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ScryptN        = 1 << 18 // 262144, CPU/memory cost parameter
	ScryptR        = 8       // block size
	ScryptP        = 1       // parallelization parameter
	SaltLength     = 16      // 128-bit salt
	// ChunkSize defines the maximum size of a data chunk to be encrypted/decrypted.
	ChunkSize = 65536 // 64 KiB
	// CounterLength is the size of the counter appended to the nonce prefix.
	CounterLength = 8 // uint64 counter
	// NoncePrefixLength is the fixed, random prefix of the 24-byte XChaCha nonce.
	// 24 bytes (XNonceSize) - 8 bytes (Counter) = 16 bytes (Prefix)
	NoncePrefixLength = 16
)

// HelpText contains the full, formatted help guide for the CLI tool.
const HelpText = `Cipherforge v%s (commit: %s)
Secure File Encryption & Decryption
Copyright (c) 2025 Peter Vils Hansen

Cipherforge is a utility for encrypting and decrypting files using strong,
modern cryptographic standards (XChaCha20-Poly1305 and scrypt key 
derivation).

USAGE

  cipherforge [COMMAND] <input_file> [-p [pass_phrase]]

COMMANDS

  -ef                      Encrypts the specified input file(s).
  -df                      Decrypts the specified input file(s).

OPTIONS

  -p <pass phrase>        Optionally, provides the password directly via
                          command line.
                          
                          If this flag is omitted when encrypting, a
                          random, strong password is generated and
                          displayed. If this flag is omitted when de-
                          crypting, the user is prompted for a passphrase.
                          
                          For security, interactive entry is always
                          preferred for decryption to prevent logging the
                          password in shell history.

EXAMPLES

  # Encrypt file using an auto-generated password:
  cipherforge -ef secrets.txt
  
  # Encrypt all text files using a supplied password:
  cipherforge -ef "*.txt" -p VerySecretPassword
  
  # Decrypt file (prompts for password):
  cipherforge -df secrets.cfo

  # Decrypt all text files using a supplied password:
  cipherforge -df "*.txt" -p VerySecretPassword

SOURCE CODE

  Full source code is available at:
  https://github.com/vilshansen/cipherforge-go/

TECHNICAL SPECIFICATION AND FORMAT

  CipherForge is written in Go (Golang) and distributed as a static, cross-
  platform executable supporting major operating systems, including Linux,
  Windows, and macOS (Darwin), on both amd64 and arm64 architectures.

ENCRYPTION PROCESS

  The encryption process involves the following key steps:
  
  Key Derivation: A 16-byte random salt and a 32-byte (256-bit) 
  encryption key are derived from the user's password using the 
  high-cost scrypt key derivation algorithm.
  
  The default parameters used for encryption are currently N=2^18 (CPU/
  Memory cost), R=8 (block size parameter), P=1 (parallelization parameter).
  These parameters provide a strong defense against brute-force attacks
  while balancing performance for typical desktop and server environments.
  The salt and scrypt parameters are stored in the file header to allow
  for future adjustments without breaking compatibility.

  A 16-byte fixed nonce prefix (initialization vector) is generated and 
  stored in the file header, followed by an 8-byte zero counter, resulting
  in the required 24-byte nonce for XChaCha20-Poly1305. For each data 
  segment, the 8-byte counter is incremented, ensuring a unique, non-
  repeating 24-byte nonce is used for every encrypted chunk. This entire 
  file header is included in the Additional Authenticated Data (AAD).

  The data is then encrypted in segments of up to 64KB. Each segment's
  resulting ciphertext (which includes a 16-byte Poly1305 Authentication
  Tag) is prefixed with an 8-byte length field before being written to
  the file.

ENCODED BINARY FILE FORMAT

The encrypted file is a binary structure consisting of a fixed-size header
followed immediately by the encrypted payload. All multi-byte values 
(lengths and parameters) are written using big-endian byte order.

DIAGRAM OF BINARY LAYOUT

  +------------------- HEADER (AAD FIELD) DETAILS (67 Bytes) -------------------+
  | Field Name       | Data Type          | Length   | Value/Purpose            |
  |------------------+--------------------+----------+--------------------------+
  | Magic Marker     | string/byte array  | 11 bytes | "CIPHERFORGE"            |
  | Salt Length      | uint32             | 4 bytes  | Scrypt salt length       |
  | Scrypt Salt      | byte array         | 16 bytes | Random scrypt salt       |
  | Scrypt N         | uint32             | 4 bytes  | CPU/Memory cost          |
  | Scrypt R         | uint32             | 4 bytes  | Block size               |
  | Scrypt P         | uint32             | 4 bytes  | Parallelization          |
  | XChaCha Nonce    | byte array         | 24 bytes | 16-byte fixed prefix +   |
  |                  |                    |          | 8-byte zero counter      |
  +---------------- ENCRYPTED PAYLOAD DETAILS (VARIABLE LENGTH) ----------------+
  | Field Name       | Data Type          | Length   | Value/Purpose            |
  |------------------+--------------------+----------+--------------------------+
  | Segment Length   | uint64             | 8 bytes  | Length Ciphertext + Tag  |
  | Ciphertext       | byte array         | <= 64 KB | Encrypted data block     |
  | Poly1305 tag     | byte array         | 16 bytes | Authentication tag       |
  |------------------+--------------------+----------+--------------------------+
  | All header fields are included in the XChaCha20 Additional Authenticated    |
  | data for complete data integrity. Repeat Segment Length + Ciphertext + Tag  |
  | structure until EOF. Decrypted segments contain the plaintext data.         |
  +-----------------------------------------------------------------------------+
`
