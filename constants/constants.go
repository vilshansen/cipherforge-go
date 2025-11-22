package constants

var GitCommit string = "unknown"
var Version string = "unknown"

const (
	// If Argon2id is not available, use scrypt with a minimum CPU/memory
	// cost parameter of (2^17), a minimum block size of 8 (1024 bytes),
	// and a parallelization parameter of 1.
	// Source: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
	MagicMarker    = "CIPHERFORGE"
	KeySize        = 32 // 256-bit XChaCha20 nøgle
	XNonceSize     = 24 // 192-bit XChaCha20 Nonce (Extended Nonce)
	TagSize        = 16 // 128-bit Poly1305 autentificeringstag
	PasswordLength = 45 // Standard længde for tilfældigt password.
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

// HelpText indeholder den fulde, formaterede hjælpevejledning til CLI-værktøjet.
const HelpText = `
Cipherforge v%s (commit: %s)
Secure File Encryption & Decryption
Copyright (c) 2025 Peter Vils Hansen

Cipherforge is a utility for encrypting and decrypting files using strong,
modern cryptographic standards (XChaCha20-Poly1305 and scrypt key 
derivation).

USAGE:
  cipherforge [COMMAND] <input_file> [-p [pass_phrase]]

COMMANDS:
  -ef, --encrypt           Encrypts the specified input file(s).
  -df, --decrypt           Decrypts the specified input file(s).

OPTIONS:
  -i, --input <file(s)>   Path to the input file(s) (to be encrypted or 
                          decrypted). Note: Quotes are required for
                          wildcard arguments.
  -o, --output <file(s)>  Path for the output file (ciphertext or 
                          plaintext).
  -p, --password <word>   Optionally, provides the password directly via
                          command line.
                          
                          If this flag is omitted when encrypting, a
                          random, strong password is generated and
                          displayed. If this flag is omitted when de-
                          crypting, the user is prompted for a passphrase.
                          
                          For security, interactive entry is always
                          preferred for decryption to prevent logging the
                          password in shell history.

EXAMPLES:
  # Encrypt file using an auto-generated password:
  cipherforge -ef secrets.txt
  
  # Encrypt all text files using a supplied password:
  cipherforge -ef "*.txt" -p VerySecretPassword
  
  # Decrypt file (prompts for password):
  cipherforge -df secrets.cfo

  # Decrypt all text files using a supplied password:
  cipherforge -df "*.txt" -p VerySecretPassword

SOURCE CODE:
  https://github.com/vilshansen/cipherforge-go/

TECHNICAL SPECIFICATION AND FORMAT:

CipherForge is written in Go (Golang) and distributed as a static, cross-
platform executable supporting major operating systems, including Linux,
Windows, and macOS (Darwin), on both amd64 and arm64 architectures. The
current stable version (v1.00) was first published in 2025.

TECHNICAL IMPLEMENTATION:

CipherForge takes its input from the specified file(s) and must be
explicitly instructed to encrypt or decrypt (via -ef or -df).

ENCRYPTION PROCESS:

The file undergoes a two-step streaming process: Compression then Encryption.

1. Compression: The plaintext input is compressed using GZIP. This is 
   crucial for securing file boundaries and reducing final file size.

2. Key Derivation: A 16-byte random salt (s) and a 32-byte (256-bit) 
   encryption key (K) are derived from the user's password (p) using the 
   high-cost scrypt key derivation algorithm (KDF). The full function 
   signature is defined as: K = scrypt(p, s, N, R, P, len).

Where:

K   : The resulting 32-byte derived encryption key.
p   : The user-provided password (pass phrase).
s   : The 16-byte random salt used to diversify the output.
N   : The CPU/Memory Cost Parameter
R   : The Block Size Parameter
P   : The Parallelization Parameter
len : The desired length of the derived key

The default parameters used for encryption are currently N=2^18 (262144),
R=8, P=1, and len is 32 bytes (256 bits).

A 16-byte fixed nonce prefix (initialization vector) is generated and 
stored in the file header, followed by an 8-byte zero counter, resulting 
in the required 24-byte nonce for XChaCha20-Poly1305. For each data 
segment, the 8-byte counter is incremented, ensuring a unique, non-
repeating 24-byte nonce is used for every encrypted chunk. This entire 
file header is included in the Additional Authenticated Data (AAD).

The compressed data is then encrypted in segments (chunks) of up to 
64KB. Each segment's resulting ciphertext (which includes a 16-byte Poly1305 
Authentication Tag) is prefixed with an 8-byte length field before being 
written to the file.

During decryption and verification, the entire header is read and the Magic
Marker (a unique CipherForge file format identifier) is validated. The salt,
nonce, and scrypt Parameters (N, R, P) are extracted from the header. The
encryption key is derived using the user-provided password and the extracted
KDF parameters. The remaining file content (ciphertext + authentication tag)
is processed segment-by-segment. The re-derived key, nonce, ciphertext, and 
the full header (as AAD) are passed to the aead.Open() function. The Poly1305 
tag verification (authentication check) must succeed to recover the plaintext. 
Failure results in an authentication failure, preventing the output of tampered
or corrupted data. Only if the authentication succeeds is the plaintext segment 
passed to the GZIP decompression stream.

ENCODED BINARY FILE FORMAT:

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
| Segment Length   | uint64             | 8 bytes  | Length Ciphertext + Tag  |
| Ciphertext + Tag | byte array         | Variable | Enc. GZIP data block +   |
|                  |                    |          | 16-byte tag              |
|------------------+--------------------+----------+--------------------------+
| All header fields are included in the XChaCha20 Additional                  |
| Authenticated Data for complete data integrity.                             |
| Repeat Segment Length + Ciphertext + Tag structure until EOF. Decrypted     |
| segments contain the compressed (GZIP) plaintext data.                      |
+-----------------------------------------------------------------------------+
`
