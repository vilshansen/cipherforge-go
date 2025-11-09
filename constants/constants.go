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
  cipherforge [COMMAND] -i <input_file> -o <output_file> [-p [pass_phrase]]

COMMANDS:
  -ef, --encrypt           Encrypts the specified input file.
  -df, --decrypt           Decrypts the specified input file.

OPTIONS:
  -i, --input <file>      Path to the input file (to be encrypted or 
                          decrypted).
  -o, --output <file>     Path for the output file (ciphertext or 
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
  cipherforge -ef -i secrets.txt -o secrets.cfo
  
  # Decrypt file (prompts for password):
  cipherforge -df -i secrets.cfo -o secrets_decrypted.txt

SOURCE CODE:
  https://github.com/vilshansen/cipherforge-go/

TECHNICAL SPECIFICATION AND FORMAT:

CipherForge is written in Go (Golang) and distributed as a static, cross-
platform executable supporting major operating systems, including Linux,
Windows, and macOS (Darwin), on both amd64 and arm64 architectures. The
current stable version (v1.00) was first published in 2025.

TECHNICAL IMPLEMENTATION:

CipherForge takes its input from the specified file (-i) and must be
explicitly instructed to encrypt or decrypt (via -ef or -df).

ENCRYPTION PROCESS:

First, a 16-byte cryptographically secure random salt (s) and a 24-byte
nonce (initialization vector) are generated. The nonce is a unique, non-
repeating random value required by the XChaCha20-Poly1305 cipher mode.

Next, a 32-byte (256-bit) encryption key (K) is derived from the user's
password (p) using the scrypt key derivation algorithm (KDF). The full
function signature is defined as:

K = scrypt(p, s, N, R, P, len).

Where:

K  : The resulting 32-byte derived encryption key.
p  : The user-provided password (pass phrase).
s  : The 16-byte random salt used to diversify the output.
N  : The CPU/Memory Cost Parameter
R  : The Block Size Parameter
P  : The Parallelization Parameter
len: The desired length of the derived key

The default parameters used for encryption are currently N=2^18 (262144),
R=8, P=1, and len is 32 bytes (256 bits).

A structured header containing all necessary metadata and KDF parameters is
constructed and written to the output file. This header is included in the
Authenticated Associated Data (AAD).

The derived encryption key (K) is used to initialize the XChaCha20-Poly1305
AEAD algorithm. The entire plaintext input is encrypted, and a 16-byte
Authentication Tag is generated using the generated Nonce (IV) and the full
header above as the AAD.

During decryption and verification, the entire header is read and the Magic
Marker (a unique CipherForge file format identifier) is validated. The salt,
nonce, and scrypt Parameters (N, R, P) are extracted from the header. The
encryption key is derived using the user-provided password and the extracted
KDF parameters. The remaining file content (ciphertext + authentication tag)
is read. The re-derived key, nonce, ciphertext, and the full header (as AAD)
are passed to the aead.Open() function. The Poly1305 tag verification
(authentication check) must succeed to recover the plaintext. Failure
results in an authentication failure, preventing the output of tampered
or corrupted data.

ENCODED BINARY FILE FORMAT:

The encrypted file is a binary structure consisting of a fixed-size header
(80 bytes) followed immediately by the encrypted payload. All multi-byte
values (lengths and parameters) are written using big-endian byte order.

DIAGRAM OF BINARY LAYOUT

+----------------- HEADER (AAD FIELD) DETAILS (80 Bytes) -----------------+
| Field Name     | Data Type          | Length   | Value/Purpose          |
|----------------+--------------------+----------+------------------------+
| Magic Marker   | string/byte array  | 11 bytes | "CIPHERFORGE"          |
| Salt Length    | uint32             | 4 bytes  | Scrypt salt length     |
| Scrypt Salt    | byte array         | 16 bytes | Random scrypt salt     |
| Scrypt N       | uint32             | 4 bytes  | CPU/Memory cost        |
| Scrypt R       | uint32             | 4 bytes  | Block size             |
| Scrypt P       | uint32             | 4 bytes  | Parallelization        |
| Nonce Length   | uint32             | 4 bytes  | XChaCha20 nonce length |
| XChaCha Nonce  | byte array         | 24 bytes | Random init. vector    |
| Ciphertext     | byte array         | Variable | Encrypted ciphertext   |
| Auth. Tag      | byte array         | 16 bytes | XChaCha20 auth. tag    |
|----------------+-------------------------+----------------+-------------+
| All fields up to (but not including) the ciphertext are included in the |
| XChaCha20 Additional Authenticated Data for complete data integrity.    |
+-------------------------------------------------------------------------+
`
