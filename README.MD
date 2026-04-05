# Cipherforge

Cipherforge is a command-line tool for encrypting and decrypting files. It uses
modern, well-audited cryptographic standards throughout and is built with
long-term archival in mind — meaning an archive encrypted today should still be
decryptable decades from now, even if the original binary is gone.

It handles files of any size through 1 MiB streaming segments, so memory usage
stays constant regardless of whether you're encrypting a 10 KB text file or a
100 GB disk image. Every encrypted file is fully authenticated: tampering with
any byte — header, payload, or trailer — is detected before any plaintext is
written to disk.

Passwords are generated automatically using a cryptographically secure random
source. You never choose a password; Cipherforge chooses one for you and prints
it once. Store it somewhere safe.

---

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [Password Generation](#password-generation)
  - [Key Derivation](#key-derivation)
  - [Key Separation](#key-separation)
  - [Encryption](#encryption)
  - [Nonce Management](#nonce-management)
  - [Authentication and Integrity](#authentication-and-integrity)
  - [Memory Safety](#memory-safety)
  - [Post-Quantum Security](#post-quantum-security)
- [File Format](#file-format)
- [Long-Term Archival](#long-term-archival)
- [Security Considerations](#security-considerations)
- [Building from Source](#building-from-source)


## Installation

Pre-built binaries for Linux, Windows, macOS, and FreeBSD are available on the
[Releases](../../releases) page. Download the binary for your platform, make it
executable, and place it somewhere on your `PATH`.

```bash
# Linux / macOS
chmod +x cfo
sudo mv cfo /usr/local/bin/
```

On Windows, rename `cfo.exe` and add its location to your `PATH` via System
Properties → Environment Variables.

## Quick Start

**Encrypt a file:**
```
cfo -e document.pdf
```
Cipherforge prints a generated password and writes `document.pdf.cfo` alongside
the original. The original file is not modified or removed.

```
Your secure, auto-generated password used for encryption:
92KXC-4CGB2-TCEJD-QBTAF-ZBWV2-63E47-2A2AF-7HZ15-ZNER1-BGYX5-NBWDH
```

**Decrypt a file:**
```
cfo -d document.pdf.cfo
```
You will be prompted for the password. Output is written to `document.pdf`.

That's all there is to it.

## Usage

```
cfo [options]

Options:
  -e <path>    Encrypt a file or glob pattern
  -d <path>    Decrypt a .cfo file or glob pattern
```

Only one flag may be used at a time. `-e` and `-d` are mutually exclusive.

### Examples

Encrypt a single file:
```bash
cfo -e report.pdf
```

Encrypt all `.txt` files in a directory (quote the pattern to prevent shell
expansion):
```bash
cfo -e "documents/*.txt"
```

Encrypt multiple explicit files:
```bash
cfo -e notes.txt passwords.kdbx secrets.tar
```

Decrypt a single file:
```bash
cfo -d report.pdf.cfo
```

Decrypt all `.cfo` files in a directory:
```bash
cfo -d "archives/*.cfo"
```

Decrypt non-interactively (piping password from a file or secret manager):
```bash
echo "3K7NV-M2QWX-..." | cfo -d archive.cfo
```
When stdin is not a terminal, Cipherforge reads the password from stdin instead
of prompting. This is useful for scripted or automated workflows.

### Notes on output filenames

Encryption appends `.cfo` to the input filename: `photo.jpg` becomes
`photo.jpg.cfo`. Decryption strips the `.cfo` suffix to recover the original
name. If for any reason stripping the suffix would produce the an existing filename, Cipherforge overwrites the output file without warning.

The original filename and extension remain visible in the `.cfo` filename.
If that is a concern (e.g. storing archives in a shared or cloud location),
rename the file before encrypting:

```bash
mv sensitive-contracts.pdf archive.pdf
cfo -e archive.pdf
```

The same goes for compression which must be done prior to encryption with Cipherforge:

```bash
tar czf sensitive-data.tar.gz data.pdf
cfo -e sensitive-data.tar.gz
```

## How It Works

### Password Generation

Cipherforge never asks you to choose a password. Human-chosen passwords are
the leading cause of cryptographic failure in practice — people reuse them,
write them down insecurely, or choose ones that are guessable.

Instead, a 55-character password is generated from a 32-character Base32 pool
(`0–9`, `A–Z` excluding visually ambiguous characters `I`, `L`, `O`) using
`crypto/rand`, Go's interface to the operating system's cryptographically secure
random number generator.

**Why 55 characters?** Each character carries approximately 5 bits of entropy
(log₂ 32 = 5). At 55 characters that's ~275 bits of raw entropy, above the 256-bit key it protects. In practice, security is bounded by the
256-bit Argon2id output, so the extra margin is due to the password being formatted in groups of five characters; trimming the password to 50 characters would result in a password with ~225 bits of entropy, which is weaker than the 256-bit key it protects.

**Rejection sampling** is used during generation to eliminate modulo bias. A
naive approach — taking a random byte and computing `byte % 32` — would slightly
favour characters at the start of the pool. Any byte value that would introduce this bias is discarded, and a new
random byte is drawn. The result is a perfectly uniform distribution across all
32 characters.

Passwords are formatted in groups of five separated by hyphens for readability
and ease of manual transcription:
```
3K7NV-M2QWX-H9RBP-T4ZSF-A6JDY-82VCG-K1NMQ-WX3H5-P7RBT-4ZSF8-V2
```

The password is shown exactly once, at the time of encryption. **There is no
recovery mechanism.** Store it in a password manager or print it and keep it
physically secure alongside the archive.

---

### Key Derivation

The password is never used directly as a key. It is processed through
**Argon2id** (RFC 9106), a memory-hard key derivation function (KDF) that
makes brute-force attacks expensive by requiring large amounts of RAM in
addition to CPU time.

Argon2id was the winner of the Password Hashing Competition (2015) and is the
current recommendation of OWASP, NIST, and the IETF for password-based key
derivation. It is specifically designed to be resistant to GPU and ASIC
acceleration: while a GPU can run thousands of cheap hash computations in
parallel, it cannot run thousands of 1 GiB memory allocations in parallel
— memory bandwidth is the bottleneck, not compute.

Cipherforge uses hardened parameters:

| Parameter | Value  | Purpose |
|-----------|--------|---------|
| Time      | 4      | Number of passes over memory |
| Memory    | 1 GiB  | RAM allocated per derivation |
| Threads   | 4      | Parallel memory lanes |
| Output    | 64 bytes | Two 256-bit keys |

A random 16-byte **salt** is generated for each file and stored in the header.
The salt ensures that two files encrypted with the same password produce
completely different keys — defeating precomputation attacks (rainbow tables).

One Argon2id call produces 64 bytes of key material. These are split into two
independent keys (see [Key Separation](#key-separation)) so the expensive KDF
operation is only paid once.

### Key Separation

The 64-byte Argon2id output is split into two non-overlapping keys:

- **Bytes 0–31** → `encKey`: the XChaCha20-Poly1305 encryption key
- **Bytes 32–63** → `macKey`: the HMAC-SHA256 key used to authenticate the
  file trailer

These two keys serve entirely different cryptographic roles and are never used
interchangeably. Deriving both from a single KDF invocation provides proper
domain separation — they are independent 256-bit outputs of the same PRF —
while avoiding the cost of running Argon2id twice (which at 1 GiB/run would
double memory consumption and decryption time).

### Encryption

Files are split into segments of up to **1 MiB (1,048,576 bytes)**. Each
segment is individually encrypted with XChaCha20-Poly1305.

**XChaCha20-Poly1305** is an Authenticated Encryption with Associated Data
(AEAD) construction. It provides both:

- **Confidentiality** — via the XChaCha20 stream cipher, a variant of the
  ChaCha20 cipher designed by Daniel Bernstein and standardised in RFC 8439
- **Integrity** — via a Poly1305 authentication tag appended to each segment

The 'X' prefix denotes the extended-nonce variant with a 192-bit (24-byte)
nonce, versus the 96-bit nonce of standard ChaCha20-Poly1305. The larger nonce
makes it safe to generate a fresh random nonce per segment without risk of
collision — at 192 bits the birthday bound is so far away as to be irrelevant
in practice. (Standard ChaCha20-Poly1305's 96-bit nonce requires careful
counter management for exactly this reason.)

The write structure for each segment is:

```
[Segment Length: 8 bytes] [Ciphertext + Poly1305 Tag]
```

The 8-byte length prefix allows the decoder to read exactly the right number of
bytes per segment without scanning for delimiters or knowing the total file size
in advance.

### Nonce Management

A 24-byte **Master Nonce** is generated randomly and stored once in the file
header. Individual per-segment nonces are derived from the Master Nonce using
**HKDF-SHA256** (RFC 5869, NIST SP 800-56C):

```
segment_nonce[i] = HKDF-SHA256(ikm=MasterNonce, salt=nil, info=uint64_big_endian(i))
```

Where `i` is the 64-bit segment counter encoded as an 8-byte big-endian value.

This is preferable to simpler approaches for two reasons:

**Why not store a full nonce per segment?** A 24-byte nonce stored with every
1 MiB segment adds 24 bytes of overhead per MiB (~0.002%). It's not a
meaningful cost, but the HKDF approach has better properties: it stores only
the 24-byte Master Nonce once in the header regardless of how many segments the
file has.

**Why not XOR the counter into the Master Nonce?** XOR-based derivation
(`nonce[i] = masterNonce XOR i`) has two weaknesses:

1. **Identity at zero** — when `i == 0`, XOR is a no-op, so the Master Nonce
   itself becomes a live encryption nonce. This is a subtle but real exposure.
2. **Linear structure** — knowing any two `(counter, nonce)` pairs immediately
   reveals the Master Nonce via XOR, leaking the root secret.

HKDF is a one-way pseudorandom function. Given any number of derived nonces and
their counters, the Master Nonce remains computationally hidden. It also has no
identity-at-zero property: `counter=0` does not yield the raw Master Nonce.
HKDF is standardised by NIST SP 800-56C for exactly this purpose (deriving
independent, domain-separated values from a shared secret).

### Authentication and Integrity

Cipherforge provides authentication at two levels.

**Per-segment authentication** via Poly1305 tags. Each segment includes a
16-byte tag that authenticates the ciphertext. Decryption of any segment
fails immediately if the ciphertext has been modified. The
**Additional Authenticated Data (AAD)** passed to the AEAD on each segment
includes both the segment counter and the plaintext length:

```
AAD = uint64_big_endian(segment_index) || uint64_big_endian(plaintext_length)
```

Binding the segment index to the AAD means an attacker cannot reorder segments
— segment 3's tag will not validate if it is presented as segment 7. Binding
the plaintext length makes the AAD self-contained and robust to any future
changes in how overhead is calculated.

Per-segment AEAD alone has a gap: it cannot detect attacks on the file as a
whole, such as swapping the header from one ciphertext to another, truncating
the file at a segment boundary, or appending extra segments.

**File-level authentication** via HMAC-SHA256 trailer. After all segments are
written, a 40-byte trailer is appended:

```
[Segment Count: 8 bytes] [HMAC-SHA256(macKey, salt || masterNonce || segmentCount): 32 bytes]
```

The HMAC commits to the salt, the Master Nonce, and the total segment count
in a single tag. This closes the gap left by per-segment AEAD:

- **Header substitution** — swapping the salt or Master Nonce from another
  file (even one encrypted with the same password) invalidates the HMAC
- **File truncation** — removing segments changes the segment count, invalidating
  the HMAC
- **Segment appending** — adding segments also changes the count

Critically, the trailer is **verified before any plaintext is written to disk**.
This means a wrong password, a corrupted file, or a tampered header is detected
upfront, without streaming the entire ciphertext. The decoder reads the trailer
from the end of the file, verifies the HMAC, and only then proceeds with
sequential decryption.

If encryption or decryption fails at any point, the incomplete output file is
automatically deleted. A failed decryption will never leave partial plaintext
on disk.

---

### Memory Safety

Sensitive material — the derived keys and the generated password — is stored in
byte slices (`[]byte`) rather than Go strings. Go strings are immutable and
interned; once allocated, the runtime may hold copies in memory indefinitely and
there is no way to force them to be zeroed. Byte slices give direct control over
the underlying memory.

All sensitive byte slices are explicitly zeroed immediately after use:
```go
for i := range b {
    b[i] = 0
}
runtime.KeepAlive(b)
```

The `runtime.KeepAlive` call is essential. Without it, the Go compiler can
legally eliminate the zeroing loop as a "dead store" — a write to memory that
is never subsequently read. `KeepAlive` proves to the compiler that the slice
is still live after the loop, preventing this optimisation.

Both derived keys (`encKey` and `macKey`) are additionally locked into physical
RAM using `mlock(2)` on Unix/Linux/macOS and `VirtualLock` on Windows. This
prevents the operating system from swapping the key material to the pagefile or
swap partition, where it could potentially be recovered by an attacker with disk
access. The lock is best-effort: it is silently ignored in sandboxed
environments or containers where the process lacks sufficient `RLIMIT_MEMLOCK`.
Zeroing is always performed regardless of whether locking succeeded.

---

### Post-Quantum Security

All cryptographic primitives used by Cipherforge are symmetric. This is
significant because the threat posed by quantum computers differs sharply
between symmetric and asymmetric cryptography.

Shor's algorithm can break RSA and elliptic-curve cryptography in polynomial
time on a sufficiently powerful quantum computer. Cipherforge uses neither.

Grover's algorithm can search an unstructured keyspace in O(√N) time rather
than O(N), effectively halving the security level of symmetric primitives. A
256-bit key provides approximately **128 bits of post-quantum security** under
Grover — which NIST SP 800-57 considers sufficient for the foreseeable future
(NIST's "Category 1" post-quantum security target is 128 bits).

XChaCha20-Poly1305, HMAC-SHA256, Argon2id, and HKDF-SHA256 are all unaffected
by Shor's algorithm. The symmetric design of Cipherforge makes it
post-quantum-ready without any special configuration.

---

## File Format

All multi-byte integer values are stored in **big-endian** byte order.

```
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
|              ENCRYPTED PAYLOAD (REPEAT UNTIL TRAILER)                  |
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
```

**Header** (52 bytes fixed):
- `Magic` (8 bytes): `0xC1 0x50 0x48 0x52 0x46 0x30 0x52 0x47` — allows fast
  rejection of non-`.cfo` files before any key derivation is attempted
- `Version` (4 bytes): format version, currently `0x00000001` — allows future
  format changes to be detected cleanly
- `Salt` (16 bytes): random Argon2id salt, unique per file
- `Master Nonce` (24 bytes): random XChaCha20 master nonce, unique per file

**Payload** (repeating):
Each segment is prefixed with an 8-byte big-endian length, followed by the
ciphertext and its 16-byte Poly1305 tag. The length field records the combined
size of ciphertext and tag, not the plaintext size. Maximum segment ciphertext
size is 1,048,576 + 16 bytes (plaintext + AEAD overhead).

**Trailer** (40 bytes fixed):
- `Segment Count` (8 bytes): total number of segments written
- `Trailer HMAC` (32 bytes): `HMAC-SHA256(macKey, salt || masterNonce || segmentCount)`

The trailer is always at `EOF - 40`. The decoder seeks to this offset first,
verifies the HMAC, then performs a single sequential read of the payload.

**Header size**: 8 + 4 + 16 + 24 = **52 bytes**  
**Minimum valid file size**: 52 (header) + 40 (trailer) = **92 bytes**  
**Overhead per segment**: 8 (length) + 16 (tag) = **24 bytes**  
**File overhead**: 92 bytes + 24 bytes per segment

---

## Long-Term Archival

Cipherforge is designed so that an archive created today can be decrypted years
or decades from now, even in the absence of the original binary.

**Binary portability.** Go compiles to self-contained static binaries with no
runtime dependencies. A binary built for `linux/amd64` today will run on a
future Linux system without installing a runtime, interpreter, or dependency
manager. Go's backwards-compatibility guarantee also means the source code can
be recompiled against any future Go toolchain without modification.

**Standardised primitives.** Every cryptographic primitive is a published
standard:

| Primitive | Standard |
|-----------|----------|
| XChaCha20-Poly1305 | RFC 8439 + IETF draft |
| Argon2id | RFC 9106 |
| HMAC-SHA256 | RFC 2104, FIPS 198-1 |
| HKDF-SHA256 | RFC 5869, NIST SP 800-56C |

If the compiled binary is unavailable on a future platform, the file format
above is a complete specification. Any developer with access to a
standards-conformant cryptographic library can write a compatible decoder from
scratch.

**Practical recommendation for long-term archives:**

1. Store the password in at least two physically separate locations (e.g. a
   printed copy in a fireproof safe and a trusted password manager)
2. Keep a copy of the source code and/or compiled binary alongside the archive
3. Record the platform the binary was built for
4. Test decryption periodically — do not wait until you need the file to
   discover the password is missing

The most common failure mode for encrypted long-term archives is not
cryptographic weakness — it is password loss.

---

## Security Considerations

**The password is shown once.** If you lose it, the data is unrecoverable.
There is no backdoor, no key escrow, and no recovery mechanism. This is
intentional.

**The filename is not encrypted.** The `.cfo` extension is appended to the
original filename. `payroll-2026.xlsx` becomes `payroll-2026.xlsx.cfo`. The
contents are protected; the name is not. Rename before encrypting if the
filename itself is sensitive.

**Cipherforge does not encrypt in place.** The original file is never modified.
After encrypting, you are responsible for securely deleting the plaintext
original if required. On most filesystems, `rm` does not overwrite file data;
use a tool like `shred` (Linux) or `Secure Empty Trash` (macOS) if this matters.

**Side-channel attacks on the decrypting machine.** Cipherforge mitigates
in-process memory exposure via zeroing and `mlock`, but it cannot protect
against a compromised operating system, a hardware keylogger, or an attacker
with live access to the machine's RAM. The threat model assumes a trustworthy
execution environment.

**Authenticated encryption is not compression or steganography.** A `.cfo`
file is identifiable as a Cipherforge archive by its magic bytes. Anyone who
can see the file knows it exists and that it was encrypted with Cipherforge,
even if they cannot read the contents.

---

## Building from Source

Requires Go 1.21 or later.

```bash
git clone https://github.com/vilshansen/cipherforge-go
cd cipherforge-go
go build -o cfo cipherforge.go
```

To build for all supported platforms:
```bash
./build-all.sh
```

To build for Linux only (faster for development):
```bash
./build-linux.sh
```

Both scripts run the full test suite before compiling and abort on any failure.
Compiled binaries are written to `dist/originals/`. UPX-compressed versions
(where supported) are written to `dist/compressed/`.

To run the tests manually:
```bash
go test -race -cover ./...
```

---

## License

Copyright (c) 2026 Peter Vils Hansen. See [LICENSE](LICENSE) for details.
