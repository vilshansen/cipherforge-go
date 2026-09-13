# Cipherforge

Cipherforge is a command-line tool for encrypting and decrypting files. It uses
modern, well-audited cryptographic standards throughout and is built with
long-term archival in mind — meaning an archive encrypted today should still be
decryptable decades from now, even if the original binary is gone.

It handles files of any size through 1 MiB streaming segments, so memory usage
stays constant regardless of whether you're encrypting a 10 KB text file or a
100 GB disk image. Every encrypted file is authenticated: tampering with the
header, payload, or trailer is detected. For CLI file decryption, plaintext is
staged and is not published to the destination until the complete file has
successfully decrypted.

By default, a secret is generated automatically from a cryptographically
secure random source. Cipherforge prints the secret once — store it somewhere
safe; it cannot be recovered.

---

## Documentation

Cipherforge ships with five documents, each written for a different audience:

| Document | Audience | Purpose |
|---|---|---|
| **[README.MD](README.MD)** (this file) | All users | Installation, quick start, usage, and a high-level "How It Works" overview |
| **[CRYPTODESIGN.MD](CRYPTODESIGN.MD)** | Developers, security reviewers | Rationale behind AES-256-GCM, HKDF-SHA256 key derivation, nonce management, authentication, and post-quantum considerations |
| **[FILEFORMAT.MD](FILEFORMAT.MD)** | Developers implementing a decoder, maintainers | Authoritative `.cfo` binary format specification. Byte-level layout, field-by-field security analysis, pseudocode for the decryption algorithm, and what each field protects against |
| **[ARCHITECTURE.MD](ARCHITECTURE.MD)** | Contributors, new developers | Codebase structure, layered architecture, data flow diagrams, TUI design, build system, and rationale for Go as the implementation language |
| **[RELEASE.MD](RELEASE.MD)** | Maintainers, release managers | Step-by-step runbook for bumping the version, building all platforms, and publishing a tagged release to GitHub |

### Suggested Reading Order

1. **Start here** (README.MD) — install the tool, encrypt a test file, get
   comfortable with the CLI and TUI. The "How It Works" section gives a
   high-level tour of the cryptography without diving into specifics.

2. **CRYPTODESIGN.MD** — once you want to understand *why* each algorithm was
   chosen. This is the document to read before relying on Cipherforge for
   sensitive data. It assumes you have some cryptography background.

3. **FILEFORMAT.MD** — if you need to write a compatible decoder in another
   language, audit the format for security, or understand what happens at the
   byte level. This is the specification; everything else is commentary.

4. **ARCHITECTURE.MD** — if you plan to contribute to the codebase or want to
   understand how the Go packages are organized before reading the source.

5. **RELEASE.MD** — if you are releasing a new version: the exact steps to
   bump the version, run the build, and publish the GitHub release.

---

## Table of Contents

- [Documentation](#documentation)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [How It Works](#how-it-works)
  - [Secret Generation](#secret-generation)
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

**Launch the terminal UI (no flags):**
```
cfo
```
Cipherforge opens a full-screen terminal interface with a main menu:

1. Encrypt file
2. Decrypt file
3. Encrypt text
4. Decrypt text
5. Quit

Navigate with arrow keys or press 1–5 for shortcuts. The TUI guides you
through the file picker, progress display, and results — all with
keyboard-driven navigation.

**Encrypt text for copy/paste:**
Select "Encrypt text" from the menu, type or paste any text, and get
base64-encoded output you can copy directly to your clipboard with `Shift+C`.
The generated secret is shown on the results screen.

**Encrypt a file:**
```
cfo -e document.pdf
```
Cipherforge prints a generated secret and writes `document.pdf.cfo` alongside
the original. The original file is not modified or removed.

```
cfo: Save this generated secret — it cannot be recovered.
8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k
```

**Decrypt a file:**
```
cfo -d document.pdf.cfo
```
You will be prompted for the generated secret. Output is written to `document.pdf`.

That's all there is to it.

## Usage

```
cfo [options]

Options:
  -e <path>    Encrypt a file or glob pattern
  -d <path>    Decrypt a .cfo file or glob pattern
  -o <file>    Output filename (requires a single input file)
  -b, --base64      Wrap encrypted output in base64 armor (BEGIN/END markers,
                    68-char lines) for easy copy/paste (encrypt only)
  -i, --interactive Launch the full-screen terminal UI
  -q, --quiet       Suppress all non-error output
  -f, --force       Overwrite output file if it already exists
  -h, --help        Show help text
  -v, --version     Show version information
```

Only one of `-e` or `-d` may be used at a time.

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

Decrypt non-interactively (piping the generated secret from a file or secret
manager):
```bash
echo "$SECRET" | cfo -d archive.cfo
```
When stdin is not a terminal, Cipherforge reads the secret from stdin instead
of prompting. This is useful for scripted or automated workflows.

Encrypt to armored base64 output (easy copy/paste, GPG-style):
```bash
cfo -e secret.txt --base64
cfo -d secret.txt.cfo --base64 -o -
```
Decrypting with `--base64` requires GPG-style armored input (bare base64 is
not accepted).

### Writing to stdout

When the ciphertext is written to stdout, the generated secret is written to
**stderr** instead. The two must never share a stream — otherwise the secret
would sit alongside the ciphertext it protects:

```bash
cfo -e document.pdf -o - > document.pdf.cfo 2> document.pdf.secret
```

Decryption to stdout is staged: plaintext is released only once the entire
payload has authenticated. A ciphertext whose later segment was modified
produces no output at all, instead of the valid plaintext that preceded the
damaged segment. The trade-off is that the plaintext is written once to a
temporary file before it is streamed out.

```bash
echo "$SECRET" | cfo -d document.pdf.cfo -o -
```

### Notes on output filenames

Encryption appends `.cfo` to the input filename: `photo.jpg` becomes
`photo.jpg.cfo`. Decryption strips the `.cfo` suffix to recover the original
name. If the input does not end with `.cfo`, `.dec` is appended instead.
By default, Cipherforge will not overwrite an existing output file — use
`-f` / `--force` to override this safety check.

### TUI Keyboard Reference

| Key | Context | Action |
|---|---|---|
| `↑` `↓` / `j` `k` | Menus, lists | Navigate |
| `1`–`5` | Main menu | Jump to option |
| `Enter` | Menus, checkboxes | Select / toggle |
| `Space` | Checkboxes | Toggle |
| `Tab` / `Shift+Tab` | Secret screen | Cycle fields |
| `Esc` | Sub-screens | Go back |
| `q` | Main menu | Quit |
| `c` | Results screen | Copy generated secret to clipboard |
| `Shift+C` | Results screen | Copy encrypted/decrypted text |
| `↑` `↓` `Enter` / `j` `k` / `PgUp` `PgDn` / `Home` `End` | Results screen | Scroll long text |
| `Ctrl+S` | Text input | Confirm and proceed |
| Type characters | File picker | Type-ahead search |
| `Backspace` | File picker | Go up one directory |

To control the output filename directly, use the `-o` flag (single file only):
```bash
cfo -e backup.tar -o archive.cfo
cfo -d archive.cfo -o restored.tar
```

The original filename and extension remain visible in the `.cfo` filename.
If that is a concern (e.g. storing archives in a shared or cloud location),
rename the file before encrypting:

```bash
mv sensitive-contracts.pdf archive.pdf
cfo -e archive.pdf
```

The same goes for compression which must be done prior to encryption with 
Cipherforge:

```bash
tar czf sensitive-data.tar.gz data.pdf
cfo -e sensitive-data.tar.gz
```

## How It Works

### Secret Generation

Cipherforge generates the encryption secret automatically — human-chosen
passwords are the leading cause of cryptographic failure in practice, so there
is no option to supply one.

The generated secret is 45 characters drawn from a 57-character clean pool
(`1–9`, `A–Z` excluding `I`, `L`, and `O`, `a–z` excluding `l`) using `crypto/rand`,
Go's interface to the operating system's cryptographically secure random number
generator. The pool excludes the five glyphs most commonly confused with each
other (`0`/`O`, `1`/`I`/`l`/`L`), making secrets unambiguous to read aloud or
transcribe from paper.

For readability the characters are printed in dash-separated groups of five. The
dashes are part of the secret — enter it exactly as displayed.

**Why 45 characters?** Each character carries approximately 5.83 bits of entropy
(log₂ 57 ≈ 5.83). 45 is the smallest multiple of five that clears 256 bits, at
~262 bits of entropy — comfortably beyond the 256-bit strength of the encryption
key. Only the 45 characters contribute entropy; the separators do not.

**Rejection sampling** is used during generation to eliminate modulo bias.
`crypto/rand.Int` draws an unbiased random integer in [0, poolSize), avoiding
the favouritism toward early pool characters that a naive `byte % 57` would
introduce. The result is a perfectly uniform distribution across all 57
characters.

```
8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k
```

The generated secret is emitted once, at the time of encryption, and is the only
way to decrypt the file. When ciphertext is written to stdout (`-o -`), the
secret is written to stderr so it cannot be mixed into the ciphertext stream.
**There is no recovery mechanism.** Store it in a password manager or print it
and keep it physically secure alongside the archive.

---

### Key Derivation

The generated secret is high-entropy random material and is used as HKDF input
keying material. A random 16-byte **salt** is generated for each file and
stored in the header. HKDF-SHA256 derives 64 bytes per file, so the salt makes
keys independent across files while retaining deterministic decryption.

There is no password-based KDF because Cipherforge does not accept
human-chosen encryption passwords. The secret is generated by the OS CSPRNG
and shown exactly once.

### Key Separation

The HKDF-SHA256 expansion produces 64 bytes of key material per file, which is
split into two non-overlapping keys:

- **Bytes 0–31** → `encKey`: the AES-256-GCM encryption key
- **Bytes 32–63** → `macKey`: the HMAC-SHA256 key used to authenticate the
  file trailer

These two keys serve entirely different cryptographic roles and are never used
interchangeably. Deriving both from the HKDF expansion provides proper domain
separation — they are independent 256-bit outputs of the same PRF.

### Encryption

Files are split into segments of up to **1 MiB (1,048,576 bytes)**. Each
segment is individually encrypted with AES-256-GCM.

**AES-256-GCM** is an Authenticated Encryption with Associated Data
(AEAD) construction. It provides both:

- **Confidentiality** — via AES-256 in Galois/Counter Mode
- **Integrity** — via a 16-byte GCM authentication tag appended to each segment

Each segment uses a 12-byte nonce formed from a random 4-byte per-file prefix
and an 8-byte big-endian segment counter. This guarantees uniqueness within
the file key without relying on random 96-bit nonce collision resistance.

The write structure for each segment is:

```
[Segment Length: 8 bytes] [Ciphertext + GCM Tag]
```

The 8-byte length prefix allows the decoder to read exactly the right number of
bytes per segment without scanning for delimiters or knowing the total file size
in advance.

### Nonce Management

A 4-byte **Nonce Prefix** is generated randomly and stored once in the file
header. Individual per-segment nonces are constructed from it and the segment
counter:

```
segment_nonce[i] = noncePrefix || uint64_big_endian(i)
```

Where `i` is the 64-bit segment counter encoded as an 8-byte big-endian value.
Nonce reuse under AES-GCM is catastrophic, so the counter must never reset for
a given file key.

This is preferable to simpler approaches for two reasons:

The prefix/counter construction stores only four random bytes once in the
header and makes nonce uniqueness mechanically auditable.

The counter is encoded in a fixed-width big-endian field, so each segment has a
distinct nonce for the file's encryption key. The random prefix prevents nonce
reuse across independently keyed files in normal operation.

### Authentication and Integrity

Cipherforge provides authentication at two levels.

**Per-segment authentication** via GCM tags. Each segment includes a
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
written, a 72-byte trailer is appended:

```
[Segment Count: 8 bytes] [HMAC-SHA256(macKey, "cipherforge-trailer-hmac-v7-aes256-gcm"
|| suite || flags || salt || noncePrefix || segmentCount): 32 bytes]
[Key-Commitment Tag: 32 bytes] HMAC-SHA256(encKey, "cipherforge-commitment-v2" || fileSalt)
```

The HMAC commits to the suite, flags, salt, nonce prefix, and
the total segment count
in a single tag. This closes the gap left by per-segment AEAD:

- **Header substitution** — swapping the salt or nonce prefix from another
  file (even one encrypted with the same secret) invalidates the HMAC
- **File truncation** — removing segments changes the segment count, invalidating
  the HMAC
- **Segment appending** — adding segments also changes the count

Critically, the trailer is **verified before any plaintext is written to disk**.
This means a wrong secret, a corrupted file, or a tampered header is detected
upfront, without streaming the entire ciphertext. The decoder reads the trailer
from the end of the file, verifies the HMAC, and only then proceeds with
sequential decryption.

Note that the trailer covers file metadata, while each segment carries its own
AES-GCM tag. A segment modified in the middle of the payload is therefore
detected only when that segment is reached, which can be after earlier plaintext
has been produced. Callers that stream to a live consumer should rely on the
staged output behaviour described in [Writing to stdout](#writing-to-stdout).

If encryption or decryption fails at any point, the incomplete output file is
automatically deleted. A failed decryption will never leave partial plaintext
on disk.

---

### Memory Safety

Sensitive material — the derived keys and the generated secret — is stored in
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

AES-256-GCM, HMAC-SHA256, and HKDF-SHA256 are all unaffected
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
| Magic             | byte array          | 9 bytes   | 0xC1PHRF0RGE     |
| Version           | uint32 (big-endian) | 4 bytes   | 0x00000007       |
| Suite             | uint8               | 1 byte    | AES-256-GCM      |
| Flags             | uint8               | 1 byte    | 0x00             |
| Salt              | byte array          | 16 bytes  | HKDF salt        |
| Nonce Prefix      | byte array          | 4 bytes   | GCM nonce prefix |
+-------------------+---------------------+-----------+------------------+
|              ENCRYPTED PAYLOAD (REPEAT UNTIL TRAILER)                  |
+-------------------+---------------------+-----------+------------------+
| Field Name        | Data Type           | Length    | Value/Purpose    |
+-------------------+---------------------+-----------+------------------+
| Segment Length    | uint64              | 8 bytes   | Ciphertext+Tag   |
| Ciphertext        | byte array          | <= 1 MiB  | Encrypted data   |
| GCM Tag           | byte array          | 16 bytes  | Auth tag         |
+-------------------+---------------------+-----------+------------------+
|                          FILE TRAILER (ONCE)                           |
+-------------------+---------------------+-----------+------------------+
| Field Name        | Data Type           | Length    | Value/Purpose    |
+-------------------+---------------------+-----------+------------------+
| Segment Count     | uint64              | 8 bytes   | Total segments   |
| Trailer HMAC      | byte array          | 32 bytes  | HMAC-SHA256      |
+-------------------+---------------------+-----------+------------------+
```

**Header** (35 bytes fixed):
- `Magic` (8 bytes): `0xC1 0x50 0x48 0x52 0x46 0x30 0x52 0x47` — allows fast
  rejection of non-`.cfo` files before any key derivation is attempted
- `Version` (4 bytes): format version, currently `0x00000007`
- `Suite` (1 byte): `0x01` for AES-256-GCM
- `Flags` (1 byte): reserved and must be zero
- `Salt` (16 bytes): random HKDF salt, unique per file
- `Nonce Prefix` (4 bytes): random prefix for the 12-byte GCM nonce

**Payload** (repeating):
Each segment is prefixed with an 8-byte big-endian length, followed by the
ciphertext and its 16-byte GCM tag. The length field records the combined
size of ciphertext and tag, not the plaintext size. Maximum segment ciphertext
size is 1,048,576 + 16 bytes (plaintext + AEAD overhead).

**Trailer** (72 bytes fixed):
- `Segment Count` (8 bytes): total number of segments written
- `Trailer HMAC` (32 bytes): `HMAC-SHA256(macKey, "cipherforge-trailer-hmac-v7-aes256-gcm" || suite || flags || salt || noncePrefix || segmentCount)`
- `Key-Commitment Tag` (32 bytes): `HMAC-SHA256(encKey, "cipherforge-commitment-v2" || fileSalt)`

The trailer is always at `EOF - 72`. The decoder seeks to this offset first,
verifies the HMAC and key-commitment tag, then performs a single sequential
read of the payload.

**Header size**: 9 + 4 + 1 + 1 + 16 + 4 = **35 bytes** (v7)
**Minimum valid file size**: 35 (header) + 72 (trailer) = **107 bytes**
**Overhead per segment**: 8 (length) + 16 (tag) = **24 bytes**  
**File overhead**: 137 bytes + 24 bytes per segment

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
| AES-256-GCM | NIST SP 800-38D |
| HMAC-SHA256 | RFC 2104, FIPS 198-1 |
| HKDF-SHA256 | RFC 5869, NIST SP 800-56C |

If the compiled binary is unavailable on a future platform, the file format
above is a complete specification. Any developer with access to a
standards-conformant cryptographic library can write a compatible decoder from
scratch.

**Practical recommendation for long-term archives:**

1. Store the generated secret in at least two physically separate locations (e.g. a
   printed copy in a fireproof safe and a trusted password manager)
2. Keep a copy of the source code and/or compiled binary alongside the archive
3. Record the platform the binary was built for
4. Test decryption periodically — do not wait until you need the file to
   discover the secret is missing

The most common failure mode for encrypted long-term archives is not
cryptographic weakness — it is secret loss.

---

## Security Considerations

**The generated secret is shown once.** If you lose it, the data is unrecoverable.
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

Requires Go 1.25 or later.

**Static, reproducible binaries.** Binaries are built with `CGO_ENABLED=0`,
`-trimpath`, and `-buildvcs=false`, producing fully static executables with no
libc/CGo runtime dependency. `git` is never required to compile.

**Vendored (offline) builds on demand.** The `vendor/` directory is *not*
committed to the repository (it is git-ignored). To snapshot every dependency
locally and build with no network access afterwards, pass `--vendor` (Unix) or
`-Vendor` (PowerShell) once while online:

```bash
./build-all.sh --vendor
```

After that, a plain `./build-all.sh` detects `vendor/` and builds fully offline
(`GOTOOLCHAIN=local`, `GOPROXY=off`, `-mod=vendor`). Without `vendor/`, the
scripts fall back to normal module resolution (which requires network).

For a single binary built against the vendored tree:
```bash
go mod vendor                      # once, with network access
go build -mod=vendor -trimpath -buildvcs=false -o cfo ./cmd/cfo/
```

### Manual builds for specific platforms

To build a single binary for a specific platform yourself (without the build
scripts), set `GOOS` and `GOARCH`, keep `CGO_ENABLED=0` for a fully static
binary, and run `go build`:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o cfo-linux-amd64 ./cmd/cfo/
```

Supported platforms:

| OS      | Architectures      | Output name |
|---------|--------------------|-------------|
| Linux   | amd64, arm64, 386  | `cfo`       |
| Windows | amd64, 386         | `cfo.exe`   |
| macOS   | amd64, arm64       | `cfo`       |
| FreeBSD | amd64              | `cfo`       |

Recommended flags for a reproducible, static release build:

```bash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build \
  -mod=vendor -trimpath -buildvcs=false \
  -ldflags "-s -w -X main.Version=7.1.0 -X main.GitCommit=$(git rev-parse --short HEAD 2>/dev/null || echo none)" \
  -o cfo-darwin-arm64 ./cmd/cfo/
```

Notes:

- `GOOS`/`GOARCH` follow Go's naming: `darwin/arm64` (Apple Silicon),
  `windows/amd64`, `freebsd/amd64`, `linux/386`, and so on.
- On Windows the output is `cfo.exe`; on all other platforms it is `cfo`.
- `CGO_ENABLED=0` produces a fully static binary (no libc), so it runs on any
  matching OS/arch without shared libraries.
- `-mod=vendor` builds against the local `vendor/` tree (create it first with
  `go mod vendor`); omit it to use normal module resolution instead.
- `-X main.Version` / `-X main.GitCommit` stamp the version and commit into the
  binary (defaults: `7.1.0` and `none`).

To build for all supported platforms on Unix-like shells:
```bash
./build-all.sh
```

To build for selected platforms only on Unix-like shells:
```bash
./build-all.sh --platforms linux/amd64,darwin/arm64
```

On Windows PowerShell, use:
```powershell
pwsh -File .\build-all.ps1
```

To build for selected platforms only in PowerShell:
```powershell
pwsh -File .\build-all.ps1 -Platforms linux/amd64,darwin/arm64
```

The build script runs the full test suite before compiling and aborts on any failure.
Compiled binaries are written to `dist/originals/` with SHA256 checksums in
`dist/checksums.txt`. UPX-compressed versions (where supported) are written to
`dist/compressed/`; the uncompressed binaries in `dist/originals/` are the
fully static, future-proof artifacts.

To run the tests manually (against the vendored tree — create it first with
`go mod vendor`):
```bash
go test -mod=vendor -cover ./...
```

---

## License

Copyright (c) 2026 Peter Vils Hansen. See [LICENSE](LICENSE) for details.
