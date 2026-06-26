# Cipherforge File Format and Cryptographic Design Reference

## Purpose of This Document

This document is the authoritative specification for the Cipherforge `.cfo`
binary file format **version 3** (v3). It is written for three audiences: a
security reviewer who wants to evaluate whether the cryptographic design is
sound; a developer who wants to write a compatible decoder without reference to
the Go source; and a future maintainer who needs to understand why the format
is the way it is before changing anything.

For each field in the format, this document explains what the field contains,
what security property it provides or relies on (confidentiality, integrity,
or authenticity), what an attacker could accomplish if the field were absent
or modified, and why alternative designs were rejected. Understanding *why*
the format exists is as important as knowing *what* it contains.

**Note on versions:** v3 is the current and only supported format version as
of Cipherforge 3.0.0+. v1 and v2 files are no longer supported for decryption
by the v3 binary; use Cipherforge 2.1.0 to decrypt v1/v2 files and re-encrypt
them with v3. See [Legacy Formats](#legacy-formats-v1v2) at the end of this
document for the historical format details.

---

## A Note on Security Properties

Throughout this document, three terms are used precisely:

**Confidentiality** — the field's value must not be learnable by an attacker
who can read the file. Fields that need confidentiality are protected by
encryption.

**Integrity** — the field's value must not be modifiable by an attacker
without detection. Fields that need integrity are covered by a MAC or AEAD
tag.

**Authenticity** — the field must be verifiable as having been produced by
someone who held the correct key. Authenticity implies integrity.

Not every field needs all three properties. Some fields (like the magic
signature) are public by design. Some fields (like the salt) need integrity
but not confidentiality — revealing their value to an attacker causes no
harm, but allowing them to be silently changed does. Getting this distinction
right is what separates a well-designed format from one that is merely
encrypted.

---

## High-Level Structure

A `.cfo` file consists of three contiguous regions:

```
╔══════════════════════════════╗
║    HEADER (64 B)             ║  Fixed size. Written first.
╠══════════════════════════════╣
║    PAYLOAD (variable)        ║  One or more encrypted segments.
╠══════════════════════════════╣
║    TRAILER (40 B)            ║  Fixed size. Written last.
╚══════════════════════════════╝
```

**The header** contains everything needed to derive the decryption keys and
reconstruct per-segment nonces. All header fields are stored in plaintext.
None of them need to be secret; what matters is that they are not tampered
with.

**The payload** is the encrypted content, divided into segments of up to
1 MiB each. Each segment is preceded by an 8-byte length field and is
independently authenticated by an AEAD tag. There is no index or directory;
the payload is read sequentially.

**The trailer** contains the total number of segments and a MAC that
authenticates the header fields and the segment count together. It is written
last because the segment count is not known until all plaintext has been
processed. It is read and verified first during decryption, before a single
segment is decrypted.

This sequencing — header first, trailer last, trailer verified before
payload — is a deliberate design decision. Verifying the trailer first means
a wrong password, a corrupt file, or a tampered header is detected before any
plaintext is written to disk and before any per-segment decryption work is
done. The cost is that decryption requires a seekable input (to jump to the
end and read the trailer). This is acceptable for file encryption, where
inputs are always regular files.

The minimum valid file size is **104 bytes**: 64-byte header plus 40-byte
trailer with no payload segments (the result of encrypting an empty file).

---

## Byte-Level Layout

All multi-byte integer fields use **big-endian** byte order throughout.

```
Byte offset   Length    Field
───────────   ──────    ─────────────────────────────────────────
0             8         Magic signature
8             4         Format version (uint32, = 3)
12            16        File salt (HKDF salt)
28            24        Segment Seed (HKDF IKM)
52            4         Argon2id time (uint32, passes)
56            4         Argon2id memory (uint32, KiB)
60            1         Argon2id threads (uint8)
61            3         Reserved (must be zero)
64            …         Payload (variable; see below)
EOF−40        8         Segment count (uint64)
EOF−32        32        Trailer HMAC-SHA256
```

Within the payload, each segment has this structure:

```
Byte offset   Length           Field
───────────   ──────           ─────────────────────────────────
+0            8                Segment ciphertext length (uint64)
+8            segmentLen       Ciphertext || Poly1305 tag (16 B)
```

Segments repeat without gaps or separators until the trailer begins at
`EOF − 40`.

---

## Header Fields

### Magic (bytes 0–7)

**Value:** the 8-byte sequence `C1 50 48 52 46 30 52 47`, which reads as the
ASCII characters `\xC1PHRF0RG` — a stylised encoding of "Cipherforge".

**Confidentiality required:** No. The magic is the same in every `.cfo` file
and is public by design.

**Integrity required:** Yes, trivially. If the magic bytes are flipped, the
decoder rejects the file before doing anything else.

**Why it exists:** Argon2id with production parameters (256 MiB, 5 passes)
takes several seconds. Checking 8 bytes before attempting key derivation
costs nothing and allows the decoder to immediately reject files that are not
`.cfo` files — including truncated files, files of the wrong type passed by
mistake, and simple corruption.

**Note on HMAC coverage:** The magic and version fields are not included in
the trailer HMAC. They affect parsing only, not decryption. If either is
tampered with, the file is rejected at the parsing stage with a clear error.

---

### Version (bytes 8–11)

**Value:** `00 00 00 03` — the uint32 value 3, encoded big-endian.

**Confidentiality required:** No.

**Integrity required:** Yes, trivially. Flipping this causes rejection or a
layout mismatch caught by the trailer HMAC.

**Why it exists:** Enables forward-compatible format detection. v3 decoders
reject files with `version < 3` (legacy formats) and `version > 3` (future
formats).

---

### File Salt (bytes 12–27)

**Value:** 16 bytes (128 bits) of uniformly random data produced by
`crypto/rand` for each file independently.

**Confidentiality required:** No. The salt is stored in plaintext.

**Integrity required:** Yes. The salt is included in the trailer HMAC.

**What the salt does:** In v3, the salt is used as the **HKDF salt** when
deriving file-specific keys from the master key (see Key Derivation below).
Each file gets a unique salt, so two files encrypted with the same password
produce independent encryption and MAC keys.

**Why 16 bytes:** 128 bits is the recommendation in RFC 9106. It guarantees
that the probability of two files sharing a salt is negligible even across
millions of files.

---

### Segment Seed (bytes 28–51)

**Value:** 24 bytes (192 bits) of uniformly random data produced by
`crypto/rand` for each file independently.

**Confidentiality required:** No. The Segment Seed is stored in plaintext.

**Integrity required:** Yes. The Segment Seed is included in the trailer
HMAC.

**What the Segment Seed does:** It is the HKDF Input Keying Material (IKM)
from which all per-segment nonces are derived. Storing one 24-byte value in
the header allows the decoder to reconstruct any segment's nonce on demand
using only the Seed and the segment's index.

An attacker who reads the Segment Seed and computes every per-segment nonce
still cannot decrypt a single byte without the encryption key.

**The HKDF construction for nonces:**

```
nonce_i = HKDF-SHA256(
    ikm  = segmentSeed,
    salt = nil,
    info = "cipherforge-segment-nonce-v1" || uint64_big_endian(i)
)[0:24]
```

The `nil` HKDF salt is safe because the IKM is already uniformly random. The
context string provides domain separation from any other HKDF use in the
protocol. Appending the fixed-width big-endian counter avoids boundary
ambiguity.

**Why HKDF rather than XOR:** XOR-based derivation (`seed XOR i`) has an
"identity at zero" weakness (the raw seed becomes nonce[0]) and a linear
structure that leaks the seed from two known (counter, nonce) pairs. HKDF is
a one-way PRF — the seed cannot be recovered from derived nonces.

---

### Argon2id Parameters (bytes 52–63)

**Value:** 12 bytes encoding three KDF parameters:

| Offset | Length | Field   | Encoding              |
|--------|--------|---------|-----------------------|
| 52     | 4      | Time    | uint32 big-endian     |
| 56     | 4      | Memory  | uint32 big-endian — KiB |
| 60     | 1      | Threads | uint8                 |
| 61     | 3      | Reserved| Must be zero          |

Production defaults: Time=5, Memory=262,144 KiB (256 MiB), Threads=4.

**Confidentiality required:** No.

**Integrity required:** Yes. The parameters are included in the trailer HMAC.
An attacker who downgrades them (e.g., swapping `time=4` → `time=1`) invalidates
the HMAC before key derivation.

**Why store parameters in the file:** Embedding the parameters makes each file
self-describing. A future binary with different defaults can still decrypt old
archives by reading the embedded parameters.

**Decoder safety limits:** To prevent resource-exhaustion attacks, the decoder
rejects parameters exceeding `time > 10` or `memory > 16,777,216 KiB` (16 GiB).
These limits are intentionally generous for production use but prevent
malicious files from forcing extreme resource consumption during key
derivation. Note: key derivation happens *before* HMAC verification, so the
HMAC cannot protect against parameter inflation — the safety limits are the
only defense.

---

## Payload

### Segment Length Field (8 bytes per segment)

**Value:** uint64, big-endian. The byte count of the following ciphertext,
**including** the 16-byte Poly1305 authentication tag.

**Confidentiality required:** No.

**Integrity required:** Yes, indirectly. The length field is not covered by
any MAC directly. Its integrity is enforced by the AEAD: if the length field
is modified, the decoder reads the wrong number of bytes, feeds them to
`aead.Open`, and the authentication tag fails.

**Bounds validation:** The decoder validates the length field against two
bounds before use:

1. **Upper bound:** `segmentLen <= SegmentSize + aead.Overhead()` (1,048,576 + 16).
   Prevents memory-exhaustion attacks from crafted length values.
2. **Lower bound:** `segmentLen >= aead.Overhead()` (16 bytes). Prevents
   unsigned integer underflow when computing plaintext length.

---

### Ciphertext and Poly1305 Tag

**Algorithm:** XChaCha20-Poly1305 (RFC 8439 plus the XChaCha extension).

**Per-segment nonce:** Derived from the Segment Seed and segment index via
HKDF-SHA256 as described above. The nonce is not stored in the file.

**Per-segment AAD:** Each segment is encrypted with Additional Authenticated
Data (AAD) computed as:

```
AAD = uint64_big_endian(segmentIndex) || uint64_big_endian(plaintextLength)
```

The AAD is 16 bytes. It is never stored in the file; both sides reconstruct
it from the loop counter and the measured plaintext length.

**What the AAD binding prevents:**
- **Segment reordering:** Moving segment 5 to position 2 fails because the tag was computed with index 5 but verified with index 2.
- **Length manipulation:** Claiming a 1 MiB segment contains only 500 KiB fails because the tag was computed over the true plaintext length.

**What per-segment AEAD cannot prevent (and why the trailer HMAC exists):**

1. **File-level truncation:** Removing the last N complete segments leaves
   all remaining segments authenticating correctly. The trailer HMAC commits
   to the segment count, catching this.
2. **Segment appending:** Adding segments from another file with the same
   key. Caught by the trailer HMAC (segment count mismatch).
3. **Header substitution:** Swapping the salt and Segment Seed from another
   file. Caught by the trailer HMAC.

---

## Trailer

The trailer is the last 40 bytes of the file.

### Segment Count (EOF−40 to EOF−33)

**Value:** uint64, big-endian. The total number of segment frames in the
payload.

**Confidentiality required:** No.

**Integrity required:** Yes. The segment count is an input to the trailer
HMAC. Any modification invalidates the HMAC, which is verified before any
decryption.

### Trailer HMAC (EOF−32 to EOF−1)

**Value:** 32 bytes. HMAC-SHA256 computed as:

```
HMAC-SHA256(
    key   = macKey,
    input = "cipherforge-trailer-hmac-v3"
          || salt                          (16 bytes)
          || segmentSeed                   (24 bytes)
          || uint32_be(argon2Time)         (4 bytes)
          || uint32_be(argon2Memory)       (4 bytes, KiB)
          || uint8(argon2Threads)          (1 byte)
          || zero[3]                       (3 reserved bytes)
          || uint64_big_endian(segmentCount) (8 bytes)
)
```

The v3 context string (`cipherforge-trailer-hmac-v3`) provides domain
separation from v1 and v2, ensuring a v3 HMAC can never validate against an
older decoder.

**What the HMAC covers and why:**

| Element | Why included |
|---|---|
| Context string | Domain separation across versions |
| `salt` | Detects salt substitution from another file |
| `segmentSeed` | Detects Segment Seed substitution from another file |
| `argon2Time`, `argon2Memory`, `argon2Threads` | Detects KDF parameter downgrade attacks |
| `segmentCount` | Detects file truncation and segment appending |

**Verification uses `hmac.Equal`** — a constant-time comparison that prevents
timing side-channel attacks on the HMAC verification.

---

## Key Derivation (v3)

### Two-Tier Architecture

v3 uses a two-tier key derivation design:

```
┌─────────────────────────────────────────────────────────────┐
│  Tier 1: Master Key (once per password)                     │
│                                                             │
│  masterKey = Argon2id(                                      │
│      password  = <user password>,                           │
│      salt      = "cipherforge-master-key-v1"  (fixed),      │
│      time      = <from header, default 5>,                  │
│      memory    = <from header, default 262,144 KiB>,        │
│      threads   = <from header, default 4>,                  │
│      keyLen    = 32                                         │
│  )                                                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Tier 2: File-Specific Keys (once per file)                 │
│                                                             │
│  raw = HKDF-SHA256(                                         │
│      ikm   = masterKey,                                     │
│      salt  = <16-byte per-file salt from header>,           │
│      info  = "cipherforge-file-key-v1",                     │
│      outLen = 64                                            │
│  )                                                          │
│                                                             │
│  encKey = raw[0:32]    — XChaCha20-Poly1305 encryption key  │
│  macKey = raw[32:64]   — HMAC-SHA256 trailer key            │
└─────────────────────────────────────────────────────────────┘
```

**Why two tiers:** The memory-hard Argon2id derivation is expensive (~several
seconds). For batch encryption of N files, the v3 design pays this cost
**once** (for the master key) rather than N times. File-specific keys are
derived via HKDF, which is extremely fast (~microseconds).

**Why the fixed master-key salt:** The master key salt is the fixed string
`"cipherforge-master-key-v1"`. This is deliberate: the master key is
ephemeral (never stored), and per-file uniqueness comes from the file salt
in the HKDF step. HKDF with a random, unique salt guarantees that each file's
keys are computationally independent, even when derived from the same master
key.

**Security implication:** With a fixed master-key salt, attacking N files
encrypted with the same password costs ~1 Argon2id derivation per password
guess (plus negligible HKDF work per file), rather than N Argon2id
derivations per guess. This is a deliberate trade-off: it makes batch
encryption dramatically faster, but it also means the attacker's per-guess
cost is independent of the number of files. **This trade-off is acceptable
when the password has sufficient entropy** — the auto-generated 44-character
passwords provide ~258 bits of entropy, making any brute-force attack
infeasible regardless of this optimization.

**Why Argon2id:** Winner of the 2015 Password Hashing Competition, specified
in RFC 9106. Its memory-hardness directly limits GPU/ASIC brute-force
parallelism: each guess requires its own 256 MiB allocation, and memory
bandwidth — not compute — is the bottleneck.

**Why 256 MiB and 5 passes (v3.2+):** Earlier versions used 1 GiB / 4 passes.
Analysis showed that for the default auto-generated 44-character passwords
(~258 bits), the KDF parameters are cryptographically irrelevant — the keyspace
is physically unsearchable regardless of Argon2 settings. For user-supplied
passwords, the critical threshold is ~256 MiB: below this, an ASIC attacker can
fit working memory on-die (SRAM), dramatically reducing per-guess cost. At
256 MiB, external DRAM is required, which is where Argon2id's memory-hardness
imposes real economic cost on ASIC designers. Above 256 MiB, returns diminish
sharply — 1 GiB quadruples attacker per-core memory cost but also quadruples
user wait time with no meaningful security gain for passwords of reasonable
length. The time parameter was raised from 4 to 5 to partially compensate for
the reduced memory by making time-memory tradeoff attacks proportionally more
expensive, at negligible runtime cost (~20% slower per pass). The combined
parameters keep brute-force cost above $200K in ASIC silicon even for a weak
8-character password, while completing in ~1 second on modern CPUs.

**Key separation:** Deriving both `encKey` and `macKey` from a single HKDF
expansion is an established pattern. There is no known relationship between
`raw[0:32]` and `raw[32:64]`, and they are used for entirely different
cryptographic operations.

---

## Verification Order (Decryption)

```
1.  Read and validate magic (8 bytes).
2.  Read and validate version (4 bytes) — must be ≥ 3.
3.  Read file salt (16 bytes).
4.  Read Segment Seed (24 bytes).
5.  Read Argon2id parameters (12 bytes), validate against safety limits.
6.  Derive masterKey = Argon2id(password, fixedSalt, params).
7.  Derive encKey, macKey = HKDF-SHA256(masterKey, fileSalt, fileKeyContext).
8.  Seek to EOF − 40. Read segment count and stored HMAC.
9.  Compute expected HMAC (v3 construction). Compare with hmac.Equal.
10. If HMAC fails: return "authentication failed" immediately.
11. Seek to payload start (byte 64). Decrypt segments sequentially.
```

Steps 1–5 happen before key derivation because magic/version validation is
cheap — no point spending several seconds on Argon2id if the file is
obviously not a `.cfo` file. Step 8 catches wrong passwords, corrupt files,
truncated files, appended files, and header substitution — all before any
plaintext is written to disk.

---

## Key Lifetime and Memory Safety

Both `encKey` and `macKey` are stored in byte slices (`[]byte`, not Go
strings) to prevent interning. Both are zeroed immediately after use via:

```go
for i := range b { b[i] = 0 }
runtime.KeepAlive(b)
```

The `runtime.KeepAlive` call prevents the Go compiler from treating the
zeroing loop as a dead store and eliminating it. Both keys are passed to
`mlock` (Unix) / `VirtualLock` (Windows) after derivation to prevent swapping.

The master key is zeroed immediately after all file-specific keys have been
derived.

**Known limitation:** Go's garbage collector may copy heap-allocated byte
slices during compaction, leaving residual copies in freed memory. This is a
Go-language limitation, not a Cipherforge-specific issue.

---

## What the Format Does and Does Not Protect

**Protected by this format:**

- Confidentiality of plaintext against an attacker who can read the file but
  does not know the password.
- Integrity of each segment against modification, truncation within a segment,
  and content substitution.
- Ordering integrity: segments cannot be reordered or deleted without
  detection.
- File-level integrity: the file cannot be truncated at a segment boundary,
  have segments appended, or have its header substituted, without the trailer
  HMAC failing.
- Prompt rejection of wrong passwords and corrupt files, before any plaintext
  is written to disk.
- Prompt rejection of non-`.cfo` files before key derivation.

**Not protected by this format:**

- **The existence of the encrypted file.** Anyone who can see the filesystem
  knows a `.cfo` file is present.
- **The original filename and extension.** The output is named
  `<original_name>.cfo`.
- **The approximate plaintext size.** Each segment contributes 24 bytes of
  overhead (8 length + 16 AEAD tag). Plaintext size is predictable to within
  one segment (1 MiB).
- **Access patterns or usage timing.** The format makes no guarantees about
  when or how often a file is decrypted.
- **Key commitment.** XChaCha20-Poly1305 does not provide key commitment.
  In a contrived scenario, a computationally powerful attacker could craft a
  ciphertext that decrypts under two different keys.

---

## Reference: Decryption Algorithm (v3)

```
function DecryptCFO(file, password) -> plaintext | error:

  1. Read 8 bytes at offset 0.
     Assert bytes equal: C1 50 48 52 46 30 52 47

  2. Read 4 bytes at offset 8 as uint32 big-endian → version.
     Assert version >= 3

  3. Read 16 bytes at offset 12 → fileSalt.

  4. Read 24 bytes at offset 28 → segmentSeed.

  5. Read 4 bytes at offset 52 as uint32 big-endian → argon2Time
     Read 4 bytes at offset 56 as uint32 big-endian → argon2Memory  (KiB)
     Read 1 byte  at offset 60 as uint8             → argon2Threads
     Skip 3 bytes at offset 61 (reserved)

     Assert argon2Time    >= 1 and <= 10
     Assert argon2Memory  >= 1 and <= 16,777,216
     Assert argon2Threads >= 1 and <= 255

  6. Derive master key:
       masterKey = Argon2id(password, "cipherforge-master-key-v1",
                            time=argon2Time, memory=argon2Memory,
                            threads=argon2Threads, keyLen=32)

  7. Derive file-specific keys:
       raw = HKDF-SHA256(ikm=masterKey, salt=fileSalt,
                         info="cipherforge-file-key-v1", outLen=64)
       encKey = raw[0:32]
       macKey = raw[32:64]

  8. Read 8 bytes at file_size - 40 as uint64 big-endian → segmentCount.
     Read 32 bytes at file_size - 32 → storedHMAC.

  9. Compute expectedHMAC:
       expectedHMAC = HMAC-SHA256(
           key   = macKey,
           input = "cipherforge-trailer-hmac-v3"
                || fileSalt
                || segmentSeed
                || uint32_big_endian(argon2Time)
                || uint32_big_endian(argon2Memory)
                || uint8(argon2Threads) || zero[3]
                || uint64_big_endian(segmentCount)
       )
     Assert hmac_equal(storedHMAC, expectedHMAC)  ← constant-time

  10. Seek to payload start (byte 64).

  11. For i in 0 .. segmentCount - 1:

       a. Read 8 bytes as uint64 big-endian → segmentLen.

       b. Assert segmentLen >= 16 and segmentLen <= 1048576 + 16

       c. Read segmentLen bytes → ciphertextWithTag.

       d. Derive nonce:
            nonce = HKDF-SHA256(
                ikm  = segmentSeed,
                salt = nil,
                info = "cipherforge-segment-nonce-v1" || uint64_big_endian(i)
            )[0:24]

       e. plaintextLen = segmentLen - 16
          Assert plaintextLen <= 1048576

       f. AAD = uint64_big_endian(i) || uint64_big_endian(plaintextLen)

       g. plaintext = XChaCha20Poly1305.Open(
              key        = encKey,
              nonce      = nonce,
              ciphertext = ciphertextWithTag,
              aad        = AAD
          )
          On failure: return "authentication failed: corrupt segment"

       h. Append plaintext to output.

  12. Return output.
```

Byte order is big-endian throughout. The HKDF info field is the exact byte
concatenation of the ASCII string and the 8-byte counter. The HMAC input is
the exact byte concatenation with no separators or length prefixes.

---

## Legacy Formats (v1/v2)

### v2 (Cipherforge 2.0.x – 2.1.x)

v2 stored the Argon2id parameters in the header (12 bytes at offset 52,
same layout as v3) but used a **per-file Argon2id salt** — the 16-byte salt
at offset 12 was the Argon2id salt, not an HKDF salt. Keys were derived as:

```
raw = Argon2id(password, fileSalt, time, memory, threads, keyLen=64)
encKey = raw[0:32]
macKey = raw[32:64]
```

The v2 trailer HMAC used context string `"cipherforge-trailer-hmac-v2"`.
Header size: 64 bytes. Minimum file size: 104 bytes. Version field: `0x00000002`.

### v1 (Cipherforge 1.x)

v1 had a 52-byte header (no Argon2id parameters). Decoders used fixed
production defaults (time=4, memory=1,048,576 KiB, threads=4). The salt
was the Argon2id salt. Version field: `0x00000001`. Trailer HMAC context:
`"cipherforge-trailer-hmac-v1"`.

### Migration Path

1. Decrypt v1/v2 `.cfo` files using Cipherforge **v2.1.0**
2. Re-encrypt the plaintext with Cipherforge **v3.x** (current version)
3. Safely discard the old `.cfo` files
