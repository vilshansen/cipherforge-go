# Cipherforge Cryptographic Design

This document explains the rationale and design decisions behind every
cryptographic choice in Cipherforge. It is written for an experienced developer
who has some familiarity with cryptography — you know what an AEAD is, you
understand the difference between a PRF and a KDF, and you have opinions about
nonce sizes. If you are evaluating whether this tool is safe to use for your
threat model, this document is for you.

Every algorithm, every parameter, and every construction is explained in terms
of the problem it solves. Where alternatives were rejected, the rejection
rationale is given. Where numbers appear (256 MiB, 44 characters, 24 bytes),
the math is shown.

---

## Table of Contents

- [Design Goals](#design-goals)
- [Algorithm Catalogue](#algorithm-catalogue)
- [Encryption: XChaCha20-Poly1305](#encryption-xchacha20-poly1305)
- [Key Derivation: Argon2id](#key-derivation-argon2id)
- [Key Separation: HKDF-SHA256](#key-separation-hkdf-sha256)
- [Two-Tier Key Architecture](#two-tier-key-architecture)
- [Nonce Management](#nonce-management)
- [Authentication and Integrity](#authentication-and-integrity)
  - [Per-Segment AEAD](#per-segment-aead)
  - [File-Level Trailer HMAC](#file-level-trailer-hmac)
- [Password Generation](#password-generation)
- [Memory Safety](#memory-safety)
- [Post-Quantum Considerations](#post-quantum-considerations)
- [What Is and Is Not Protected](#what-is-and-is-not-protected)
- [References](#references)

---

## Design Goals

Cipherforge is designed for **long-term archival encryption**. The core
assumption is that a file encrypted today must be decryptable decades from now,
possibly with different hardware, a different operating system, and without the
original binary. This assumption drives every decision:

1. **Algorithm simplicity over hardware acceleration.** An algorithm that can be
   specified in a few pages of pseudocode ages better than one that relies on
   a specific instruction set extension.

2. **Self-describing format.** The `.cfo` file carries its own KDF parameters,
   so a future decoder doesn't need to know what defaults were in fashion when
   the file was created.

3. **No silent corruption.** Tampering with any byte — header, payload, or
   trailer — is detected before any plaintext is written to disk.

4. **Defense in depth.** Multiple independent authentication layers (per-segment
   AEAD + file-level HMAC) protect against different classes of attack.

5. **Forward secrecy is not a goal.** This is file encryption, not a network
   protocol. Keys are derived from a long-lived password; there is no ephemeral
   key exchange. See [What Is and Is Not Protected](#what-is-and-is-not-protected).

---

## Algorithm Catalogue

| Component | Algorithm | Standard | Key/Output Size |
|---|---|---|---|
| Password hashing | Argon2id | [RFC 9106] | 256-bit output |
| Key separation | HKDF-SHA256 | [RFC 5869] | 2 × 256-bit keys |
| Encryption | XChaCha20 | [RFC 8439] + [draft-irtf-cfrg-xchacha] | 256-bit key |
| Authentication (segment) | Poly1305 | [RFC 8439] | 128-bit tag |
| Authentication (file) | HMAC-SHA256 | [RFC 2104] / [FIPS 198-1] | 256-bit tag |
| Key commitment (v5) | HMAC-SHA256 | [RFC 2104] / [FIPS 198-1] | 256-bit tag |
| Hashing | SHA-256 | [FIPS 180-4] | 256-bit |
| Randomness | OS CSPRNG | — | — |
| Password generation | `crypto/rand` + rejection sampling | — | ~257-bit entropy |

Every algorithm in this table has been standardized and publicly reviewed for
at least a decade. No proprietary, patented, or obscure constructions are used.

---

## Encryption: XChaCha20-Poly1305

### What It Is

XChaCha20-Poly1305 is an Authenticated Encryption with Associated Data (AEAD)
construction. It combines:

- **XChaCha20**: a stream cipher. ChaCha20 is the 256-bit-key, 96-bit-nonce
  variant specified in [RFC 8439]. The "X" prefix denotes the **extended nonce**
  variant: a 192-bit nonce is hashed (via HChaCha20) into the 96-bit internal
  nonce that ChaCha20 expects.

- **Poly1305**: a one-time authenticator. It produces a 128-bit authentication
  tag over the ciphertext and the Additional Authenticated Data (AAD).

Together they provide IND-CCA3 security: confidentiality, ciphertext integrity,
and binding of associated (unencrypted) data.

### Why XChaCha20-Poly1305 and Not AES-GCM

This is the single most important design decision. The comparison:

| Property | AES-GCM | XChaCha20-Poly1305 |
|---|---|---|
| Nonce size | 96 bits | 192 bits |
| Safe with random nonces? | No — ~2³² encryptions before collision risk | Yes — ~2⁶⁴ encryptions, practically unlimited |
| Hardware acceleration | AES-NI (x86), ARMv8 Crypto | None (but constant-time in software) |
| Specification length | Complex — GHASH field arithmetic | Short — ARX (add-rotate-XOR) design |
| Side-channel resistance | Table-based implementations leak via cache | Constant-time by construction |

The critical difference is the **nonce size**. AES-GCM's 96-bit nonce means
that with random nonces, the probability of a collision reaches 50% after
approximately 2³² encryptions under the same key (birthday bound). For a
network protocol encrypting billions of packets, this is a real concern. For
file encryption, the risk is smaller but still unnecessary.

XChaCha20's 192-bit nonce eliminates nonce-reuse concerns entirely for random
nonces: at 2⁶⁴ encryptions, the collision probability is still negligible
(~2⁻⁶⁴). This means Cipherforge can generate a fresh random nonce per segment
(~1 MiB of plaintext) with no risk of reuse, even for a multi-terabyte file
with millions of segments.

For long-term archival, **algorithm simplicity** also matters. XChaCha20-Poly1305
is built from three simple primitives (ChaCha20 quarter-round, Poly1305
clamping, HChaCha20 hash). A motivated developer can implement it from the RFC
pseudocode in a weekend. AES-GCM requires understanding GHASH field arithmetic
over GF(2¹²⁸), which is substantially more complex and error-prone.

### Implementation

Cipherforge uses the Go standard extended library implementation:

```go
import "golang.org/x/crypto/chacha20poly1305"

aead, err := chacha20poly1305.NewX(key) // key must be exactly 32 bytes
```

The `NewX` constructor selects the extended-nonce (XChaCha20) variant. Per
[RFC 8439 § 2.8], the nonce is 24 bytes (192 bits).

### Relevant Standards

- [RFC 8439] — ChaCha20 and Poly1305 for IETF Protocols
- [draft-irtf-cfrg-xchacha] — XChaCha20 extended-nonce variant
- [FIPS 180-4] — SHA-256 (used by HChaCha20 internally)

---

## Key Derivation: Argon2id

### What It Is

Argon2id is a memory-hard password-based key derivation function. It won the
Password Hashing Competition (PHC) in 2015 and is standardized in [RFC 9106].

Argon2 has two variants and a hybrid:

- **Argon2d**: data-dependent memory access. Maximally resistant to GPU/ASIC
  attacks, but vulnerable to side-channel attacks (cache timing).
- **Argon2i**: data-independent memory access. Side-channel resistant, but
  weaker against GPU/ASIC attacks.
- **Argon2id**: hybrid. First pass is data-independent (Argon2i), subsequent
  passes are data-dependent (Argon2d). This combines side-channel resistance
  with GPU/ASIC resistance. This is the variant Cipherforge uses.

### Parameters

| Parameter | Production Value | Purpose |
|---|---|---|
| Time (passes) | 5 | Number of iterations over memory |
| Memory | 262,144 KiB (256 MiB) | Working memory size |
| Threads (lanes) | 4 | Degree of parallelism |
| Output length | 32 bytes (256 bits) | Matches XChaCha20 key size |
| Salt | `"cipherforge-master-key-v1"` (fixed) | Domain separation |

### Why These Parameters

**Memory: 256 MiB.** The key insight of memory-hard KDFs is that memory is
expensive. An ASIC attacker must provision 256 MiB of SRAM or DRAM per
parallel guess. Below ~64 MiB, working memory fits in on-die SRAM on a
specialized ASIC, making per-guess cost negligible. At 256 MiB, external DRAM
is required, and DRAM bandwidth — not compute — becomes the bottleneck.
Argon2's memory-hardness means that even an ASIC with thousands of cores
cannot parallelize across guesses without provisioning thousands of 256 MiB
DRAM chips. At current DRAM prices (~$3/GB), the memory alone for 1,000
parallel cores costs ~$768,000.

Above 256 MiB, returns diminish sharply. Doubling memory to 512 MiB doubles
both attacker cost and user wait time, with no meaningful security gain for
passwords of reasonable length. The standard recommendation from [RFC 9106
§ 4] for file encryption is 256 MiB.

**Time: 5 passes.** Earlier versions of Cipherforge used 4 passes with 1 GiB
of memory. When memory was reduced to 256 MiB (to keep the KDF under ~1 second
on modern hardware), the time parameter was increased from 4 to 5 to partially
compensate. The extra pass makes time-memory tradeoff (TMTO) attacks
proportionally more expensive: an attacker who halves memory must double
computation, and the baseline is now 5 passes instead of 4. The 5th pass adds
~20% to user wait time.

Combined cost estimate: cracking a single 8-character alphanumeric password
with these parameters would require over $200,000 in ASIC silicon (DRAM cost
alone), even assuming ideal attack hardware.

**Threads: 4.** Matches typical consumer CPU core count. Argon2's parallelism
is within a single invocation, so it benefits multi-core CPUs without
requiring them. A decoder running on a single-core machine simply runs the 4
lanes sequentially; the memory cost is unchanged.

### Why Argon2id and Not bcrypt, scrypt, or PBKDF2

| KDF | Memory Hardness | Standardized | Notes |
|---|---|---|---|
| PBKDF2 | None | [RFC 8018] / [NIST SP 800-132] | CPU-only. Trivially parallelizable on GPU. |
| bcrypt | 4 KiB (fixed) | De facto | Memory too small for modern ASIC resistance. |
| scrypt | Configurable | [RFC 7914] | Predecessor to Argon2. Weaker TMTO resistance. |
| **Argon2id** | **Configurable, 256 MiB default** | **[RFC 9106]** | PHC winner. OWASP and RFC 9106 recommended. |

PBKDF2 with a high iteration count is still the most widely deployed KDF, but
it provides no memory hardness. An attacker with a GPU farm can test billions
of passwords per second regardless of the iteration count. bcrypt's 4 KiB
memory limit was designed for 1999 hardware and is now trivially satisfied by
GPU register files.

scrypt is the direct predecessor to Argon2 and shares its memory-hard design.
However, scrypt has a known time-memory tradeoff vulnerability: an attacker
can reduce memory usage by a factor of ~4 with only ~2× computation overhead.
Argon2id was specifically designed to minimize this tradeoff.

### Relevant Standards

- [RFC 9106] — Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

---

## Key Separation: HKDF-SHA256

### What It Is

HKDF (HMAC-based Key Derivation Function) is defined in [RFC 5869]. It takes
input keying material (IKM), an optional salt, and an optional context string
(info), and produces cryptographically independent output keys.

HKDF has two stages:

1. **Extract:** `PRK = HMAC-SHA256(salt, IKM)` — concentrates entropy into a
   fixed-size pseudorandom key.
2. **Expand:** `OKM = HMAC-SHA256(PRK, info || 0x01) || HMAC-SHA256(PRK, OKM_prev || info || counter) ...`

Cipherforge uses the single-stage `hkdf.New` convenience function, which
combines Extract and Expand for the common case.

### Usage in Cipherforge

HKDF-SHA256 is used in two places:

#### 1. File-Specific Key Derivation

```
raw (64 bytes) = HKDF-SHA256(
    ikm  = masterKey,           // 32 bytes, from Argon2id
    salt = fileSalt,            // 16 bytes, per-file random
    info = "cipherforge-file-key-v1"
)

encKey = raw[0:32]   // XChaCha20-Poly1305 encryption key
macKey = raw[32:64]  // HMAC-SHA256 trailer authentication key
```

#### 2. Per-Segment Nonce Derivation

```
nonce (24 bytes) = HKDF-SHA256(
    ikm  = segmentSeed,                     // 24 bytes, per-file random
    salt = nil,                              // safe: IKM is uniformly random
    info = "cipherforge-segment-nonce-v1" || uint64_be(segmentIndex)
)[0:24]
```

### Why HKDF and Not Simpler Constructions

**Why not XOR (seed ⊕ counter)?** Two problems:

1. **Identity at zero.** When `counter = 0`, the nonce equals the seed. This
   means nonce[0] for every file would be the raw seed value, and the seed
   would be derivable from any known-plaintext segment at index 0.

2. **Linear structure.** Given two (counter, nonce) pairs, an attacker can
   XOR them to recover the seed: `nonce[0] ⊕ nonce[1] = seed ⊕ 0 ⊕ seed ⊕ 1`
   (with a simple XOR-based counter). With HKDF, the seed cannot be recovered
   from any number of derived nonces — it's a one-way PRF.

**Why not SHA-256 alone?** SHA-256 is not designed as a KDF. While
`SHA-256(seed || counter)` is likely secure in practice, HKDF provides a
formal security proof under the assumption that HMAC is a PRF. Using an
established KDF rather than an ad-hoc construction reduces the attack surface
and makes the design easier to audit.

**Why nil salt for segment nonces?** [RFC 5869 § 3.1] permits a nil salt when
the IKM already has sufficient entropy. The `segmentSeed` is a 24-byte
uniformly random value from `crypto/rand`, so a salt adds no security. The
`info` string provides domain separation.

### Key Separation Guarantee

Deriving both `encKey` and `macKey` from a single 64-byte HKDF expansion is
an established pattern used in TLS 1.3, Signal, and WireGuard. The security
property is that knowing `encKey` provides no information about `macKey`, and
vice versa — they are computationally independent.

### Relevant Standards

- [RFC 5869] — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [RFC 2104] — HMAC: Keyed-Hashing for Message Authentication
- [FIPS 198-1] — The Keyed-Hash Message Authentication Code (HMAC)

---

## Two-Tier Key Architecture

Cipherforge v4 uses a two-tier key derivation design that separates the
expensive memory-hard KDF from the cheap per-file key derivation:

```
┌─────────────────────────────────────────────────────────────┐
│  Tier 1: Master Key (once per password, ~1 second)          │
│                                                             │
│  masterKey = Argon2id(                                      │
│      password,                                              │
│      salt   = "cipherforge-master-key-v1"  (fixed string),  │
│      time   = 5,   memory = 256 MiB,  threads = 4           │
│  )                                                          │
├─────────────────────────────────────────────────────────────┤
│  Tier 2: File-Specific Keys (once per file, ~microseconds)  │
│                                                             │
│  encKey, macKey = HKDF-SHA256(masterKey, fileSalt)          │
│  nonce_i       = HKDF-SHA256(segmentSeed, counter=i)        │
└─────────────────────────────────────────────────────────────┘
```

### Why Two Tiers

The motivation is **batch encryption performance**. Encrypting 100 files
naively — running Argon2id 100 times — would take ~100 seconds on modern
hardware. With the two-tier design, Argon2id runs **once** to produce the
master key, and each file gets independent keys via HKDF-SHA256 (a single
HMAC invocation, ~1 microsecond per file). The total cost drops from ~100
seconds to ~1 second + 100 microseconds.

### Security Implications of the Fixed Master-Key Salt

The master-key salt is the fixed ASCII string `"cipherforge-master-key-v1"`.
This is an intentional design choice, but it has a security consequence that
must be understood.

With a fixed salt, the master key is always `Argon2id(password, "cipherforge-master-key-v1")`.
An attacker who wants to crack N files encrypted with the same password only
needs to run Argon2id **once per password guess** (plus negligible HKDF work
per file to check each file's HMAC). If the master-key salt were per-file,
the attacker would need N Argon2id derivations per guess.

This tradeoff is acceptable **because Cipherforge auto-generates 44-character
passwords with ~257 bits of entropy**. At that keyspace size, brute force is
physically impossible regardless of the KDF cost — the attacker would need to
test more passwords than there are atoms in the observable universe. The
two-tier design is optimized for the auto-generated password case, which is
the default and recommended mode.

**When user-supplied passwords are used** (via `-p`), a warning is displayed
if the password is shorter than 20 characters and multiple files are being
encrypted. In this case, each file shares the same master key, and a weak
password compromises all files simultaneously. This is an inherent limitation
of password-based encryption, not specific to the two-tier design.

### Key Lifetimes

| Key | Derived When | Zeroed When | Scope |
|---|---|---|---|
| `masterKey` | Once per batch or file | After all file keys derived | Per password |
| `encKey` | Once per file | After all segments decrypted | Per file |
| `macKey` | Once per file | After trailer HMAC verified | Per file |
| Per-segment nonce | On demand | After segment AEAD operation completes | Per segment |

All keys are stored in `[]byte` slices (never Go strings, which are interned
and immutable). All are zeroed explicitly via `crypto.ZeroBytes` and locked
against swapping via `mlock`/`VirtualLock`. See [Memory Safety](#memory-safety).

---

## Nonce Management

### The Problem

A stream cipher nonce must never repeat under the same key. If it does, the
confidentiality of both messages is compromised: XORing the two ciphertexts
eliminates the keystream, revealing `plaintext1 ⊕ plaintext2`.

For a 1 TB file encrypted in 1 MiB segments, Cipherforge produces ~1,048,576
segments. If nonces were generated randomly per segment using a 96-bit nonce
(AES-GCM), the birthday bound collision probability would be non-negligible:

$$p(\text{collision}) \approx \frac{n^2}{2 \cdot 2^{96}} = \frac{(10^6)^2}{2 \cdot 2^{96}} \approx 2 \times 10^{-17}$$

While still small, this is unnecessary risk. With a 192-bit nonce
(XChaCha20), the same calculation gives a collision probability of
approximately 2⁻⁷⁶ — effectively zero.

### Deterministic Nonce Derivation

Cipherforge avoids random nonces entirely. Instead, per-segment nonces are
**derived deterministically** from a per-file random seed:

```
nonce_i = HKDF-SHA256(
    ikm  = segmentSeed,       // 192-bit random, stored in header
    salt = nil,
    info = "cipherforge-segment-nonce-v1" || uint64_be(i)
)[0:24]
```

This construction guarantees:

1. **Uniqueness:** Each segment index `i` produces a unique nonce. The counter
   is a simple incrementing `uint64`, so nonce reuse is mathematically
   impossible as long as the segment index is unique within a file.

2. **One-way property:** Given `nonce_i` for any set of segment indices, the
   `segmentSeed` cannot be recovered. This is important because the seed is
   stored in plaintext in the file header; an attacker who reads the seed can
   compute all nonces but still cannot decrypt without the encryption key.

3. **Streaming-friendliness:** The decoder can reconstruct `nonce_i` for any
   segment index on demand, without storing an array of 1M+ nonce values. It
   re-derives the nonce from the seed each time — the HKDF cost is negligible
   compared to the AEAD decryption cost.

### Why HKDF and Not a Counter Nonce

XChaCha20's internal 96-bit ChaCha20 nonce is constructed from the 192-bit
XChaCha20 nonce via HChaCha20. One might think a simple counter would suffice
as the 192-bit nonce: `nonce = segmentSeed || uint64_be(i)` (concatenation).

This would work and would be secure. The rejection rationale is defense in
depth: HKDF ensures that even if the segment seed has poor entropy (a bug in
`crypto/rand`, a compromised PRNG, etc.), the derived nonces are still
uniformly distributed. Counter-based nonces expose the raw seed structure.
The HKDF cost is ~1 microsecond per segment, which is negligible compared to
the AEAD operation (~5-10 microseconds per 1 MiB segment).

---

## Authentication and Integrity

Cipherforge uses a **defense-in-depth** authentication design with two
independent layers:

### Per-Segment AEAD

Each 1 MiB segment is independently encrypted and authenticated by
XChaCha20-Poly1305. The authenticated data includes:

```
AAD = uint64_be(segmentIndex) || uint64_be(plaintextLength)
```

| Attack | Prevented By |
|---|---|
| Segment content modified | Poly1305 tag fails → AEAD rejects |
| Segment reordered (move segment 5 to position 2) | AAD contains `segmentIndex` → tag was computed with index 5, verified with index 2 |
| Segment length forged (claim 1 MiB segment is 500 KiB) | AAD contains `plaintextLength` → tag was computed over true length, mismatch on verify |
| Bit flip within a segment | Poly1305 tag fails |

**What per-segment AEAD does NOT protect against:**

1. **File truncation.** Removing the last N segments — all remaining segments
   still authenticate correctly.
2. **Segment appending.** Adding segments from another `.cfo` file encrypted
   with the same key — the appended segments authenticate individually.
3. **Header substitution.** Swapping the salt and segment seed with those from
   another file — per-segment AEAD doesn't cover the header.

These are protected by the file-level HMAC.

### File-Level Trailer HMAC

The trailer (last 40 bytes of the file) contains an 8-byte segment count and
a 32-byte HMAC-SHA256 tag computed over all header fields:

```
HMAC-SHA256(
    key   = macKey,
    input = "cipherforge-trailer-hmac-v4"   // domain separation
         || fileSalt         (16 bytes)
         || segmentSeed      (24 bytes)
         || uint32_be(time)  (4 bytes)
         || uint32_be(memory)(4 bytes)
         || uint8(threads)   (1 byte)
         || zero[3]          (3 reserved bytes)
         || uint64_be(segmentCount)  (8 bytes)
)
```

| Attack | Prevented By |
|---|---|
| File truncation | HMAC commits to `segmentCount` |
| Segment appending | HMAC commits to `segmentCount` — appended segments cause mismatch |
| Header substitution (salt, seed swapped) | HMAC covers `fileSalt` and `segmentSeed` |
| KDF parameter downgrade (change time=5 → time=1) | HMAC covers Argon2 parameters |

**Critical design detail: verification order.** The HMAC is verified **before**
any segment is decrypted. The decryption algorithm:

1. Read header (magic, version, salt, seed, KDF params) — cheap, no crypto
2. Derive keys from password + header fields — expensive (~1 second)
3. Seek to EOF−40, read trailer HMAC
4. Compute expected HMAC and compare in constant time (`hmac.Equal`)
5. **Only if HMAC matches:** seek back to payload and decrypt segments

This means a wrong password, tampered file, or corrupted header is detected
before any plaintext is written to disk. This is a deliberate design choice
that requires a seekable input (the decoder needs to jump to the end and
back), which rules out streaming from stdin for decryption. This is an
acceptable tradeoff for file encryption, where inputs are always regular
files.

### Constant-Time HMAC Comparison

The HMAC comparison uses `crypto/hmac.Equal`:

```go
if !hmac.Equal(storedHMAC, expectedHMAC) {
    return ErrAuthenticationFailed
}
```

`hmac.Equal` compares byte slices in constant time — it does not return early
on the first mismatched byte. A timing side-channel on the HMAC comparison
could otherwise leak, byte by byte, the correct HMAC value to an attacker who
can submit chosen ciphertexts and measure the rejection time.

### Segment Length Bounds

When reading segments, the decoder validates the length field against two
bounds **before** allocating memory or passing data to the AEAD:

1. **Upper bound:** `segmentLen ≤ 1,048,576 + 16` (SegmentSize + AEAD overhead).
   Prevents memory exhaustion from a maliciously crafted length value of
   2⁶⁴ − 1 bytes.

2. **Lower bound:** `segmentLen ≥ 16` (minimum AEAD tag size). Prevents
   unsigned integer underflow when computing `plaintextLen = segmentLen - 16`.

These bounds are the only defense against crafted payload lengths, since the
length field itself is not covered by any MAC directly. Its integrity is
enforced indirectly: a wrong length causes the decoder to read the wrong
number of bytes, which makes the Poly1305 tag fail.

### Key Commitment (v5)

**Version:** Introduced in file format v5.

#### The Problem

XChaCha20-Poly1305 does not provide **key commitment** (also called "robust
encryption"). In a contrived scenario, a computationally powerful attacker
could craft a ciphertext that decrypts without error under two different keys,
producing two different plaintexts. This matters when:

- **Auditability disputes.** Alice claims the archive contains contract A,
  Bob claims it contains contract B. Both can decrypt it "successfully" with
  their own keys. There is no cryptographic way to determine which key was
  original.
- **Abuse reporting.** A platform scans for abusive content by decrypting with
  a key the uploader provides. The uploader could construct a file that
  decrypts to harmless content under the reporting key but abusive content
  under their own key.

Key commitment is not provided by any widely deployed AEAD (AES-GCM,
ChaCha20-Poly1305, AES-GCM-SIV all lack it). It is an active area of
cryptographic research with no IETF-standardized solution as of 2026.

#### The Construction

v5 adds a 32-byte key-commitment tag to the trailer, computed as:

```
keyCommitTag = HMAC-SHA256(
    key     = encKey,
    message = "cipherforge-commitment-v1" || fileSalt
)
```

The tag is appended after the existing trailer HMAC, producing a 72-byte v5
trailer (up from 40 bytes in v4):

```
v5 Trailer (72 bytes):
  [segmentCount: 8] [trailerHMAC: 32] [keyCommitTag: 32]
```

#### Security Analysis

For an attacker to craft a file that decrypts under two different passwords:

1. The per-segment Poly1305 tags must verify under both `encKey₁` and `encKey₂`.
2. The trailer HMAC must verify under both `macKey₁` and `macKey₂`.
3. The key-commitment tag must verify: `HMAC(encKey₁, ctx || salt) == HMAC(encKey₂, ctx || salt)`.

Condition 3 requires a collision in HMAC-SHA256 with different keys on the
same message — a 2¹²⁸ work factor. The full 32-byte HMAC output is used
(no truncation) to maintain 128-bit post-quantum collision resistance under
Grover's algorithm.

The key-commitment tag is verified in constant time via `hmac.Equal`,
immediately after the trailer HMAC check and before any plaintext is written
to disk.

#### Why Not Hash the Ciphertext

Hashing the entire ciphertext would require a second pass over the file
during encryption and decryption, which is impractical for large files. The
key-commitment tag based on `encKey` and `fileSalt` is sufficient because:

- `encKey` and `macKey` are derived together via HKDF from the same
  `masterKey`. Finding two passwords that produce the same `encKey` is
  equivalent to a collision in the HKDF expansion.
- The trailer HMAC already commits to `salt`, `segmentSeed`, `argon2Params`,
  and `segmentCount`. Tampering with any of these invalidates the HMAC before
  the key-commitment tag is even checked.

#### Verification Order (v5)

```
1. Read and validate magic.
2. Read version (must be 5).
3. Read header fields → derive encKey, macKey.
4. Seek to trailer. Read segmentCount, storedHMAC, storedKeyCommit.
5. Compute expectedHMAC; compare constant-time. Fail → "authentication failed".
6. Compute expectedKeyCommit; compare constant-time. Fail → "key commitment verification failed".
7. Only if all checks pass: decrypt segments.
```

v5 is the only supported format version. v4 files must be re-encrypted with
a v5 encoder (Cipherforge 5.0.0 or later) before they can be decrypted.

---

## Password Generation

When the user doesn't supply a password, Cipherforge generates one
automatically using `crypto/rand` (the operating system's CSPRNG):

```
/crypto/rand → 44 characters from a 57-character pool → ~257 bits entropy
```

### Character Pool

The pool of 57 characters is designed to be unambiguous:

```
123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

Characters removed for ambiguity:

| Removed | Confusable With |
|---|---|
| `0` (zero) | `O` (capital O) |
| `I` (capital i) | `l` (lowercase L), `1` (one) |
| `L` (capital L) | `l` (lowercase L), `1` (one) |
| `O` (capital O) | `0` (zero) |
| `l` (lowercase L) | `I`, `L`, `1` |

The user may need to type this password from a printout or screenshot.
Ambiguous characters cause frustration and support requests.

### Entropy Calculation

With 57 characters and 44 positions:

$$\log_2(57^{44}) = 44 \cdot \log_2(57) \approx 44 \cdot 5.83289 \approx 256.65 \text{ bits}$$

This exceeds the 256-bit security level of the XChaCha20 key, meaning the
password itself is not the weakest link — the encryption algorithm is.

### Rejection Sampling

The password generator uses rejection sampling via `crypto/rand.Int` to avoid
**modulo bias**:

```go
limit := big.NewInt(int64(len(pool)))  // 57
for i := 0; i < length; i++ {
    n, _ := rand.Int(rand.Reader, limit)
    password = append(password, pool[n.Int64()])
}
```

Modulo bias would occur with a naive `rand() % 57` approach: since the
underlying random source produces values in [0, 2ⁿ), not all remainders mod
57 are equally likely. With 57 being small relative to typical CSPRNG output
sizes, this bias would be tiny, but `crypto/rand.Int` eliminates it entirely
at negligible cost.

---

## Memory Safety

Cipherforge makes a best-effort attempt to protect key material in memory, but
there are inherent limitations due to Go's runtime.

### Protections

1. **Byte slices, never strings.** All keys and passwords are stored in
   `[]byte`. Go strings are immutable and interned — once a string is created,
   its contents cannot be overwritten. Byte slices can be zeroed.

2. **Explicit zeroing.** Every key and password is zeroed immediately after its
   last use:

   ```go
   func ZeroBytes(b []byte) {
       for i := range b { b[i] = 0 }
       runtime.KeepAlive(b)
   }
   ```

   `runtime.KeepAlive(b)` is a compiler directive that prevents the Go
   compiler from treating the zeroing loop as a dead store and optimizing it
   away. Without it, the compiler might observe that `b` is never read after
   the loop and eliminate the zeroing entirely.

3. **Memory locking.** Keys are locked against swapping via:
   - Unix: `mlock` (via `golang.org/x/sys/unix`)
   - Windows: `VirtualLock` (via `golang.org/x/sys/windows`)

   This prevents the OS from writing key material to the swap file or page
   file, where it could persist after the process exits.

### Known Limitations

**Go garbage collector copying.** Go's garbage collector may relocate
heap-allocated objects during compaction. When a byte slice backing array is
copied, the old copy remains in freed memory but is no longer reachable by
the application. `ZeroBytes` can only zero the current backing array; it
cannot zero residual copies left by GC compaction.

This is a Go-language limitation, not a Cipherforge-specific issue.
Mitigations that would require C or Rust (pinned allocations, page-protected
memory) were rejected to keep the tool in pure Go — a deliberate tradeoff
favoring build simplicity and portability over stronger memory-residency
guarantees.

For most threat models (protecting files at rest), the relevant attack
requires physical memory access (DMA, cold boot, or kernel compromise), at
which point the attacker likely has more direct paths to the plaintext.

---

## Post-Quantum Considerations

### Current State

All cryptographic primitives in Cipherforge rely on symmetric-key constructions,
which are generally considered **post-quantum safe** with doubled key sizes:

| Algorithm | Classical Security | Post-Quantum Security (Grover) | Assessment |
|---|---|---|---|
| XChaCha20 (256-bit key) | 256 bits | 128 bits | Acceptable for long-term archival |
| Poly1305 (128-bit tag) | 128 bits | 128 bits (forgery not accelerated by Grover) | Acceptable |
| HMAC-SHA256 (256-bit key) | 256 bits | 128 bits | Acceptable |
| SHA-256 (256-bit output) | 256 bits (preimage) | 128 bits (Grover) | Acceptable |
| Argon2id (256-bit output) | 256 bits | 128 bits | Acceptable |

Grover's algorithm provides a quadratic speedup for brute-force search.
Against a 256-bit key, this reduces effective security to 128 bits — which is
still considered computationally infeasible for the foreseeable future.

### What Is NOT Post-Quantum Safe

Cipherforge does not use any asymmetric cryptography (no key exchange, no
digital signatures, no public-key encryption), which is where quantum
computers pose the greatest threat (Shor's algorithm breaks RSA, DSA, and
ECDSA in polynomial time). There are no post-quantum vulnerabilities in the
cryptographic design.

### Key Commitment

As of v5, Cipherforge provides key commitment via a 32-byte HMAC-SHA256
commitment tag in the trailer. See [Key Commitment (v5)](#key-commitment-v5)
for the full design and security analysis.

---

## What Is and Is Not Protected

### Protected

- **Confidentiality** of plaintext against an attacker who can read the `.cfo`
  file but does not know the password.
- **Integrity** of every byte in the file: header, payload, and trailer are
  all authenticated. Any tampering is detected.
- **Segment ordering.** Segments cannot be reordered, deleted, or duplicated
  without detection.
- **File truncation.** The trailer HMAC commits to the segment count.
- **Header substitution.** The trailer HMAC covers all header fields.
- **KDF parameter downgrade.** The trailer HMAC covers Argon2 parameters.
- **Early rejection.** Wrong passwords and corrupt files are detected before
  any plaintext is written to disk.
- **File type detection.** The magic signature prevents expensive KDF work
  on files that are not `.cfo` files.

### Not Protected

- **Existence of the encrypted file.** The `.cfo` extension and file size are
  visible to anyone with filesystem access. Cipherforge is not a deniable
  encryption tool.
- **Original filename.** Encrypted output is named `<original>.cfo`.
- **Approximate plaintext size.** Each 1 MiB segment adds 24 bytes of overhead
  (8 length prefix + 16 Poly1305 tag). Plaintext size is predictable to within
  one segment (~1 MiB). There is no padding to hide file size.
- **Access patterns.** The format provides no guarantees about when or how
  often a file is decrypted. This is orthogonal to file encryption.
- **Key commitment.** Provided via a 32-byte HMAC-SHA256 commitment tag
  in the trailer. See [Key Commitment (v5)](#key-commitment-v5).
- **Forward secrecy.** This is file encryption. There is no ephemeral key
  exchange. Compromise of the password compromises all files encrypted with it,
  past and future.
- **Side-channel resistance beyond algorithm constant-time properties.**
  Cipherforge uses constant-time AEAD and HMAC comparison, but makes no
  guarantees about power analysis, electromagnetic emanations, or cache-timing
  attacks beyond the inherent properties of the underlying Go crypto libraries.

---

## References

### Standards and RFCs

| Reference | Title |
|---|---|
| [RFC 8439] | ChaCha20 and Poly1305 for IETF Protocols |
| [RFC 9106] | Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications |
| [RFC 5869] | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| [RFC 2104] | HMAC: Keyed-Hashing for Message Authentication |
| [RFC 8018] | PKCS #5: Password-Based Cryptography Specification (PBKDF2) |
| [RFC 7914] | The scrypt Password-Based Key Derivation Function |
| [FIPS 180-4] | Secure Hash Standard (SHA-2) |
| [FIPS 198-1] | The Keyed-Hash Message Authentication Code (HMAC) |
| [NIST SP 800-132] | Recommendation for Password-Based Key Derivation |
| [draft-irtf-cfrg-xchacha] | XChaCha20: eXtended-nonce ChaCha20 |

### Further Reading

| Resource | Description |
|---|---|
| [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | Current best practices for KDF parameters |
| [Password Hashing Competition](https://www.password-hashing.net/) | Argon2's selection as the PHC winner (2015) |
| [Latacora Cryptographic Right Answers](https://latacora.micro.blog/2018/04/03/cryptographic-right-answers.html) | Practical guidance on algorithm selection |
| [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography) | NIST standardization of post-quantum algorithms |
| [A Graduate Course in Applied Cryptography](https://cryptobook.net/) | Dan Boneh & Victor Shoup (free online textbook) |

### Project Documents

- [FILEFORMAT.MD](FILEFORMAT.MD) — Authoritative `.cfo` binary format specification
- [ARCHITECTURE.MD](ARCHITECTURE.MD) — Codebase architecture and data flow
- [README.MD](README.MD) — User-facing documentation

---

[RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
[RFC 9106]: https://datatracker.ietf.org/doc/html/rfc9106
[RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869
[RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
[RFC 8018]: https://datatracker.ietf.org/doc/html/rfc8018
[RFC 7914]: https://datatracker.ietf.org/doc/html/rfc7914
[FIPS 180-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[FIPS 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
[NIST SP 800-132]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
[draft-irtf-cfrg-xchacha]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha
