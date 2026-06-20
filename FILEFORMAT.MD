# Cipherforge File Format and Cryptographic Design Reference

## Purpose of This Document

This document is the authoritative specification for the Cipherforge `.cfo`
binary file format. It is written for three audiences: a security reviewer
who wants to evaluate whether the cryptographic design is sound; a developer
who wants to write a compatible decoder without reference to the Go source;
and a future maintainer who needs to understand why the format is the way it
is before changing anything.

For each field in the format, this document explains what the field contains,
what security property it provides or relies on (confidentiality, integrity,
or authenticity), what an attacker could accomplish if the field were absent
or modified, and why alternative designs were rejected. Understanding *why*
the format exists is as important as knowing *what* it contains.

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
║    HEADER (64 B in v2)       ║  Fixed size. Written first.
║    HEADER (52 B in v1)       ║  Legacy v1 header (no KDF params).
╠══════════════════════════════╣
║       PAYLOAD (variable)     ║  One or more encrypted segments.
╠══════════════════════════════╣
║         TRAILER (40 B)       ║  Fixed size. Written last.
╚══════════════════════════════╝
```

Format version 1 (v1) uses a 52-byte header and stores no Argon2id
parameters — decoders must use production defaults (time=4, memory=1 GiB,
threads=4).  Format version 2 (v2) extends the header to 64 bytes with 12
bytes of explicit KDF parameters immediately after the Segment Seed.  This
document describes v2; the v1 layout is identical except the 12 Argon2
parameter bytes are absent and everything after the Segment Seed shifts up by
12 bytes (payload starts at offset 52 instead of 64).

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

The minimum valid file size is 92 bytes for v1 and 104 bytes for v2:
header plus trailer with no payload segments (the result of encrypting an
empty file).

---

## Byte-Level Layout

All multi-byte integer fields use **big-endian** byte order throughout.

```
Byte offset   Length    Field
───────────   ──────    ─────────────────────────────────────────
0             8         Magic signature
8             4         Format version (uint32)
12            16        Argon2id salt
28            24        Segment Seed (HKDF IKM)
52            12        Argon2id parameters (v2+; absent in v1)
64            …         Payload (variable; see below)
EOF−40        8         Segment count (uint64)
EOF−32        32        Trailer HMAC-SHA256
```

Within the payload, each segment has this structure:

```
Byte offset   Length           Field
───────────   ──────           ─────────────────────────────────
+0            8                Segment ciphertext length (uint64)
+8            segmentLen       Ciphertext || Poly1305 tag (16 B of tag)
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
decoder rejects the file before doing anything else. This is not a meaningful
attack; a denial of service against a file the attacker can already modify is
not a useful capability.

**Why it exists:** Argon2id with production parameters (1 GiB, 4 passes)
takes several seconds. Checking 8 bytes before attempting key derivation
costs nothing and allows the decoder to immediately reject files that are not
`.cfo` files — including truncated files, files of the wrong type passed by
mistake, and simple corruption.

**What happens without it:** The decoder would attempt key derivation on
every file, including non-`.cfo` files. A malicious actor could flood the
decoder with dummy files and cause it to spend arbitrary amounts of time and
memory.

**Note on HMAC coverage:** The magic and version fields are not included in
the trailer HMAC. They affect parsing only, not decryption. If either is
tampered with, the file is rejected at the parsing stage with a clear error.
Including them in the HMAC would add complexity without adding meaningful
security.

---

### Version (bytes 8–11)

**Value:** `00 00 00 01` — the uint32 value 1, encoded big-endian. Currently
always 1.

**Confidentiality required:** No.

**Integrity required:** Yes, trivially. Flipping this to an unsupported value
causes rejection; flipping it to a future supported value on a v1 file would
cause the decoder to attempt decryption with the wrong layout — which would
fail at the trailer HMAC step because the HMAC would not match.

**Why it exists:** Enables forward-compatible format detection. If a future
release changes the binary layout — different field sizes, additional header
fields, a different segment framing — it increments this field. A v1 decoder
encountering a v2 file rejects it with a clear error ("unsupported format
version 2, expected 1") rather than attempting decryption with the wrong
assumptions and producing a confusing authentication failure.

**Why 4 bytes:** A 1-byte version field would be sufficient for any
foreseeable number of versions, but a 4-byte uint32 aligns the subsequent
salt field to a 4-byte boundary and matches the natural encoding width. The
cost is 3 bytes.

---

### Salt (bytes 12–27)

**Value:** 16 bytes (128 bits) of uniformly random data produced by
`crypto/rand` for each file independently.

**Confidentiality required:** No. The salt is stored in plaintext and its
value can be read by anyone who opens the file. This is not a vulnerability.

**Integrity required:** Yes. The salt is included in the trailer HMAC. If an
attacker modifies the salt, the HMAC verification fails before any decryption
occurs.

**What the salt does:** The salt is the second input to Argon2id (after the
password). Argon2id is a deterministic function — the same password and salt
always produce the same key. Without a per-file random salt, two files
encrypted with the same password would have the same encryption key. An
attacker who compromised the ciphertext of any one of those files, and who
then observed that another file produced identical-looking output under the
same key, would gain information. With a fresh random salt, each file's key
is independent even if the password is the same.

**What the salt does not do:** It does not make the password harder to guess.
An attacker who wants to brute-force the password still has to pay the full
Argon2id cost for every guess, salt or not. What the salt does is ensure that
precomputation attacks — computing Argon2id outputs for a dictionary of
passwords ahead of time and looking up the result — are useless because the
precomputed table would need a separate entry for every salt value. With a
128-bit salt, precomputation is completely infeasible.

**Why 16 bytes:** 128 bits is the recommendation in RFC 9106 (the Argon2
specification). It is large enough that the probability of two files sharing
a salt (even across millions of files encrypted with the same password) is
negligible for any realistic use case.

**Relationship to the HMAC:** The salt is one of four values included in the
trailer HMAC input:

```
HMAC-SHA256(macKey, "cipherforge-trailer-hmac-v1" || salt || segmentSeed 
|| segmentCount)
```

This means the HMAC binds the salt to the payload. An attacker who swaps the
salt from file A into file B (both encrypted with the same password) would
change the derived keys, causing per-segment AEAD authentication to fail — but
that would not be detected until the payload is read. Including the salt in the
HMAC catches this substitution attack immediately, before any payload bytes
are read.

---

### Segment Seed (bytes 28–51)

**Value:** 24 bytes (192 bits) of uniformly random data produced by
`crypto/rand` for each file independently.

**Confidentiality required:** No. The Segment Seed is stored in plaintext in
the header and can be read by anyone who opens the file. This is intentional
and not a vulnerability.

**Integrity required:** Yes. The Segment Seed is included in the trailer
HMAC. If an attacker modifies the Segment Seed, the HMAC verification fails
before any decryption occurs.

**What the Segment Seed does:** It is the HKDF Input Keying Material (IKM)
from which all per-segment nonces are derived. Storing one 24-byte value in
the header allows the decoder to reconstruct any segment's nonce on demand
using only the Seed and the segment's index, without storing nonces in the
file.

**Why confidentiality is not required:** The Segment Seed is the IKM for
HKDF, which produces nonces. Nonces, in standard AEAD use, are not secret —
they are routinely transmitted alongside ciphertext. What makes ciphertext
confidential is the encryption key, not the nonce. An attacker who reads the
Segment Seed from the header and successfully computes every per-segment
nonce still cannot decrypt a single byte without the encryption key. The
encryption key is never stored anywhere; it exists only ephemerally in memory
during an active session, derived from the password via Argon2id.

**What does matter:** The Seed must not be silently substituted. If an
attacker replaced the Segment Seed with the Seed from a different file, the
nonces derived during decryption would not match those used during encryption,
and every AEAD tag in the payload would fail. The trailer HMAC catches this
before any decryption is attempted.

**Why HKDF rather than XOR or a counter:**

XOR-based derivation (nonce_i = seed XOR i) has two structural weaknesses.
First, when i = 0, XOR is a no-op, so the Seed itself is used directly as a
nonce. This is the "identity at zero" property: the nonce for segment 0
leaks the raw Seed. Second, the derivation is linear: given any two pairs
(i, nonce_i) and (j, nonce_j), the Seed can be recovered trivially from
`nonce_i XOR i`. XOR over a counter provides no one-way guarantee.

HKDF-SHA256 is a one-way pseudorandom function. Given any set of (counter,
derived_nonce) pairs, the Seed cannot be recovered. There is no identity at
zero — HKDF(seed, info="...||0") produces a value unrelated to the Seed.
HKDF is specified in RFC 5869 and recommended by NIST SP 800-56C for exactly
this use case.

**The HKDF construction in full:**

```
nonce_i = HKDF-SHA256(
    ikm  = segmentSeed,
    salt = nil,
    info = "cipherforge-segment-nonce-v1" || uint64_big_endian(i)
)[0:24]
```

The `nil` HKDF salt is safe because the IKM is already uniformly random. RFC
5869 specifies that a nil salt is treated as a zero string of HashLen (32)
bytes, which is the correct behaviour when the IKM has sufficient entropy and
no additional salt is needed for uniqueness.

The `info` field is the concatenation of the fixed ASCII string
`"cipherforge-segment-nonce-v1"` and the 8-byte big-endian encoding of the
segment index. The fixed-length context string prefix provides domain
separation: if the same Seed were ever used as IKM in a different context —
a future v2 format, or an unrelated application — the context string ensures
the derived nonces are completely different. Appending the counter after a
fixed-length prefix avoids boundary ambiguity (there is no risk that
`"...v1" || "\x00\x01"` could be confused with `"...v10" || "\x01"`).

**Why 24 bytes:** XChaCha20-Poly1305 requires a 24-byte nonce. Using 24 bytes
for the Seed means one constant (`XNonceSize`) serves both roles. The Seed
could in principle be any length that HKDF accepts as IKM; 24 bytes was
chosen for simplicity.

---

## Argon2id Parameters (v2+; bytes 52–63)

**Value:** 12 bytes encoding three KDF parameters:

| Offset | Length | Field | Encoding |
|--------|--------|-------|----------|
| 52     | 4      | Time  | uint32 big-endian — number of passes |
| 56     | 4      | Memory | uint32 big-endian — KiB of RAM |
| 60     | 1      | Threads | uint8 — degree of parallelism |
| 61     | 3      | Reserved | Must be zero |

**Confidentiality required:** No.

**Integrity required:** Yes. The parameters are included in the trailer HMAC.
An attacker who downgrades them (e.g., swapping `time=4` → `time=1`) makes
brute-force attacks dramatically cheaper. The HMAC catches this before key
derivation.

**Why store parameters in the file:** Without embedded parameters, changing
the KDF defaults — even for good reasons, such as responding to new hardware
or updated OWASP recommendations — would break decryption of every existing
archive. Embedding the parameters makes each file self-describing: the
decoder reads them from the header and uses them regardless of what a future
binary considers the default. A v2 decoder can decrypt a file encrypted with
`time=8` five years from now without any configuration or heuristics.

**Why KiB for memory:** Storing bytes directly would require uint64 and push
the parameter block past 12 bytes. KiB in uint32 handles up to 4 TiB, which
covers any realistic Argon2id configuration for the foreseeable future.

**V1 fallback:** v1 files carry no parameters. A v2 decoder encountering a
v1 file uses the original production defaults (time=4, memory=1,048,576 KiB,
threads=4). This ensures backward compatibility without special-casing the
decryption logic.

**Decoder safety limits:** To prevent resource-exhaustion attacks from crafted
files, the decoder rejects parameters that exceed implementation-defined
ceilings: `time > 100` or `memory > 16,777,216 KiB` (16 GiB). These limits
are intentionally generous — no realistic Argon2id configuration approaches
them — but they prevent a malicious file from forcing multi-terabyte memory
allocation or unbounded CPU consumption during key derivation. The HMAC
cannot protect against this because key derivation must complete before the
HMAC can be verified.

**Relationship to the HMAC:** In v2, the parameters are included in the
trailer HMAC after the Segment Seed and before the segment count:

```
HMAC-SHA256(macKey, "cipherforge-trailer-hmac-v2" || salt || segmentSeed
          || uint32_be(time) || uint32_be(memory) || uint8(threads)
          || zero[3] || uint64_be(segmentCount))
```

The v2 context string (`cipherforge-trailer-hmac-v2`) provides domain
separation from v1, ensuring a v2 HMAC can never validate against a v1
decoder.

---

## Payload

The payload is a sequence of encrypted segments, written contiguously without
separators. The number of segments is not stored in the payload itself; it is
in the trailer, which is read before the payload.

### Segment Length Field (8 bytes per segment)

**Value:** uint64, big-endian. The byte count of the following ciphertext,
including the 16-byte Poly1305 authentication tag that the AEAD appends.

**Confidentiality required:** No.

**Integrity required:** Yes, indirectly. The length field is not covered by
any MAC directly. Its integrity is enforced by the AEAD: if the length field
is modified, the decoder reads the wrong number of bytes, feeds them to
`aead.Open`, and the authentication tag fails.

**Why it exists:** Without a length prefix, the decoder would have no way to
know where one segment ends and the next begins, since segments are written
contiguously. The alternative — a fixed ciphertext size per segment — would
complicate handling of the final segment, which is almost always shorter than
1 MiB.

**Bounds validation:** The decoder validates the length field against two
bounds before using it:

1. **Upper bound:** `segmentLen <= SegmentSize + aead.Overhead()`. A
   well-formed segment can produce at most `SegmentSize` bytes of ciphertext
   plus 16 bytes of tag. A length exceeding this is impossible for a valid
   file and signals corruption or a memory-exhaustion attack (an attacker
   trying to make the decoder allocate a huge buffer). This check happens
   before any allocation.

2. **Lower bound:** `segmentLen >= aead.Overhead()` (16 bytes). The
   plaintext length is computed as `segmentLen - 16`. If `segmentLen` were
   less than 16, this subtraction would wrap around to a huge uint64 value
   in unsigned arithmetic, because Go does not panic on unsigned underflow.
   The subsequent AEAD call would fail regardless, but the wrapped value
   would have passed through `buildAAD` with a nonsensical plaintext length
   first. This guard makes the failure immediate and explicit.

**Why 8 bytes for a value that can never exceed ~1 MiB:** Simplicity and
alignment. A 4-byte field would be sufficient for the current segment size,
but uint64 matches the segment count field in the trailer, avoids a different
read helper, and leaves room for a hypothetical future format with larger
segments.

---

### Ciphertext and Poly1305 Tag

**Algorithm:** XChaCha20-Poly1305 (RFC 8439 plus the XChaCha extension).

**Why XChaCha20-Poly1305, not AES-GCM:**

AES-GCM is more widely deployed and is often the default choice. However, it
has one significant operational constraint for this format: its nonce is 96
bits. The birthday bound for a 96-bit nonce is reached at approximately
2^48 encryption operations, at which point there is a meaningful probability
of a nonce collision for a given key. For per-segment nonces derived from a
Segment Seed that is fresh per file, collisions across files with the same
password are avoided by the independent Seed. But for collisions within a
single file, 2^48 segments of 1 MiB each represents 2^68 bytes — far more
than any file. So AES-GCM would be safe here too.

XChaCha20-Poly1305 was chosen for a different reason: its 192-bit nonce
means the birthday bound is at 2^96 operations, which is simply never a
concern. This eliminates an entire category of analysis. Additionally,
ChaCha20 is designed to be fast and secure in constant-time software on all
platforms, without hardware acceleration. AES-GCM's performance degrades
significantly on hardware without AES-NI, and timing side-channels in
software AES implementations are a known concern. XChaCha20 has no such
dependency.

**Per-segment nonce:** Each segment uses a unique nonce derived from the
Segment Seed and the segment index via HKDF-SHA256, as described in the
Segment Seed section above. The nonce is not stored in the file.

**Per-segment AAD:** Each segment is encrypted with Additional Authenticated
Data (AAD) computed as:

```
AAD = uint64_big_endian(segmentIndex) || uint64_big_endian(plaintextLength)
```

The AAD is 16 bytes. It is never stored in the file. Both the encryptor and
the decryptor reconstruct it from the loop counter and the measured plaintext
length. The AEAD tag covers both the ciphertext and the AAD, so any
discrepancy between the AAD at encryption time and at decryption time causes
authentication to fail.

**What binding the segment index prevents:** Segment reordering. If an
attacker moves segment 5 to position 2, the decoder reconstructs the AAD
with index 2, but the tag was computed over AAD with index 5. The tags are
different, and decryption fails. This guarantee holds even if all segments
were encrypted with the same key and nonce — which they are not, but the AAD
binding provides a second independent layer of protection.

**What binding the plaintext length prevents:** Length manipulation. An
attacker cannot falsely claim that a 1 MiB segment contains only 500 KiB of
plaintext by modifying the length field — the tag was computed over the AAD
containing the true plaintext length, so any mismatch in the reconstructed
AAD causes authentication failure.

**What per-segment AEAD cannot prevent:** Per-segment AEAD covers attacks
within a segment and attacks on the ordering and completeness of the segment
sequence, but it cannot prevent three file-level attacks:

1. **File-level truncation:** Removing the last N complete segments leaves
   the remaining segments all authenticating correctly. Without an external
   count commitment, the decoder cannot distinguish a truncated file from a
   shorter one.

2. **Segment appending:** Adding segments from another file encrypted with
   the same key at the end of a file, then adjusting nothing else, may
   produce segments that authenticate correctly. The decoder cannot tell
   they do not belong.

3. **Header substitution:** Swapping the salt and Segment Seed from file A
   into file B, if both were encrypted with the same password, changes the
   derived keys, causing per-segment authentication to fail — but this is
   only detected during payload decryption, not before.

All three attacks are addressed by the trailer HMAC.

**The Poly1305 tag:** The 16-byte Poly1305 tag is appended by `aead.Seal`
and is included in the `segmentLen` count stored in the length field. It is
not stored separately. On decryption, `aead.Open` reads and verifies the
tag internally. The decoder never sees or handles the tag directly.

---

## Trailer

The trailer is the last 40 bytes of the file. It is written at the end of
encryption, after all segments, because the segment count is not known until
all plaintext has been processed. On decryption, it is read first.

### Segment Count (EOF−40 to EOF−33)

**Value:** uint64, big-endian. The total number of segment frames in the
payload.

**Confidentiality required:** No.

**Integrity required:** Yes. The segment count is an input to the trailer
HMAC. Any modification to it invalidates the HMAC, which is verified before
any decryption.

**Why it exists:** The decoder needs to know how many segments to read. The
alternatives are:

- Store the count in the header. Impossible — the count is not known until
  encryption is complete.
- Scan the payload for an end-of-segments sentinel. Requires either a
  two-pass read or a sentinel value that must be escaped in the data, adding
  complexity.
- Read segments until EOF. Without knowing the trailer boundary, the decoder
  would attempt to parse the 40-byte trailer as a segment, either failing
  with a length error or, worse, misidentifying the trailer bytes as ciphertext.
- Store the count at a fixed offset in the trailer. This is what the format
  does: write the count last, read it first, and use it to bound the payload
  loop.

**Attacks the count commits to:** An attacker who modifies the stored count
to a smaller value can make the decoder stop reading early, silently ignoring
trailing segments. An attacker who increases it can make the decoder read
into the trailer bytes as if they were a segment, producing either a length
error or authentication failure. Both are caught by the HMAC: the stored
count is part of the HMAC input, so any modification to it produces a
different expected HMAC, which does not match the stored HMAC.

---

### Trailer HMAC (EOF−32 to EOF−1)

**Value:** 32 bytes. HMAC-SHA256 computed as:

v1 (format version 1):
```
HMAC-SHA256(
    key   = macKey,
    input = "cipherforge-trailer-hmac-v1"
          || salt                          (16 bytes)
          || segmentSeed                   (24 bytes)
          || uint64_big_endian(segmentCount) (8 bytes)
)
```

v2 (format version ≥ 2):
```
HMAC-SHA256(
    key   = macKey,
    input = "cipherforge-trailer-hmac-v2"
          || salt                          (16 bytes)
          || segmentSeed                   (24 bytes)
          || uint32_be(argon2Time)         (4 bytes)
          || uint32_be(argon2Memory)       (4 bytes, KiB)
          || uint8(argon2Threads)          (1 byte)
          || zero[3]                       (3 reserved bytes)
          || uint64_big_endian(segmentCount) (8 bytes)
)
```

**Confidentiality required:** No. The HMAC output is not secret; revealing it
to an attacker does not help them forge a valid HMAC without `macKey`.

**Integrity and Authenticity required:** Yes. The HMAC is verified using
`hmac.Equal`, which is a constant-time comparison. This prevents timing
side-channel attacks where an attacker probes the comparison one byte at a
time by observing response latency.

**What macKey is:** The MAC key is derived from a master key and the file's salt
via HKDF-SHA256. The master key is derived from the password via Argon2id.
The HKDF expansion produces 64 bytes of key material per file. Bytes 32–63
are the MAC key (`macKey`), and bytes 0–31 are the encryption key (`encKey`).
Using two non-overlapping halves of one HKDF invocation means the two keys are
fully independent, and the memory-hard Argon2id cost is paid only once per password
(producing the master key), rather than once per file.

`macKey` is never stored. It exists only in memory during an active session
and is zeroed (via a `runtime.KeepAlive`-guarded loop) immediately after the
HMAC is computed or verified.

**Why HMAC-SHA256 rather than a second AEAD tag:** An AEAD tag requires a
nonce. Introducing a nonce for the trailer MAC would require generating,
storing, and authenticating another nonce value — adding complexity and
another field. HMAC-SHA256 is a deterministic MAC: given the same key and
input, it always produces the same 32-byte output with no nonce required.
For authenticating a fixed set of committed values, a deterministic MAC is
strictly simpler and equally secure.

**Why the context string is first:** The literal ASCII string
`"cipherforge-trailer-hmac-v1"` is the first thing written to the HMAC
input. This provides domain separation. If a future version of the format
added a new field to the HMAC input, the v1 and v2 context strings would be
different, making it impossible for a valid v2 MAC to satisfy the v1
verification check. Without a context string, the inputs to v1 and a
hypothetical v2 would be in the same namespace, and a carefully crafted v2
file could in principle produce an input that collides with a valid v1 HMAC
input. The context string makes this impossible by design.

**What the HMAC covers and why each element is included:**

| Element | Why included |
|---|---|
| Context string | Domain separation across versions |
| `salt` | Detects salt substitution from another file |
| `segmentSeed` | Detects Segment Seed substitution from another file |
| `argon2Time`, `argon2Memory`, `argon2Threads` (v2) | Detects KDF parameter downgrade attacks |
| `segmentCount` | Detects file truncation and segment appending |

The magic and version bytes are not included. If either is tampered with,
the decoder rejects the file at the parsing stage before the HMAC is even
computed. Including them would add 12 bytes of input to every HMAC
computation without adding any security.

The payload ciphertext is not included. Per-segment AEAD already
authenticates every byte of ciphertext with strong per-segment guarantees.
Including the full payload in the HMAC would require a full streaming read
before verification — eliminating the "verify before decrypting" property
that is central to the design.

**Verification order:** On decryption, the decoder proceeds as follows:

1. Read and validate magic (8 bytes).
2. Read and validate version (4 bytes).
3. Read salt (16 bytes).
4. Read Segment Seed (24 bytes).
5. If version ≥ 2: read Argon2id parameters (12 bytes). If version = 1: use
   production defaults (time=4, memory=1,048,576 KiB, threads=4).
6. Derive `masterKey` from password + fixed salt + parameters via Argon2id.
   Derive `encKey` and `macKey` from `masterKey` + file salt via HKDF-SHA256.
7. Seek to `EOF − 40`. Read segment count and stored HMAC.
8. Compute expected HMAC (using the version-appropriate construction).
   Compare with `hmac.Equal`.
9. If HMAC fails: return error immediately, delete output file (empty at this
   point), done.
10. Seek to payload start (byte 52 for v1, byte 64 for v2). Decrypt segments.

Step 8 catches wrong passwords, corrupt files, truncated files, appended
files, and header substitution — all before a single byte of plaintext is
written to disk. Steps 1–5 happen before step 6 (key derivation) because
magic and version validation are cheap; there is no point spending several
seconds on Argon2id if the file is obviously not a `.cfo` file.

---

## Key Derivation

### From Password to Keys

The user's password is never stored. On both encryption and decryption, it is
fed into Argon2id along with the salt and parameters from the file header
(or production defaults for v1 files):

masterKey = Argon2id(
    password = <user-supplied password>,
    salt     = "cipherforge-master-key-v1",
    time     = <argon2Time from header, or 4 for v1>,
    memory   = <argon2Memory from header, or 1,048,576 for v1>,
    threads  = <argon2Threads from header, or 4 for v1>,
    keyLen   = 32
)

raw = HKDF-SHA256(
    ikm   = masterKey,
    salt  = <16-byte file salt from header>,
    info  = "cipherforge-file-key-v1",
    outLen = 64
)

encKey = raw[0:32]    — XChaCha20-Poly1305 encryption key
macKey = raw[32:64]   — HMAC-SHA256 trailer key
```

**Why Argon2id:** Argon2id is the winner of the 2015 Password Hashing
Competition and is specified in RFC 9106. Its defining property is
memory-hardness: it requires a configurable amount of RAM in addition to
computation time. This directly limits the speed of brute-force attacks,
because each guess requires its own allocation of 1 GiB. A GPU cracking rig
that can parallelise SHA-256 across thousands of cores cannot parallelise
Argon2id to the same degree, because each attempt competes for memory
bandwidth. The memory requirement cannot be traded away for more computation
time — reducing memory below the configured amount produces wrong outputs.

**Why these parameters:** Time=4, memory=1 GiB, threads=4. These are well
above current OWASP minimum recommendations (64 MiB for interactive logins)
and reflect a use case where the legitimate user pays the cost once per
decryption session, but an attacker must pay it for every password guess. At
1 GiB per attempt, a machine with 64 GiB of RAM can parallelise at most 64
simultaneous guesses — a far cry from the millions per second achievable
against unsalted or weakly-iterated hashes.

**Why derive keys via HKDF:** In v3, calling Argon2id once to derive a master
key and then using HKDF to derive file-specific keys is a batch optimization.
For multiple files, the expensive memory-hard Argon2id cost is paid once.
Deriving 64 bytes of key material from HKDF and splitting the output is an
established pattern for domain separation. There is no known relationship
between `raw[0:32]` and `raw[32:64]` from a single HKDF expansion, and they are
used for entirely different cryptographic operations.

### Key Lifetime and Zeroing

Both `encKey` and `macKey` are stored in byte slices (not Go strings) to
prevent interning on the Go heap. Both are zeroed immediately after use via:

```go
for i := range b { b[i] = 0 }
runtime.KeepAlive(b)
```

The `runtime.KeepAlive(b)` call prevents the Go compiler from treating the
zeroing loop as a dead store and eliminating it as an optimisation. Without
it, the compiler is permitted to prove that `b` is not read again and remove
the writes entirely. `KeepAlive` makes `b` observable after the loop,
forcing the writes to be retained.

Both keys are also passed to `mlock` immediately after derivation. `mlock`
requests that the OS not page these memory regions to disk. This is a
best-effort operation — it can fail on systems where the process lacks
sufficient privileges — but is attempted regardless, as it reduces the window
during which key material might appear in a swap file or hibernation image.

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
  `<original_name>.cfo`, so `document.pdf` becomes `document.pdf.cfo`. The
  original name and extension are visible. This should be considered when
  storing files in shared or cloud-hosted locations.
- **The approximate plaintext size.** Each segment contributes 16 bytes of
  AEAD overhead plus 8 bytes of length framing. The total ciphertext size
  differs from the plaintext size by a predictable function of the segment
  count. An observer can estimate the plaintext size to within one segment
  (1 MiB).
- **Access patterns or usage timing.** The format makes no guarantees about
  when or how often a file is decrypted.

---

## Reference: Decryption Algorithm

The following is a complete specification for a compatible decoder. All
standards referenced (Argon2id, HKDF-SHA256, HMAC-SHA256,
XChaCha20-Poly1305) are published IETF or NIST specifications implementable
from their respective RFCs without reference to the Cipherforge source code.

```
function DecryptCFO(file, password) -> plaintext | error:

  1. Read 8 bytes at offset 0.
     Assert bytes equal: C1 50 48 52 46 30 52 47
     On failure: return "not a valid .cfo file"

  2. Read 4 bytes at offset 8 as uint32 big-endian → version.
     Assert version == 1 or version == 2
     On failure: return "unsupported format version"

  3. Read 16 bytes at offset 12 → salt.

  4. Read 24 bytes at offset 28 → segmentSeed.

  5. If version >= 2:
       Read 4 bytes at offset 52 as uint32 big-endian → argon2Time
       Read 4 bytes at offset 56 as uint32 big-endian → argon2Memory  (KiB)
       Read 1 byte  at offset 60 as uint8             → argon2Threads
       Skip 3 bytes at offset 61 (reserved)
     Else (version == 1):
       Set argon2Time = 4, argon2Memory = 1048576, argon2Threads = 4

  6. Derive keys:
       masterKey = Argon2id(password, "cipherforge-master-key-v1",
                            time=argon2Time, memory=argon2Memory,
                            threads=argon2Threads, keyLen=32)
       raw = HKDF-SHA256(masterKey, salt, "cipherforge-file-key-v1")
       encKey = raw[0:32]
       macKey = raw[32:64]

  7. Read 8 bytes at file_size - 40 as uint64 big-endian → segmentCount.
     Read 32 bytes at file_size - 32 → storedHMAC.

  8. Compute:
       if version == 1:
         expectedHMAC = HMAC-SHA256(
             key   = macKey,
             input = "cipherforge-trailer-hmac-v1"
                  || salt
                  || segmentSeed
                  || uint64_big_endian(segmentCount)
         )
       else:
         expectedHMAC = HMAC-SHA256(
             key   = macKey,
             input = "cipherforge-trailer-hmac-v2"
                  || salt
                  || segmentSeed
                  || uint32_big_endian(argon2Time)
                  || uint32_big_endian(argon2Memory)
                  || uint8(argon2Threads) || zero[3]
                  || uint64_big_endian(segmentCount)
         )
     Assert hmac_equal(storedHMAC, expectedHMAC)  ← constant-time comparison
     On failure: return "authentication failed: wrong password or corrupt file"

  9. Seek to payload start (byte 52 for v1, byte 64 for v2).

  10. For i in 0 .. segmentCount - 1:

       a. Read 8 bytes as uint64 big-endian → segmentLen.

       b. Assert segmentLen >= 16          (underflow guard)
          Assert segmentLen <= 1048576+16  (OOM guard)
          On failure: return "corrupt segment"

       c. Read segmentLen bytes → ciphertext.

       d. Derive nonce:
            nonce = HKDF-SHA256(
                ikm  = segmentSeed,
                salt = nil,
                info = "cipherforge-segment-nonce-v1" || uint64_big_endian(i)
            )[0:24]

       e. Compute plaintextLen = segmentLen - 16.
          Assert plaintextLen <= 1048576
          On failure: return "corrupt segment"

       f. Construct AAD = uint64_big_endian(i) || uint64_big_endian(plaintextLen)

       g. plaintext_segment = XChaCha20Poly1305.Open(
              key        = encKey,
              nonce      = nonce,
              ciphertext = ciphertext,
              aad        = AAD
          )
          On failure: return "authentication failed: corrupt segment"

       h. Append plaintext_segment to output.

  11. Return output.
```

Byte order is big-endian throughout. The HKDF info field is the exact byte
concatenation of the ASCII string and the 8-byte counter with no separator.
The HMAC input is the exact byte concatenation of the context string, salt,
Segment Seed, Argon2 parameters (v2+), and 8-byte segment count with no
separators or length prefixes.
