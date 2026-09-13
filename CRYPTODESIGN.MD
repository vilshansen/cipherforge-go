# Cipherforge Cryptographic Design

This document describes the current Cipherforge file format. The current format
is v7 and uses AES-256-GCM with HKDF-SHA256. Older formats are not supported.

## Design Goals

Cipherforge is file encryption for long-term archives. The design requires:

1. High-entropy machine-generated encryption secrets with no password-based
   KDF.
2. Independent keys for encryption, file authentication, and key commitment.
3. Mechanically unique nonces for every encrypted segment.
4. Authentication of header metadata, segment ordering, lengths, and payload.
5. Verification of file-level authentication before CLI plaintext publication.
6. A bounded, deterministic binary format that can be implemented without the
   original program.

## Algorithm Catalogue

| Component | Algorithm | Size or parameters |
|---|---|---|
| Secret key derivation | HKDF-SHA256 | 64 bytes per file; 16-byte random salt |
| Key expansion | HKDF-SHA256 | 64 bytes per file |
| Encryption | AES-256-GCM | 32-byte key, 12-byte nonce, 16-byte tag |
| File authentication | HMAC-SHA256 | 32-byte tag |
| Key commitment | HMAC-SHA256 | 32-byte tag |
| Randomness | OS CSPRNG | `crypto/rand` |

AES-256-GCM is used through Go's standard library. The 32-byte encryption key
is derived from the generated secret; the secret is not used directly as an
AES key.

## Key Derivation

Cipherforge generates a high-entropy secret with the operating system CSPRNG.
Each file has an independent 16-byte random salt. File keys are derived with:

```
raw    = HKDF-SHA256(secret, fileSalt,
           "cipherforge-file-key-v2", 64)
encKey = raw[0:32]
macKey = raw[32:64]
```

The encryption key (encKey) and trailer-MAC key (macKey) are independent outputs
of HKDF. The key-commitment tag is computed with `encKey`, and is not reused as
an AEAD key.

HKDF-SHA256 is a key-expansion function, not a password-stretching function: it
does not slow down guessing, so it offers no brute-force resistance against a
low-entropy input. The construction above is sound only because the secret is
about 262 bits of CSPRNG output. If a user-chosen passphrase mode is ever added,
the passphrase must be routed through a memory-hard KDF (Argon2id) and must never
be passed to `DeriveKeys` directly.

## AES-GCM Nonces

Every file header contains a 4-byte random nonce prefix. Segment `i` uses the
12-byte nonce:

```
nonce_i = noncePrefix || uint64_big_endian(i)
```

The segment counter is unique within a file and the file encryption key is
unique because it is derived using the per-file salt. This avoids random
96-bit nonce collision risk and makes nonce uniqueness mechanically auditable.
The decoder rejects malformed segment lengths and bounds the segment counter by
the file's segment count.

Nonce reuse under AES-GCM is catastrophic. Implementations must never reset a
segment counter under the same file key, generate independent random nonces
instead of the specified construction, or reuse a nonce prefix with a new
file key without regenerating the complete file header.

## Segments and Associated Data

Plaintext is processed in segments of at most 1 MiB. Each segment is encoded:

```
uint64_be(ciphertextLength) || AES-256-GCM.Seal(plaintext, nonce_i, aad_i)
```

The associated data is:

```
aad_i = uint64_be(segmentIndex) || uint64_be(plaintextLength)
```

This binds the ciphertext to its position and length. Reordering, resizing, or
substituting a segment fails GCM authentication.

## Trailer Authentication and Key Commitment

Each file ends with a 72-byte trailer:

```
uint64_be(segmentCount) || trailerHMAC || keyCommitment
```

The trailer HMAC authenticates the suite, flags, file salt, nonce prefix,
and segment count. Its context is:

```
cipherforge-trailer-hmac-v7-aes256-gcm
```

The key commitment is:

```
HMAC-SHA256(encKey,
  "cipherforge-commitment-v2" || fileSalt)
```

The trailer closes gaps that per-segment AEAD cannot close by itself: file
truncation at a segment boundary, segment appending, and header substitution.
Both tags are compared with constant-time comparison.

The key commitment also permits bounded correction of a mistyped secret. Given
the public file salt and the commitment tag, Cipherforge can test supported
single-edit variants of a supplied secret without processing the ciphertext
payload. A candidate is accepted only when its derived `encKey` reproduces the
256-bit commitment.

## Verification Order

Decryption performs file-level authentication checks before processing payload
segments:

1. Validate magic, version, suite, and reserved flags.
2. Derive the file keys from the generated secret and file salt.
3. Seek to the fixed-size trailer.
4. Verify the trailer HMAC and key commitment.
5. Read exactly the payload region described by the trailer offset.
6. Authenticate and write each segment in order.

The generic library API writes each successfully authenticated segment to its
supplied `io.Writer`. The CLI stages decrypted plaintext in a temporary file and
publishes it only once the entire payload has authenticated — atomically renaming
it into place for a file target, or streaming it to stdout on success — so a
failed CLI decryption publishes no partial plaintext.

## Memory Handling

Derived keys are byte slices, locked when supported by the operating system,
and explicitly zeroed after use. Go's garbage collector can retain historical
copies of heap data; zeroing and memory locking are best-effort protections,
not a guarantee against every memory-residency attack.

Two secret copies sit outside that discipline by design. A secret rendered on
the terminal UI's results screen is held as a Go string, because the Bubble Tea
render path is string-only and strings are immutable, so the copy cannot be
zeroed; the underlying `[]byte` is wiped as soon as the string is made. A secret
copied to the system clipboard is outside this process entirely — it is not
locked, zeroed, or expired by Cipherforge, and other software on the machine may
read it.

## Security Properties and Limits

The format provides confidentiality and authenticated integrity for the
plaintext, metadata, segment ordering, and file boundaries when the generated
secret is secret and nonce construction is followed. It does not hide file existence,
output names, approximate plaintext size, or access timing. Security depends on
the generated secret remaining secret: it is high-entropy random material, and
there is no user-chosen password whose strength affects the brute-force
resistance of a file.

Cipherforge does not provide arbitrary secret recovery. The `RepairSecret`
facility searches only the bounded set of secrets differing from the supplied
value by one supported substitution, adjacent transposition, deletion, or
insertion. A completely lost secret cannot be recovered.

## Standards

- AES-GCM: NIST SP 800-38D
- HKDF: RFC 5869
- HMAC: RFC 2104 and FIPS 198-1
- SHA-256: FIPS 180-4
