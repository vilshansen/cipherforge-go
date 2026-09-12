# Cipherforge Cryptographic Design

This document describes the current Cipherforge file format. The current format
is v6 and uses AES-256-GCM. Older formats are not supported by this release.

## Design Goals

Cipherforge is file encryption for long-term archives. The design requires:

1. Memory-hard password protection with self-described parameters.
2. Independent keys for encryption, file authentication, and key commitment.
3. Mechanically unique nonces for every encrypted segment.
4. Authentication of header metadata, segment ordering, lengths, and payload.
5. Trailer verification before plaintext is written.
6. A bounded, deterministic binary format that can be implemented without the
   original program.

## Algorithm Catalogue

| Component | Algorithm | Size or parameters |
|---|---|---|
| Password KDF | Argon2id | 32-byte output; 5 passes, 256 MiB, 4 lanes |
| Key expansion | HKDF-SHA256 | 64 bytes per file |
| Encryption | AES-256-GCM | 32-byte key, 12-byte nonce, 16-byte tag |
| File authentication | HMAC-SHA256 | 32-byte tag |
| Key commitment | HMAC-SHA256 | 32-byte tag |
| Randomness | OS CSPRNG | `crypto/rand` |

AES-256-GCM is used through Go's standard library. The 32-byte encryption key
is derived from the password; it is never used directly as a password hash.

## Key Derivation

The password is processed once per operation:

```
masterKey = Argon2id(
    password,
    salt="cipherforge-master-key-v1",
    time=header.time,
    memory=header.memory,
    threads=header.threads,
    output=32
)
```

Each file has an independent 16-byte random salt. File keys are derived with:

```
raw    = HKDF-SHA256(masterKey, fileSalt,
                     "cipherforge-file-key-v1", 64)
encKey = raw[0:32]
macKey = raw[32:64]
```

The encryption and trailer keys are independent outputs of HKDF. The
key-commitment tag is computed with `encKey`, and is not reused as an AEAD key.

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
Argon2 parameters, and segment count. Its context is:

```
cipherforge-trailer-hmac-v6-aes256-gcm
```

The key commitment is:

```
HMAC-SHA256(encKey,
  "cipherforge-commitment-v1" || fileSalt)
```

The trailer closes gaps that per-segment AEAD cannot close by itself: file
truncation at a segment boundary, segment appending, and header substitution.
Both tags are compared with constant-time comparison.

## Verification Order

Decryption performs these checks before writing plaintext:

1. Validate magic, version, suite, and reserved flags.
2. Read and validate Argon2 parameters against resource limits.
3. Derive the master and file keys.
4. Seek to the fixed-size trailer.
5. Verify the trailer HMAC and key commitment.
6. Read exactly the payload region described by the trailer offset.
7. Authenticate and write each segment in order.

The generic library API writes to its supplied `io.Writer` as segments pass
authentication. The CLI writes to a sibling temporary file and atomically
renames it only after successful completion, so failed CLI decryptions do not
publish partial plaintext.

## Memory Handling

Derived keys are byte slices, locked when supported by the operating system,
and explicitly zeroed after use. Go's garbage collector can retain historical
copies of heap data; zeroing and memory locking are best-effort protections,
not a guarantee against every memory-residency attack.

## Security Properties and Limits

The format provides confidentiality and authenticated integrity for the
plaintext, metadata, segment ordering, and file boundaries when the password
is secret and nonce construction is followed. It does not hide file existence,
output names, approximate plaintext size, or access timing. Password strength
remains important despite Argon2id; the generated secrets are intended to be
high entropy.

## Standards

- AES-GCM: NIST SP 800-38D
- Argon2id: RFC 9106
- HKDF: RFC 5869
- HMAC: RFC 2104 and FIPS 198-1
- SHA-256: FIPS 180-4
