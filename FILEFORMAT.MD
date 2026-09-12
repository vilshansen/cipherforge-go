# Cipherforge File Format

This is the authoritative specification for the current `.cfo` binary format,
version 6. The current release uses AES-256-GCM only; earlier formats are not
accepted.

## Structure

All integers are unsigned and big-endian. A file contains a fixed header, zero
or more encrypted segments, and a fixed trailer.

```
HEADER (47 bytes) | PAYLOAD (variable) | TRAILER (72 bytes)
```

An empty file is therefore 119 bytes before any armor encoding.

## Header

| Offset | Length | Field |
|---:|---:|---|
| 0 | 9 | Magic: `C1 50 48 52 46 30 52 47 45` |
| 9 | 4 | Version: uint32, value `6` |
| 13 | 1 | Suite: value `1` = AES-256-GCM |
| 14 | 1 | Flags: must be zero |
| 15 | 16 | File salt, random |
| 31 | 4 | Nonce prefix, random |
| 35 | 4 | Argon2id time |
| 39 | 4 | Argon2id memory in KiB |
| 43 | 1 | Argon2id threads |
| 44 | 3 | Reserved Argon2 bytes, must be zero |

The salt and nonce prefix are public but authenticated by the trailer HMAC.
Argon2id parameters are validated before key derivation to prevent resource
exhaustion from hostile files.

## Key Derivation

```
masterKey = Argon2id(password, "cipherforge-master-key-v1", parameters, 32)
raw       = HKDF-SHA256(masterKey, fileSalt,
                        "cipherforge-file-key-v1", 64)
encKey    = raw[0:32]
macKey    = raw[32:64]
```

The encryption key is used by AES-256-GCM. The MAC key is used only for the
trailer HMAC.

## Payload

Each plaintext segment contains at most 1 MiB and is encoded as:

```
uint64_be(ciphertextLength) || ciphertext || 16-byte GCM tag
```

The length includes the tag. Valid lengths are at least 16 and at most
1,048,592 bytes. Segment `i` uses:

```
nonce_i = noncePrefix || uint64_be(i)
AAD_i   = uint64_be(i) || uint64_be(plaintextLength)
```

The counter construction guarantees unique nonces within the file. A decoder
must never substitute random nonces or reset the counter.

## Trailer

The final 72 bytes are:

| Offset from EOF | Length | Field |
|---:|---:|---|
| -72 | 8 | Segment count |
| -64 | 32 | Trailer HMAC-SHA256 |
| -32 | 32 | Key-commitment HMAC-SHA256 |

The trailer HMAC is:

```
HMAC-SHA256(macKey,
  "cipherforge-trailer-hmac-v6-aes256-gcm" ||
  uint8(1) || uint8(0) || fileSalt || noncePrefix ||
  uint32_be(time) || uint32_be(memory) || uint8(threads) || zero[3] ||
  uint64_be(segmentCount))
```

The key commitment is:

```
HMAC-SHA256(encKey, "cipherforge-commitment-v1" || fileSalt)
```

The trailer is verified before payload processing. The payload reader is
limited to the bytes between the 47-byte header and the 72-byte trailer, so
extra bytes and inconsistent segment counts are rejected.

## Decryption Algorithm

1. Read and validate the magic and version.
2. Validate suite `1` and zero flags.
3. Read salt, nonce prefix, and Argon2id parameters.
4. Reject parameters outside the decoder's resource limits.
5. Derive `masterKey`, `encKey`, and `macKey`.
6. Read and verify the fixed trailer with constant-time comparisons.
7. Seek to byte 47 and read exactly the payload region.
8. For each segment index, validate the length, derive its prefix/counter
   nonce, reconstruct AAD, and call AES-GCM `Open`.
9. Reject any unread payload bytes after the declared segment count.

## Security Notes

The format authenticates metadata, segment ordering, segment lengths, payload,
file truncation, and segment appending. It does not conceal file existence,
output names, or approximate plaintext size. Nonce uniqueness is mandatory for
AES-GCM; the specified prefix/counter construction provides it within each
file key.
