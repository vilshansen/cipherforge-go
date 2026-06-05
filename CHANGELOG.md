# Changelog

## v1.0.0 (2026-06-05)

First stable release.

### Features

- Encrypt and decrypt files using XChaCha20-Poly1305 AEAD
- Argon2id key derivation with hardened parameters (1 GiB memory, 4 passes)
- Streaming 1 MiB segments for constant memory usage on files of any size
- Two-layer authentication: per-segment AEAD tags + file-level HMAC-SHA256 trailer
- Automatic password generation: 44-character mixed-case clean pool (~258 bits entropy)
- Explicit password support via `-p` flag for scripting or user preference
- Custom output filename via `-o` flag
- Memory locking (`mlock`) and explicit key zeroing for sensitive material
- Big-endian, fully-specified binary file format with magic header
- Cross-platform: Linux, macOS, Windows, FreeBSD

### Security Properties

- Confidentiality: XChaCha20 stream cipher (256-bit key)
- Integrity: Poly1305 per-segment authentication + HMAC-SHA256 file trailer
- Wrong password / corrupt file detected before any plaintext is written to disk
- Non-`.cfo` files rejected before expensive key derivation
- Constant-time HMAC comparison
- All symmetric primitives — post-quantum security at ~128 bits (Grover)
