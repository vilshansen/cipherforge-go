# Changelog

## v2.0.0 (2026-06-06)

### Changed

- **File format v2**: Argon2id parameters (time, memory, threads) are now stored
  in the file header (12 bytes). Each encrypted file is self-describing — future
  parameter changes won't break decryption of existing archives.
- v2 decoders read v1 files transparently, falling back to production defaults.
- KDF parameters are authenticated by the trailer HMAC (v2 context string),
  preventing downgrade attacks.
- Header size increased from 52 to 64 bytes. Minimum file size from 92 to 104 bytes.

### Removed

- Package-level Argon2id globals removed. `DeriveKeys` now accepts a `format.Argon2Params`
  struct, making it a pure function.

## v1.0.1 (2026-06-05)

### Added

- `-h` / `--help` flag for inline help
- `-v` / `--version` flag for version information
- `-o <file>` flag for custom output filenames (single file only)
- `--platforms` flag on build script for selective cross-compilation
- SHA256 checksums generated for all release binaries
- MIT LICENSE file

### Changed

- Password format: 44-character flat string from a 58-character mixed-case clean pool (~258 bits entropy), replacing the 65-character hyphenated format from a 32-character pool
- Build script unified into a single `build-all.sh` with platform selection (`build-linux.sh` removed)

### Fixed

- Decrypt progress bar now computes an accurate plaintext size estimate from the trailer segment count, reaching 100% instead of capping at ~79%
- Potential panic on empty `-p` command-line argument
- Dead error return removed from `computeTrailerHMAC`
- Stale build command in integration test fallback (`cipherforge.go` → `../cmd/cfo/`)
- `go.mod` indirect dependency markings corrected (`go mod tidy`)
- README typo and stale Go version requirement (1.21 → 1.25)
- README updated with `-o`, `-h`, `-v` usage documentation

## v1.0.0 (2026-06-05)

First stable release.
