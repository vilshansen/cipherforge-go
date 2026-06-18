# Changelog

## v3.0.0 (2026-06-18) — BREAKING CHANGE

### ⚠️ Breaking Changes

**v3 files are not compatible with v2 or earlier.** This is a mandatory upgrade for new files; use v2.1.0 to decrypt v1/v2 files.

### Changed

- **File format v3**: Optimized key derivation using master key + HKDF
  - Master key derived once from password using Argon2id
  - File-specific keys derived per-file using HKDF with file salt
  - No backward compatibility with v1/v2 files
  - v3 decoder rejects v1/v2 files with clear error message
- **Version field enforcement**: v3 requires Argon2id parameters in header (non-negotiable)
- **Trailer HMAC context**: New "cipherforge-trailer-hmac-v3" prevents downgrade attacks

### Why This Change

- **Performance**: Batch encryption of N files now requires 1 expensive Argon2id + N fast HKDFs instead of N expensive Argon2ids
  - Example: encrypting 10 files is ~10× faster for KDF (1 slow + 10 fast vs. 10 slow)
- **Security unchanged**: Password strength remains the only bottleneck; each file still gets unique key
- **Future-proof**: Separating master key derivation from file-specific key derivation enables future parallelization and key rotation strategies
- **Clean break**: Rather than support v2 forever, v3 is a deliberate, documented breaking change with clear upgrade path

### Migration

- **New files**: Use v3.0.0 (faster batch encryption, all new features)
- **Existing v1/v2 files**: Continue using v2.1.0 to decrypt; re-encrypt with v3.0.0 if desired
- **No in-place upgrade**: Files must be re-encrypted with v3.0.0 binary (v2.1.0 cannot read v3 files, v3.0.0 cannot read v1/v2 files)

## v2.1.0 (2026-06-07)

### Added

- `-q` / `--quiet` flag to suppress progress bar and summary output
- `-f` / `--force` flag to overwrite existing output files (safe by default)
- Encryption summary line showing input → output and file size
- File size displayed in progress bar prefix
- Short-password warning for `-p` passwords under 12 characters

### Changed

- `.cfo` files are now skipped when encrypting with wildcard patterns
- Password display unified with consistent box formatting
- Progress bar prefix widened from 40 to 50 characters

### Fixed

- Progress bar estimate now uses correct v2 header size (64 bytes)
- `macKey` zeroed immediately after last use instead of at function exit
- KDF parameter validation rejects `time=0`, `memory=0`, or `threads=0`
- Clean error message for files smaller than 40 bytes
- Glob errors properly propagated instead of silently ignored

## v2.0.1 (2026-06-06)

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
