# Changelog

## v5.0.1 (2026-08-09)

### Fixed

- **Documentation corrected throughout.** Removed stale v4 references from
  FILEFORMAT.MD, CRYPTODESIGN.MD, ARCHITECTURE.MD, and README.MD. All
  documents now consistently describe the v5-only format: 72-byte trailer,
  137-byte minimum file size, `cipherforge-trailer-hmac-v5` HMAC context,
  and key commitment in the "Protected" list. The pseudocode decryption
  algorithm includes the key-commitment verification step.

## v5.0.0 (2026-08-09)

### Changed

- **v5 is now the only supported format.** v4 backward compatibility has
  been removed. The decoder strictly requires v5 files. v4 files must be
  re-encrypted with Cipherforge 4.2.0 before upgrading.

- **Simplified trailer handling.** The trailer is always 72 bytes: 8 bytes
  segment count + 32 bytes HMAC-SHA256 + 32 bytes key-commitment tag. The
  HMAC context string is always `cipherforge-trailer-hmac-v5`.

- **Key commitment is always verified.** The 32-byte key-commitment tag
  (`HMAC-SHA256(encKey, "cipherforge-commitment-v1" || fileSalt)`) is
  computed and verified in constant time on every decrypt. There is no
  code path that skips this check.

### Removed

- **v4 backward compatibility.** The decoder no longer accepts v4 files.
  The `V4TrailerSize` constant and the version-switching logic in `Decrypt`
  have been removed. The `computeTrailerHMAC` function no longer takes a
  version parameter.

- **`TestV4BackwardCompatibility`** test.

### Documentation

- Updated all documents (FILEFORMAT.MD, CRYPTODESIGN.MD, ARCHITECTURE.MD,
  README.MD) to reflect v5-only format. Pseudocode decryption algorithm
  updated to include the key-commitment verification step. Trailer size
  and minimum file size updated throughout.

## v4.2.0 (2026-08-09)

### Added

- **Key commitment (file format v5).** A 32-byte HMAC-SHA256 key-commitment
  tag is appended to the trailer, computed as
  `HMAC-SHA256(encKey, "cipherforge-commitment-v1" || fileSalt)`. This proves
  that a file was encrypted with a specific key, preventing an attacker from
  crafting a ciphertext that decrypts under two different passwords. The
  trailer HMAC context string is now version-specific
  (`cipherforge-trailer-hmac-v4` / `cipherforge-trailer-hmac-v5`) to prevent
  cross-version splicing attacks.

- **Backward compatibility.** v5 decoders accept both v4 (40-byte trailer,
  no key commitment) and v5 (72-byte trailer, with key commitment) files.
  Encryption always produces v5 output.

- **Cryptographic design documentation (`CRYPTODESIGN.MD`).** Comprehensive
  reference covering algorithm selection rationale, parameter choices,
  two-tier KDF architecture, nonce management, authentication design,
  memory safety, post-quantum considerations, and key commitment analysis.
  Includes links to all relevant RFCs and standards.

- **Documentation overview in README.** New documentation section with a
  summary of all project documents and suggested reading order.

### Changed

- **File format version bumped to v5.** The on-disk format is unchanged
  except for the 32-byte key-commitment tag appended to the trailer.
  Header layout (65 bytes) and payload format are identical to v4.

## v4.1.2 (2026-08-04)

### Added

- **Architecture documentation (`ARCHITECTURE.MD`).** Comprehensive reference
  covering directory layout, layered architecture, data flow diagrams,
  cryptographic design rationale, TUI screen flow, and dependency
  justification.

## v4.1.1 (2026-08-02)

### Added

- **TUI unit tests (`internal/tui/tui_test.go`).** Tests for `wrap64`,
  `buildResults`, and `deriveOutputPath`.
- **Base64 round-trip test in `pkg/cipherforge`.** Full encrypt → base64 →
  decode → decrypt cycle.

### Changed

- **Dropped ~70 lines of Java tutorial comments** from `internal/crypto/crypto.go`.
  Kept memory security caveat and `KeepAlive` explanation.
- **Corrected character count comment** from 58 to 57 in the character pool.

### Fixed

- **Base64 encrypt performance.** Added `bufio.Writer` with 1 MB buffer;
  throughput improved from ~1 MB/s to expected speed.
- **Decrypt failure now allows retry.** Wrong password redirects back to the
  password screen instead of exiting to the main menu.
- **Text output truncation on results screen.** Long encrypted/decrypted text
  now truncated at 100 characters with a copy hint.

## v4.1.0 (2026-08-01)

### Added

- **Full-screen terminal UI (TUI).** Running `cfo` without flags launches an
  interactive interface with keyboard-driven navigation. Built on Bubble Tea
  (pure Go, statically linked, no system dependencies).
  - Main menu with numbered shortcuts (1–5)
  - File picker with type-ahead search
  - Password entry with auto-generate checkbox and clear-text display
  - Live progress bar with bytes processed, speed, and elapsed time
  - Results screen with auto-generated password display and clipboard copy
  - Encrypt/decrypt text mode for copy/paste workflows with base64 output
  - Wrong password retry without restarting the workflow
- **Base64 transport wrapper (`-b` / `--base64`).** Encrypt output can be
  wrapped in RFC 4648 base64 for easy copy/paste. Decrypt accepts base64-
  encoded `.cfo` data.
- **Interactive mode flag (`-i` / `--interactive`).** Forces TUI launch even
  when CLI flags are present.
- **Clipboard copy shortcuts.** `c` copies auto-generated password, `Shift+c`
  copies encrypted/decrypted text output.

### Changed

- **Entry point restructured.** `main()` now routes to TUI (`runInteractive`)
  or CLI (`runCLI`) based on flags and terminal state. No flags + interactive
  terminal = TUI. Flags present = CLI.
- **`-e` / `-d` no longer required** when running interactively.
- **Build version bumped to 4.1.0.**

## v4.0.0 (2026-07-26) — BREAKING CHANGE

### ⚠️ Breaking Changes

**v4 files are not compatible with v3 or earlier.** This release removes all
backwards compatibility with legacy formats. Only v4 files are accepted for
decryption. The v4 trailer HMAC uses context string
`cipherforge-trailer-hmac-v4`. v3 and earlier files must be decrypted with
Cipherforge 3.3.2 and re-encrypted with v4.

### Removed

- **All v1/v2 backwards compatibility.** `DeriveKeys`, `DeriveKey`,
  `GenerateNonce` removed from `internal/crypto`. `PayloadOffset`,
  `V1HeaderSize`, v1/v2 HMAC context strings removed from `internal/format`.
  `trailerHMACContext` removed from `pkg/cipherforge`.
- **Version range checks in Decrypt.** Decrypt now accepts only exact
  version match (v4), not a range from v3 upward.

### Changed

- **File format version bumped to 4.** `FileVersion` = 4.
- **Magic signature corrected** to 9 bytes (`\xC1PHRF0RGE`), properly
  encoding "Cipherforge" with the final 'E'.
- **Trailer HMAC context** changed to `cipherforge-trailer-hmac-v4`.

## v3.3.2 (2026-07-19)

### Fixed

- **Cross-compilation broken by multi-file package.** `build-all.sh` and
  `build-all.ps1` compiled `cmd/cfo/main.go` as a single file, missing the
  new `params.go`. Changed to `./cmd/cfo/` (package path).

### Changed

- **Argument parsing extracted to `params.go`.** `getParameters()` now returns
  a `params` struct instead of 8 separate values. `resolvePasswordInteractive`
  moved alongside it.
- **Deduplicated crypto helpers.** `randRead()` shared by `GenerateSalt`/
  `GenerateNonce`; `splitKeyPair()` shared by `DeriveKeys`/`DeriveKeysFromMaster`.
- **Deduplicated trailer HMAC.** `trailerHMACContext()` eliminates copy-pasted
  v2/v3 branches.
- **`Encrypt` split into `writeHeader` and `encryptSegments`.**
- **`CharacterPool` exported from `internal/crypto`** — removes duplicate
  definition in `cmd/cfo/main.go` and `crypto_test.go`.
- **`FastTestParams()` added to `internal/format`** — shared by all test files.
- **Error wrapping added to `WriteUint64`/`WriteUint32`/`ReadUint64`/`ReadUint32`.**
- **`PrintSuccess` removed** (empty function); `ReadPasswordFromTerminal` uses
  `TrimSuffix` instead of `TrimRight`.
- **`ErrAuthenticationFailed` sentinel error** in `pkg/cipherforge`.

## v3.3.1 (2026-07-18)

### Fixed

- **CLI exits with non-zero code on failure.** `main()` now calls `os.Exit(1)`
  when any file operation fails. Previously errors were printed but the process
  always exited 0, which caused integration tests (and scripts relying on exit
  codes) to miss authentication failures.
- **Decrypt no longer requires `.cfo` extension.** Files created with `-o`
  (custom output names) could not be decrypted because `processFile` rejected
  inputs missing the `.cfo` suffix. The check was removed — trailer HMAC
  verification provides real authentication regardless of filename.
- **Non-`.cfo` decrypt output no longer overwrites input.** `deriveOutputPath`
  now appends `.dec` when the input does not end with `.cfo`, preventing the
  decryptor from truncating its own input.

### Changed

- **Build scripts handle missing CGO gracefully.** `build-all.sh` and
  `build-all.ps1` now check `go env CGO_ENABLED` before using `-race`. When CGO
  is unavailable (e.g. Windows without mingw-w64), tests run without the race
  detector and a warning is printed.
- **PowerShell build script now runs unit tests.** `build-all.ps1` previously
  skipped testing entirely.

## v3.3.0 (2026-06-26)

### Added

- **Stdin/stdout support via `-`.** Encrypt from stdin and decrypt to stdout
  using the standard Unix `-` convention. `echo "Hello" | cfo -e -o out.cfo`
  encrypts piped input; `cfo -d file.cfo -o -` decrypts to stdout. When stdin
  is not a terminal, `-e` can be omitted entirely: `echo "Hello" | cfo -o out.cfo`
  auto-detects stdin. Decrypt from stdin is intentionally unsupported (the
  decryptor requires a seekable input for trailer-HMAC verification).

### Changed

- Filename listings (tar `-v` style) now go to stderr instead of stdout,
  keeping data output (`-o -`) clean for piping.

## v3.2.0 (2026-06-26)

### Changed

- **Argon2id parameters reduced** from 1 GiB / 4 passes to 256 MiB / 5 passes.
  For auto-generated 44-character passwords (~258 bits entropy), the KDF parameters
  are cryptographically irrelevant — the keyspace is physically unsearchable. For
  user-supplied passwords, 256 MiB is the threshold that forces even a custom-ASIC
  attacker into external DRAM (rather than on-die SRAM), which is where Argon2id's
  memory-hardness imposes real economic cost. Above 256 MiB, returns diminish:
  1 GiB quadruples both attacker per-core memory cost and user wait time. The time
  parameter was raised from 4 to 5 to partially compensate at negligible runtime
  cost. Derivation completes in ~1 second on modern hardware (down from ~4–8 s)
  while keeping brute-force cost above $200K in ASIC silicon even for a weak
  8-character password.
- **Console output redesigned to mimic tar(1).** No ANSI colors, no progress bars,
  no decorative symbols (✓, ✗, ⚠). Filenames are printed as each file is processed
  (like `tar -v`). Prompts, warnings, and errors go to stderr with a `cfo:` prefix;
  only data output (auto-generated password, filenames) goes to stdout. Success is
  silent. Help and version output use minimal plain-text formatting.

### Fixed

- **Source archive no longer stalls.** `build-all.sh` now uses `git archive` instead
  of `tar --exclude` for the source tarball, avoiding the 9.4 GiB untracked
  `bin.bin` test artifact that caused the tar step to hang.

## v3.1.0 (2026-06-25)

### Security

- `MaxArgon2Time` reduced from 100 to 10 passes to limit DoS potential from
  crafted files with inflated KDF parameters. Key derivation happens before
  HMAC verification, so safety limits are the only defense against parameter
  inflation attacks. No legitimate use case needs >10 passes with 1 GiB memory.
- Short-password warning: when encrypting multiple files with a user-supplied
  password shorter than 20 characters, a warning explains the v3 batch
  optimisation trade-off (one Argon2id run covers all files).

### Added

- `-a` / `--atomic` flag: decrypts to a temporary file in the output
  directory and renames to the final path only on success. Prevents partial
  plaintext from ever appearing at the target path if decryption fails
  mid-stream (e.g., a corrupted segment after the trailer HMAC has passed).

### Changed

- `FILEFORMAT.MD` rewritten for v3. The document now describes the current
  two-tier key derivation (master key + HKDF), the v3 trailer HMAC context,
  and the version-enforcement behaviour. v1/v2 formats are documented in a
  legacy section at the end.
- `README.MD` format version updated to v3; HMAC context updated to
  `cipherforge-trailer-hmac-v3`; new flags (`-q`, `-f`, `-a`) documented.

### Fixed

- `--atomic` mode: eliminated a redundant file descriptor (`os.CreateTemp` +
  `os.OpenFile` opened the temp file twice). The temp file is now used
  directly as the output writer.
- `build-all.sh`: enabled global `set -euo pipefail`; replaced `echo | cut`
  subshells with bash parameter expansion for OS/ARCH extraction.
- `test/test.sh`: added prerequisite checks (`timeout`, `dd`, `sha256sum`)
  with clear failure messages; added content-integrity verification (SHA-256)
  to single-file encrypt/decrypt tests; corrected `fault_kill_once` and
  `test_fault_truncate` to compare decrypted output against the saved original
  rather than stdout or a never-written file.
- `build-all.sh`: replaced `cd -` anti-patterns with explicit directory
  save/restore for robustness.
- `test/test.sh`: `pkill(1)` replaced with `kill` for portability; cleanup
  reliability improved.

## v3.0.1 (2026-06-20)

### Security

- Intermediate key material (`raw` slice) in `DeriveKeysFromMaster` and
  `DeriveKeys` is now copied into independent allocations and explicitly
  zeroed, preventing residual key data from lingering on the heap.
- Argon2id parameters read from file headers are now validated against
  upper-bound safety limits (`time ≤ 100`, `memory ≤ 16 GiB`) to prevent
  resource-exhaustion denial-of-service from crafted `.cfo` files.

### Added

- Package-level documentation on `internal/crypto` documenting the inherent
  Go garbage-collector limitation: heap compaction may retain copies of key
  material in freed memory beyond application control.

### Fixed

- Missing `format` import in `cmd/cfo/main.go` (pre-existing build error).
- Missing `masterKey` argument in `cmd/cfo/main_test.go` (pre-existing test
  compilation error).

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
