# Cipherforge Architecture

This document describes the architecture of Cipherforge for developers reading
the code for the first time. It covers directory structure, data flow, key
design decisions, and the rationale behind dependencies.

## Overview

Cipherforge is a file encryption tool built with long-term archival in mind.
It encrypts files of any size using XChaCha20-Poly1305 and Argon2id, writing
them in a self-describing `.cfo` format designed to be decodable decades from
now. It doubles as a terminal application (TUI) and a traditional CLI tool,
both from the same binary.

## Directory Structure

```
cipherforge-go/
├── cmd/cfo/             # CLI entry point (package main)
│   ├── main.go          #   argument dispatch, file I/O, TUI/CLI routing
│   ├── main_test.go     #   CLI argument parsing tests
│   └── params.go        #   CLI flag parsing
├── pkg/cipherforge/     # Public API: Encrypter and Decrypter engines
│   ├── cipherforge.go   #   high-level streaming encrypt/decrypt
│   └── cipherforge_test.go
├── internal/
│   ├── crypto/          # Cryptographic primitives (no file-format awareness)
│   │   ├── crypto.go    #   Argon2id KDF, HKDF, password generation, ZeroBytes
│   │   ├── crypto_test.go
│   │   ├── mlock_unix.go
│   │   └── mlock_windows.go
│   ├── format/          # .cfo binary format constants and serialization
│   │   ├── format.go
│   │   └── format_test.go
│   ├── ui/              # Terminal I/O: password prompts, warning/error output
│   │   ├── ui.go
│   │   └── ui_test.go
│   └── tui/             # Full-screen terminal UI (Bubble Tea)
│       ├── tui.go           #   Model, screen routing, View/Update loop
│       ├── screen_main.go   #   Main menu
│       ├── screen_picker.go #   File picker with type-ahead
│       ├── screen_text.go   #   Text input for encrypt/decrypt text mode
│       ├── screen_password.go # Password entry with auto-generate
│       ├── screen_progress.go # Progress bar during operations
│       ├── screen_results.go  # Results display with copy shortcuts
│       └── tui_test.go
├── sample.txt           # Unicode test file
├── FILEFORMAT.MD        # Authoritative .cfo format specification
├── ARCHITECTURE.MD      # This file
├── README.MD
├── CHANGELOG.md
├── build-all.ps1        # Windows build script
└── build-all.sh         # Unix build script
```

## Layered Architecture

The code follows a strict layering where lower layers never import higher ones:

```
┌─────────────────────────────────────────┐
│  cmd/cfo  (CLI entry point)             │
│  - argument parsing                     │
│  - file I/O setup                       │
│  - TUI launch / CLI dispatch            │
├─────────────────────────────────────────┤
│  internal/tui  (terminal UI)            │
│  - Bubble Tea screens                   │
│  - progress channel management          │
│  - clipboard interaction                │
├─────────────────────────────────────────┤
│  pkg/cipherforge  (public API)          │
│  - Encrypter / Decrypter engines        │
│  - segment-level AEAD encryption        │
│  - header/trailer construction          │
├─────────────────────────────────────────┤
│  internal/crypto  (primitives)          │
│  - Argon2id, HKDF, CSPRNG               │
│  - password generation                  │
│  - memory locking / zeroing             │
├─────────────────────────────────────────┤
│  internal/format  (constants)           │
│  - .cfo binary format constants         │
│  - serialization helpers                │
└─────────────────────────────────────────┘
```

**Key rule:** `internal/crypto` and `internal/format` know nothing about files
or the `.cfo` format. `pkg/cipherforge` orchestrates them. `cmd/cfo` handles
user interaction. The TUI sits between `cmd/cfo` and `pkg/cipherforge`.

## Data Flow

### File Encryption

```
User input (file path + password)
    │
    ▼
cmd/cfo/main.go
    │  opens input file, determines output path
    ▼
pkg/cipherforge.Encrypter.Encrypt(reader, writer)
    │
    ├── crypto.DeriveMasterKey(password, argon2params)  → 32-byte master key
    ├── crypto.GenerateSalt()                           → 16-byte file salt
    ├── crypto.DeriveKeysFromMaster(masterKey, salt)     → encKey + macKey
    ├── format.WriteHeader(writer, salt, params)
    │
    ├── for each 1 MiB segment:
    │     ├── deriveSegmentNonce(seed, segmentNum)     → 24-byte nonce
    │     ├── buildAAD(segmentNum, plaintextLen)        → 16-byte AAD
    │     ├── AEAD.Seal(plaintext, nonce, aad)          → ciphertext + tag
    │     └── write segment length + ciphertext to output
    │
    └── format.WriteTrailer(writer, segmentCount, trailerHMAC)
```

### File Decryption

```
User input (.cfo file + password)
    │
    ▼
cmd/cfo/main.go
    │  opens .cfo file
    ▼
pkg/cipherforge.Decrypter.Decrypt(reader, writer)
    │
    ├── Seek to end, read trailer
    ├── Read header → salt, Argon2 params
    ├── crypto.DeriveMasterKey(password, params)
    ├── crypto.DeriveKeysFromMaster(masterKey, salt)
    ├── Verify trailer HMAC  ← detects wrong password BEFORE any plaintext
    │
    └── for each segment:
          ├── read segment length
          ├── deriveSegmentNonce(seed, segmentNum)
          ├── buildAAD(segmentNum, plaintextLen)
          └── AEAD.Open(ciphertext, nonce, aad) → plaintext
```

## Cryptographic Design

| Component | Algorithm | Rationale |
|---|---|---|
| Key derivation | Argon2id (5 passes, 256 MiB, 4 threads) | Memory-hard, ASIC-resistant, OWASP recommended |
| Key separation | HKDF-SHA256 (RFC 5869) | Independent enc/mac keys from one master key |
| Encryption | XChaCha20-Poly1305 (IETF variant) | 192-bit nonce, no nonce-reuse risk |
| Authentication | Poly1305 per segment + HMAC-SHA256 trailer | Segments independently verified |
| Randomness | OS CSPRNG (crypto/rand) | /dev/urandom, CNG — not userspace PRNG |
| Password gen | crypto/rand + rejection sampling | No modulo bias, 256+ bits entropy |
| Memory | mlock (best-effort) + ZeroBytes | Key material locked; passwords explicitly zeroed |

The trailer HMAC is verified **before** any segment is decrypted. This means a
wrong password is detected immediately — no plaintext touches disk.

## File Format

The `.cfo` format (v4) has three contiguous regions:

```
╔══════════════════════╗
║ HEADER  (65 bytes)   ║  magic, version, salt, KDF params
╠══════════════════════╣
║ PAYLOAD (variable)   ║  1+ segments: [8-byte len][AEAD ciphertext]
╠══════════════════════╣
║ TRAILER (40 bytes)   ║  segment count + HMAC over header fields
╚══════════════════════╝
```

Full specification: [FILEFORMAT.MD](FILEFORMAT.MD).

## TUI Architecture

The TUI uses the [Bubble Tea](https://github.com/charmbracelet/bubbletea)
framework (Elm Architecture):

```
Model ←→ Update ←→ View
  ↑                  │
  └── tea.Cmd ───────┘
```

### Screen Flow

```
MainMenu → FilePicker → Password → Progress → Results → MainMenu
                │                        │
                └── TextInput ───────────┘
```

Every screen is a sub-model stored on the top-level `Model` struct. Screen
transitions happen by changing `m.screen` and returning the new screen's
`Init()` command. The top-level `View()` dispatches to the active sub-model's
`View()`.

### Progress Channel

Encryption/decryption runs in a goroutine with a 256-slot buffered channel for
progress updates. A blocking send on the channel throttles the worker to the
UI's drain rate (~60 MB/s), keeping the progress bar responsive without
dropping updates.

### Key TUI Files

| File | Responsibility |
|---|---|
| `tui.go` | Model, screen routing, View/Update, progress handling |
| `screen_main.go` | Main menu with numbered shortcuts |
| `screen_picker.go` | File picker, type-ahead search |
| `screen_text.go` | Multi-line text input for text encrypt/decrypt |
| `screen_password.go` | Password entry, auto-generate checkbox, focus cycling |
| `screen_progress.go` | Progress bar, runEncrypt/runDecrypt, text operations |
| `screen_results.go` | Success/failure display, password box, clipboard |

## CLI vs TUI Dispatch

```
main()
  │
  ├── -h/-v?  → show help/version, exit
  ├── no flags + terminal?  → runInteractive() → tui.Run()
  └── flags present?        → runCLI(cfg)
```

When launched without flags from an interactive terminal, the TUI starts.
When flags are provided (or stdin is piped), the traditional CLI runs.
The `-i` flag forces TUI mode.

## Dependencies

### Direct (chosen deliberately)

| Dependency | Purpose | Why |
|---|---|---|
| `golang.org/x/crypto` | Argon2id, HKDF, XChaCha20-Poly1305 | Official Go extended library, well-audited |
| `golang.org/x/term` | Terminal detection, raw mode, ReadPassword | Official Go extended library |
| `golang.org/x/sys` | mlock, Windows syscalls | Official Go extended library |
| `github.com/charmbracelet/bubbletea` | TUI framework (Elm Architecture) | Pure Go, 30k+ stars, no CGo |
| `github.com/charmbracelet/bubbles` | TUI widgets (textinput, textarea) | Official companion to bubbletea |
| `github.com/charmbracelet/lipgloss` | Terminal styling | Pure Go, no CGo |
| `github.com/atotto/clipboard` | Clipboard access | Pure Go, cross-platform |

### Indirect (pulled by Bubble Tea)

All transitive dependencies are pure Go with no CGo — the binary remains a
single statically-linked executable.

## Build System

Two build scripts produce binaries for 8 platforms:

```
build-all.ps1   # Windows (PowerShell)
build-all.sh    # Linux/macOS (bash)
```

Targets: `linux/{amd64,arm64,386}`, `windows/{amd64,386}`, `darwin/{amd64,arm64}`, `freebsd/amd64`

The version and git commit are injected via linker flags:

```
go build -ldflags "-X main.Version=4.1.1 -X main.GitCommit=abc1234"
```

## Design Decisions

### Why Argon2id and not bcrypt/scrypt/PBKDF2?

Argon2id is the winner of the Password Hashing Competition (2015) and is the
OWASP recommendation. It is memory-hard (256 MiB default), making GPU/ASIC
attacks expensive. bcrypt is limited to 4 KiB memory; PBKDF2 has no memory
hardness.

### Why XChaCha20-Poly1305 and not AES-GCM?

XChaCha20-Poly1305 uses a 192-bit nonce (vs AES-GCM's 96-bit), eliminating
nonce-reuse risk for random nonces. It's also constant-time in software and
doesn't require AES-NI hardware. For long-term archival, algorithm simplicity
matters more than hardware acceleration.

### Why 1 MiB segments?

Streaming segments keep memory constant regardless of file size. Each segment
is independently authenticated, so corruption in one segment doesn't affect
others. The 1 MiB size balances overhead (~16 bytes per segment) with
granularity.

### Why Bubble Tea?

Pure Go, statically linked, no CGo, no system dependencies. The Elm
Architecture (Model/Update/View) is well-understood and keeps screen logic
separated. The ecosystem (`bubbles`, `lipgloss`) provides widgets and styling.

### Why Go?

Single static binary, cross-compilation built-in, strong standard library
(crypto, io, os), and the Go 1.x compatibility guarantee means code compiled
today will compile with future Go versions. Critical for a tool designed for
decade-spanning archival.

## Testing

Tests are co-located with source files (`*_test.go`). The `internal/tui`
package has unit tests for pure functions (wrapping, path derivation, results
construction). The `pkg/cipherforge` package has integration tests for
encrypt/decrypt round-trips including base64 encoding. Run with:

```
go test ./...
```

The build scripts run tests before cross-compiling.
