# Cipherforge Architecture

This document describes the architecture of Cipherforge for developers reading
the code for the first time. It covers directory structure, data flow, key
design decisions, and the rationale behind dependencies.

## Overview

Cipherforge is a file encryption tool built with long-term archival in mind.
It encrypts files of any size using AES-256-GCM with HKDF-SHA256 key
derivation, writing them in a self-describing `.cfo` format designed to be
decodable decades from now. It doubles as a terminal application (TUI) and a traditional CLI tool,
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
│   │   ├── crypto.go    #   HKDF, secret generation, ZeroBytes
│   │   ├── crypto_test.go
│   │   ├── mlock_unix.go
│   │   └── mlock_windows.go
│   ├── format/          # .cfo binary format constants and serialization
│   │   ├── format.go
│   │   └── format_test.go
│   ├── ui/              # Terminal I/O: secret prompts, warning/error output
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
│  - HKDF, CSPRNG                         │
│  - secret generation                    │
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
User input (file path)
    │
    ▼
cmd/cfo/main.go
    │  opens input file, determines output path
    ▼
pkg/cipherforge.Encrypter.Encrypt(reader, writer)
    │
    ├── crypto.GenerateSecurePassword()                 → generated secret
    ├── crypto.GenerateSalt()                            → 16-byte file salt
    ├── crypto.DeriveKeys(secret, salt)                  → encKey + macKey
    ├── format.WriteHeader(writer, salt)
    │
    ├── for each 1 MiB segment:
    │     ├── deriveSegmentNonce(prefix, segmentNum)   → 12-byte nonce
    │     ├── buildAAD(segmentNum, plaintextLen)        → 16-byte AAD
    │     ├── AEAD.Seal(plaintext, nonce, aad)          → ciphertext + tag
    │     └── write segment length + ciphertext to output
    │
    └── format.WriteTrailer(writer, segmentCount, trailerHMAC)
```

### File Decryption

```
User input (.cfo file + generated secret)
    │
    ▼
cmd/cfo/main.go
    │  opens .cfo file
    ▼
pkg/cipherforge.Decrypter.Decrypt(reader, writer)
    │
    ├── Seek to end, read trailer
    ├── Read header → salt
    ├── crypto.DeriveKeys(secret, salt)
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
| Key derivation and separation | HKDF-SHA256 (RFC 5869) | Independent enc/mac keys from generated secret and file salt |
| Encryption | AES-256-GCM | 12-byte prefix/counter nonce, 16-byte tag |
| Authentication | GCM per segment + HMAC-SHA256 trailer | Segments independently verified |
| Key commitment | HMAC-SHA256(encKey, context || salt) | Ciphertext binds to a single key |
| Randomness | OS CSPRNG (crypto/rand) | /dev/urandom, CNG — not userspace PRNG |
| Password gen | crypto/rand + rejection sampling | No modulo bias, 256+ bits entropy |
| Memory | mlock (best-effort) + ZeroBytes | Key material locked; passwords explicitly zeroed |

The trailer HMAC and key-commitment tag are verified **before** any segment is
decrypted. This means a wrong password is detected immediately — no plaintext
touches disk.

## File Format

The `.cfo` format (v7) has three contiguous regions:

```
╔══════════════════════╗
║ HEADER  (35 bytes)   ║  magic, version, suite, salt, nonce prefix
╠══════════════════════╣
║ PAYLOAD (variable)   ║  1+ segments: [8-byte len][AEAD ciphertext]
╠══════════════════════╣
║ TRAILER (72 bytes)   ║  segment count + HMAC + key-commitment tag
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
| `golang.org/x/crypto` | HKDF-SHA256 | Official Go extended library, well-audited |
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
go build -ldflags "-X main.Version=7.1.0 -X main.GitCommit=abc1234"
```

## Design Decisions

### Why is there no password-based KDF?

Cipherforge never accepts a human-chosen encryption password. The secret is
generated by the operating system CSPRNG at 45 characters (~262 bits of
entropy, printed in dash-separated groups of five), so the keyspace is already
far beyond brute force and a memory-hard
KDF would add attacker cost only in a scenario that cannot occur. Skipping it
also removes the embedded-KDF-parameter attack surface: there are no
attacker-controlled cost parameters in the header to validate or bound. Key
separation is still provided by HKDF-SHA256, which expands the secret into
independent encryption and MAC keys per file.

### Why AES-256-GCM?

AES-256-GCM is available in Go's standard library, is widely standardized, and
benefits from AES acceleration on common CPUs. Cipherforge does not rely on
random 96-bit nonces: each file stores a random 4-byte prefix and combines it
with the 8-byte segment counter to form a unique 12-byte nonce. Nonce reuse is
catastrophic for GCM, so the prefix/counter construction is part of the file
format and is covered by the trailer HMAC.

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
