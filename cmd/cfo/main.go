// Command cfo is the Cipherforge CLI — a tool for encrypting and decrypting
// files using XChaCha20-Poly1305 and Argon2id.
//
// # Go Language Notes for Java Developers (Entry Point & CLI)
//
// This file demonstrates several Go patterns common in CLI applications:
//
//   - `package main` is special — it defines an executable (like a class with
//     `public static void main`). `func main()` is the entry point.
//     No class wrapping, no `public static` — just a function in `package main`.
//
//   - `var Version = "dev"` at package scope is a package-level variable
//     (like a static field). Build tools inject the real version at link time
//     using `-ldflags "-X main.Version=3.2.0"`.
//
//   - `os.Args` is like Java's `String[] args` but includes the program name
//     at index 0. Use `os.Args[1:]` to skip it.
//
//   - `os.Exit(1)` terminates the process immediately (like System.exit(1)).
//     Deferred functions do NOT run on os.Exit.
//
//   - `switch` in Go does NOT fall through by default (unlike Java).
//     No `break` needed after each case.
//
//   - `fmt.Fprintf(os.Stderr, ...)` is like Java's `System.err.printf(...)`.
//     `fmt.Printf(...)` writes to stdout (System.out).
package main

import (
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
	"github.com/vilshansen/cipherforge-go/internal/tui"
	"github.com/vilshansen/cipherforge-go/internal/ui"
	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

// Version and GitCommit are set at build time via linker flags:
//
//	go build -ldflags "-X main.Version=3.2.0 -X main.GitCommit=abc123"
//
// If not set, they default to "dev" and "none" respectively.
// This is Go's equivalent of Maven's resource filtering or Gradle's
// processResources to inject build metadata.
var Version = "dev"
var GitCommit = "none"

// characterPool is the set of unambiguous characters used for auto-generated
// passwords. Digits 1-9 (no 0 — confused with O), uppercase A-Z without I/O,
// lowercase a-z without l. 58 characters total.
//
// 44 chars × log₂(57) ≈ 257.7 bits ≥ 256-bit key strength.
const passwordLength = 44

func main() {
	// Always show help for -h/--help, version for -v/--version.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help":
			showHelp()
			os.Exit(0)
		case "-v", "--version":
			fmt.Printf("cfo %s\n", Version)
			os.Exit(0)
		}
	}

	cfg, err := getParameters()
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	// Interactive TUI mode: launch the terminal UI, get config, execute.
	if cfg.Interactive {
		runInteractive()
		return
	}

	// CLI mode: existing flow.
	runCLI(cfg)
}

// runInteractive launches the full-screen TUI. The TUI handles all
// encryption/decryption work internally with live progress bars.
// It loops until the user explicitly quits.
func runInteractive() {
	if err := tui.Run(Version, GitCommit); err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
}

// runCLI executes the traditional command-line workflow.
func runCLI(cfg params) {
	// Expand glob patterns and validate input paths.
	inputFiles, err := expandInputPaths(cfg.Inputs, cfg.Operation)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	// Validate stdin constraints.
	for _, f := range inputFiles {
		if f == "-" && len(inputFiles) > 1 {
			ui.PrintError("stdin (-) cannot be combined with other input files")
			os.Exit(1)
		}
	}
	if cfg.Output != "" && len(inputFiles) > 1 {
		ui.PrintError("-o requires a single input file")
		os.Exit(1)
	}
	if len(inputFiles) > 0 && inputFiles[0] == "-" && cfg.Output == "" {
		ui.PrintError("stdin requires -o <output>")
		os.Exit(1)
	}

	// Resolve the password: use the user-supplied one, or generate/ask.
	password, err := resolvePassword(cfg.Operation, cfg.Password)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
	defer crypto.ZeroBytes(password)

	// Security warning: short user-supplied password + multiple files.
	if cfg.Operation == "encrypt" && cfg.Password != nil && len(cfg.Password) < 20 && len(inputFiles) > 1 {
		ui.PrintWarning(fmt.Sprintf(
			"Short password (%d chars) with %d files. The v4 batch optimisation derives\n"+
				"                all file keys from one Argon2id run — a weak password puts every\n"+
				"                output file at risk. Consider a longer password or encrypting\n"+
				"                files separately with different passwords.",
			len(cfg.Password), len(inputFiles)))
	}

	// For encryption, derive the master key ONCE and reuse for all files.
	var masterKey []byte
	if cfg.Operation == "encrypt" {
		masterKey = crypto.DeriveMasterKey(password, format.DefaultArgon2Params())
		defer crypto.ZeroBytes(masterKey)
	}

	var hasErrors bool
	for _, inputFile := range inputFiles {
		outputFile := cfg.Output
		if outputFile == "" {
			outputFile = deriveOutputPath(cfg.Operation, inputFile)
		}
		if err := processFile(cfg.Operation, inputFile, outputFile, password, masterKey, cfg.Quiet, cfg.Force, cfg.Atomic, cfg.Base64); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to process %s: %v", inputFile, err))
			hasErrors = true
		}
	}
	if hasErrors {
		os.Exit(1)
	}
}

// deriveOutputPath determines the output filename from the operation and input.
// Encryption: append ".cfo" → "doc.pdf" becomes "doc.pdf.cfo"
// Decryption: strip ".cfo" if present, otherwise append ".dec"
// stdin ("-"): pass through as "-" (stdout)
func deriveOutputPath(operation, inputFile string) string {
	if inputFile == "-" {
		return "-"
	}
	if operation == "encrypt" {
		return inputFile + ".cfo"
	}
	// strings.TrimSuffix removes the suffix if present; no-op otherwise.
	if strings.HasSuffix(inputFile, ".cfo") {
		return strings.TrimSuffix(inputFile, ".cfo")
	}
	return inputFile + ".dec"
}

// processFile dispatches to encryptFile or decryptFile based on the operation.
// Also performs path validation and checks for existing output files.
func processFile(operation, inputFile, outputFile string, password, masterKey []byte, quiet, force, atomic, base64 bool) error {
	// os.Stat returns (FileInfo, error). If err == nil, the file exists.
	if outputFile != "-" && !force {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file %q already exists (use -f to overwrite)", outputFile)
		}
	}
	if operation == "encrypt" {
		return encryptFile(inputFile, outputFile, password, masterKey, quiet, base64)
	}
	return decryptFile(inputFile, outputFile, password, quiet, atomic, base64)
}

// encryptFile handles I/O setup for encryption and delegates to the Encrypter engine.
// When base64 is true, the output is wrapped in RFC 4648 base64 encoding
// (no line breaks) for easy copy/paste. On failure, the output file is
// automatically removed.
func encryptFile(inputFile, outputFile string, password, masterKey []byte, quiet, base64 bool) error {
	// Open input. os.Stdin is a global *os.File for standard input (like System.in).
	var in *os.File
	if inputFile == "-" {
		in = os.Stdin
	} else {
		var err error
		in, err = os.Open(inputFile)
		if err != nil {
			return err
		}
		defer in.Close()
	}

	// Open output. os.O_WRONLY|os.O_CREATE|os.O_TRUNC are bit flags.
	// 0600 is Unix permission: owner read+write only.
	var out *os.File
	if outputFile == "-" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
	}

	// Automatic cleanup on failure: the closure captures `succeeded` and
	// `outputFile` by reference. If we return with an error, the defer
	// removes the partial output file.
	succeeded := false
	defer func() {
		if outputFile != "-" {
			out.Close()
			if !succeeded {
				os.Remove(outputFile)
			}
		}
	}()

	if !quiet && outputFile != "-" {
		if inputFile == "-" {
			fmt.Fprintln(os.Stderr, "(stdin)")
		} else {
			fmt.Fprintln(os.Stderr, filepath.Base(inputFile))
		}
	}

	// Select the appropriate Encrypter constructor: batch mode (pre-derived
	// master key) or single-file mode (derive master key on demand).
	var enc *cipherforge.Encrypter
	if masterKey != nil {
		enc = cipherforge.NewEncrypterWithMasterKey(password, masterKey)
	} else {
		enc = cipherforge.NewEncrypter(password)
	}

	// Wrap output with base64 encoder if requested.
	var writer io.Writer = out
	var b64Closer io.Closer
	if base64 {
		b64w := b64.NewEncoder(b64.StdEncoding, out)
		writer = b64w
		b64Closer = b64w
	}

	err := enc.Encrypt(in, writer, nil) // nil = no progress callback

	// Must close the base64 encoder to flush any remaining bytes.
	if b64Closer != nil {
		if closeErr := b64Closer.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}

	if err == nil {
		succeeded = true
	}
	return err
}

// decryptFile handles I/O setup for decryption and delegates to the Decrypter engine.
// Stdin decryption is NOT supported (requires seekable input for trailer HMAC).
// Base64 decryption reads the entire input into memory, decodes it, and wraps
// the result in a seekable bytes.Reader — suitable for copy/paste workflows
// with reasonably-sized files.
// Supports atomic mode: decrypt to temp file, rename on success.
func decryptFile(inputFile, outputFile string, password []byte, quiet, atomic, base64 bool) error {
	if inputFile == "-" {
		return fmt.Errorf("decrypt from stdin is not supported (seek required for trailer HMAC)")
	}

	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	// If base64, read the entire file, decode it into memory, and wrap in a
	// seekable Reader so the Decrypter can seek to the trailer.
	var reader io.ReadSeeker
	if base64 {
		raw, err := io.ReadAll(in)
		if err != nil {
			return fmt.Errorf("reading base64 input: %w", err)
		}
		in.Close() // Done with the file; raw data is in memory.

		decoded := make([]byte, b64.StdEncoding.DecodedLen(len(raw)))
		n, err := b64.StdEncoding.Decode(decoded, raw)
		if err != nil {
			return fmt.Errorf("decoding base64 input: %w", err)
		}
		reader = bytes.NewReader(decoded[:n])
	} else {
		reader = in
	}

	// Open output — with special handling for atomic mode.
	// os.CreateTemp is like Java's Files.createTempFile().
	// The temp file is in the same directory as the final output to ensure
	// atomic rename (rename across filesystems is not atomic).
	var out *os.File
	writePath := outputFile
	if outputFile == "-" {
		out = os.Stdout
	} else if atomic {
		out, err = os.CreateTemp(filepath.Dir(outputFile), ".cfo-decrypt-*")
		if err != nil {
			return fmt.Errorf("cannot create temp file for atomic decrypt: %w", err)
		}
		writePath = out.Name()
	} else {
		out, err = os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
	}

	// Automatic cleanup on failure.
	succeeded := false
	defer func() {
		if outputFile != "-" {
			out.Close()
			if !succeeded {
				os.Remove(writePath)
			}
		}
	}()

	if !quiet && outputFile != "-" {
		fmt.Fprintln(os.Stderr, filepath.Base(inputFile))
	}

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(reader, out, nil)

	if err == nil {
		succeeded = true
	}

	// Atomically rename the temp file to the final output path.
	// os.Rename is atomic when src and dst are on the same filesystem.
	if atomic && succeeded && outputFile != "-" {
		out.Close() // Must close before rename on Windows
		if err := os.Rename(writePath, outputFile); err != nil {
			os.Remove(writePath)
			return fmt.Errorf("atomic rename failed: %w", err)
		}
	}
	return err
}

// resolvePassword determines the password to use for the operation.
// Priority: 1) User-supplied via -p, 2) Auto-generated for encrypt, 3) Prompt for decrypt.
func resolvePassword(operation string, userPassword []byte) ([]byte, error) {
	if userPassword != nil {
		if len(userPassword) == 0 {
			return nil, fmt.Errorf("password must not be empty")
		}
		if len(userPassword) < 12 {
			ui.PrintWarning(fmt.Sprintf("Short password (%d chars). Consider a longer one.", len(userPassword)))
		}
		return userPassword, nil
	}

	if operation == "encrypt" {
		p, err := crypto.GenerateSecurePassword(passwordLength, crypto.CharacterPool)
		if err != nil {
			return nil, err
		}
		fmt.Printf("%s\n", p)
		fmt.Fprintf(os.Stderr, "cfo: Save this password — it cannot be recovered.\n")
		return p, nil
	}

	for {
		p, err := ui.ReadPasswordStarred("Enter password for decryption: ")
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			return p, nil
		}
		ui.PrintError("Password cannot be empty")
	}
}

// expandInputPaths expands glob patterns into concrete file paths.
// Uses filepath.Glob (like Java's FileSystem.getPathMatcher("glob:...")).
// Skips .cfo files during encryption (prevents double-encryption).
// Skips directories.
func expandInputPaths(inputs []string, op string) ([]string, error) {
	var files []string
	for _, input := range inputs {
		if input == "-" {
			files = append(files, "-")
			continue
		}
		matches, err := filepath.Glob(input)
		if err != nil {
			return nil, fmt.Errorf("glob pattern %q: %w", input, err)
		}
		for _, match := range matches {
			if op == "encrypt" && strings.HasSuffix(match, ".cfo") {
				continue
			}
			info, err := os.Stat(match)
			if err == nil && !info.IsDir() {
				files = append(files, match)
			}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no files found")
	}
	return files, nil
}

// showHelp prints the help text to stdout.
func showHelp() {
	fmt.Printf("cfo %s — encrypt and decrypt files with XChaCha20-Poly1305 and Argon2id.\n\n", Version)

	fmt.Println("Usage: cfo -e <file...>")
	fmt.Println("       cfo -d <file...>")
	fmt.Println("       cfo -e <file> -o <out>.cfo")
	fmt.Println("       cfo -e <file...> -p <pwd>")
	fmt.Println("       cfo -e <file...> -p")
	fmt.Println("       cfo -e -o <out>.cfo           (reads from stdin)")

	fmt.Println("\nFlags:")
	fmt.Println("  -e                Encrypt — each input file produces <name>.cfo")
	fmt.Println("  -d                Decrypt — each .cfo file produces its original name")
	fmt.Println("  -o <file>         Output filename (use - for stdout)")
	fmt.Println("  -p [pwd]          Supply a password. Without -p, encryption auto-generates one;")
	fmt.Println("                    decryption prompts interactively")
	fmt.Println("  -b, --base64      Wrap encrypted output in base64 encoding (encrypt only)")
	fmt.Println("  -i, --interactive Launch the full-screen terminal UI")
	fmt.Println("  -q, --quiet       Suppress all non-error output")
	fmt.Println("  -f, --force       Overwrite output file if it already exists")
	fmt.Println("  -a, --atomic      Decrypt to a temp file, rename only on success")
	fmt.Println("  -h, --help        Show this help text")
	fmt.Println("  -v, --version     Show version information")

	fmt.Println("\nExamples:")
	fmt.Println("  cfo -e document.pdf                Encrypt document.pdf → document.pdf.cfo")
	fmt.Println("  cfo -e *.txt -p mysecret           Encrypt all .txt files (skips .cfo files)")
	fmt.Println("  cfo -d document.pdf.cfo            Decrypt (prompts for password)")
	fmt.Println("  cfo -d *.cfo -p mysecret           Decrypt all .cfo files")
	fmt.Println("  cfo -e backup.tar -o archive.cfo   Encrypt to a custom output name")
	fmt.Println("  cfo -e secret.txt --base64         Encrypt to base64-encoded .cfo output")
	fmt.Println("  echo 'Hello' | cfo -e -o out.cfo   Encrypt from stdin")
	fmt.Println("  cfo -d file.cfo -o -               Decrypt to stdout")
	fmt.Println("  cfo                                 Launch the terminal UI (no flags)")

	fmt.Println("\nNotes:")
	fmt.Println("  The auto-generated password is 44 characters — shown once, cannot be recovered.")
	fmt.Println("  Argon2id KDF uses 256 MiB memory per operation; each takes ~1 second.")
	fmt.Println("  The .cfo file reveals the original filename and approximate plaintext size")
	fmt.Println("  but does not hide the existence of encrypted data.")
	fmt.Println("  File format details: see FILEFORMAT.MD")
	fmt.Println()
}
