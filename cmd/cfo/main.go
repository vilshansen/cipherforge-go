// Command cfo is the Cipherforge CLI — a tool for encrypting and decrypting
// files using AES-256-GCM and HKDF-SHA256.
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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/vilshansen/cipherforge-go/internal/armor"
	"github.com/vilshansen/cipherforge-go/internal/crypto"
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
var Version = "7.2.0"
var GitCommit = "none"

// init wires the application version into the ASCII-armor Version header so
// armored output identifies the emitting app version, mirroring GPG's armor.
func init() {
	armor.Version = "Version: Cipherforge " + Version
}

// Generated secrets come from crypto.GenerateSecret: crypto.SecretLength random
// characters drawn from crypto.CharacterPool and grouped by crypto.GroupSecret.
// The separators are part of the secret, so it is used exactly as displayed.

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

	// Resolve the secret. When the ciphertext is written to stdout the generated
	// secret must not share that stream (see resolvePassword).
	password, err := resolvePassword(cfg.Operation, cfg.Output == "-")
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
	defer crypto.ZeroBytes(password)

	var hasErrors bool
	for _, inputFile := range inputFiles {
		outputFile := cfg.Output
		if outputFile == "" {
			outputFile = deriveOutputPath(cfg.Operation, inputFile)
		}
		if err := processFile(cfg.Operation, inputFile, outputFile, password, cfg.Quiet, cfg.Force, cfg.Base64); err != nil {
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
func processFile(operation, inputFile, outputFile string, password []byte, quiet, force, base64 bool) error {
	// os.Stat returns (FileInfo, error). If err == nil, the file exists.
	if outputFile != "-" && !force {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file %q already exists (use -f to overwrite)", outputFile)
		}
	}
	if operation == "encrypt" {
		return encryptFile(inputFile, outputFile, password, quiet, base64)
	}
	return decryptFile(inputFile, outputFile, password, quiet, base64)
}

// encryptFile handles I/O setup for encryption and delegates to the Encrypter engine.
// When base64 is true, the output is wrapped in GPG-style base64 armor
// (BEGIN/END markers, 68-char lines) for easy copy/paste. On failure, the
// output file is automatically removed.
func encryptFile(inputFile, outputFile string, password []byte, quiet, base64 bool) error {
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

	// Always write to a temporary file in the destination directory and
	// atomically rename it into place on success, so a failed or interrupted
	// encryption never leaves a partial output file at the final path.
	var out *os.File
	writePath := outputFile
	if outputFile == "-" {
		out = os.Stdout
	} else {
		var err error
		out, err = os.CreateTemp(filepath.Dir(outputFile), ".cfo-encrypt-*")
		if err != nil {
			return fmt.Errorf("cannot create temp file for encryption: %w", err)
		}
		writePath = out.Name()
	}

	// Automatic cleanup on failure: the closure captures `succeeded` and
	// `writePath` by reference. If we return with an error, the defer
	// removes the temporary file.
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
		if inputFile == "-" {
			fmt.Fprintln(os.Stderr, "(stdin)")
		} else {
			fmt.Fprintln(os.Stderr, filepath.Base(inputFile))
		}
	}

	enc := cipherforge.NewEncrypter(password)

	// Wrap output in ASCII armor if requested: base64 wrapped at 68 cols
	// with BEGIN/END markers (GPG-style).
	var writer io.Writer = out
	var armorCloser io.WriteCloser
	if base64 {
		armorCloser = armor.EncodeWriter(out)
		writer = armorCloser
	}

	err := enc.Encrypt(in, writer, nil) // nil = no progress callback

	// Must close the armor writer to flush remaining bytes and emit the footer.
	if armorCloser != nil {
		if closeErr := armorCloser.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}

	if err == nil {
		succeeded = true
		// Atomically rename the temp file to the final output path.
		// os.Rename is atomic when src and dst are on the same filesystem.
		if outputFile != "-" {
			out.Close() // Must close before rename on Windows
			if rerr := os.Rename(writePath, outputFile); rerr != nil {
				os.Remove(writePath)
				return fmt.Errorf("atomic rename failed: %w", rerr)
			}
		}
	}
	return err
}

// decryptFile handles I/O setup for decryption and delegates to the Decrypter engine.
// Stdin decryption is NOT supported (requires seekable input for trailer HMAC).
// Base64 decryption reads the entire input into memory, decodes it, and wraps
// the result in a seekable bytes.Reader — suitable for copy/paste workflows
// with reasonably-sized files.
//
// Plaintext is staged in a temporary file and published only once the entire
// payload has authenticated: a file target is atomically renamed into place, and
// stdout receives the staged bytes on success.
func decryptFile(inputFile, outputFile string, password []byte, quiet, base64 bool) error {
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

		decoded, err := armor.DecodeBytes(raw)
		if err != nil {
			return fmt.Errorf("decoding base64 input: %w", err)
		}
		reader = bytes.NewReader(decoded)
	} else {
		reader = in
	}

	// Decrypted plaintext is always staged in a temporary file and published only
	// after the whole payload has authenticated:
	//   - file target: atomically renamed into place, so a failed or interrupted
	//     decryption never leaves partial plaintext at the final path;
	//   - stdout: streamed out on success only, so a ciphertext whose later
	//     segment was modified never exposes the earlier plaintext segments to
	//     whatever is consuming stdout.
	// os.CreateTemp is like Java's Files.createTempFile(). For a file target the
	// temp file lives in the destination directory because rename across
	// filesystems is not atomic.
	var out *os.File
	if outputFile == "-" {
		out, err = os.CreateTemp("", ".cfo-stdout-*")
	} else {
		out, err = os.CreateTemp(filepath.Dir(outputFile), ".cfo-decrypt-*")
	}
	if err != nil {
		return fmt.Errorf("cannot create temp file for atomic decrypt: %w", err)
	}
	writePath := out.Name()

	// Automatic cleanup unless the staged plaintext was successfully published.
	published := false
	defer func() {
		if !published {
			out.Close()
			os.Remove(writePath)
		}
	}()

	if !quiet && outputFile != "-" {
		fmt.Fprintln(os.Stderr, filepath.Base(inputFile))
	}

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(reader, out, nil)

	// A mistyped secret is by far the most likely cause of an authentication
	// failure, and the trailer's key-commitment tag lets us test nearby variants
	// without reading the payload. A variant that authenticates is not a guess —
	// it reproduces a 256-bit tag — so continuing with it is safe.
	if err != nil && isAuthenticationFailure(err) {
		if corrected, rerr := cipherforge.RepairSecret(reader, password); rerr == nil {
			ui.PrintWarning(fmt.Sprintf(
				"The supplied secret did not authenticate %s, but a one-character correction does. "+
					"Update your stored copy.", filepath.Base(inputFile)))
			fmt.Fprintf(os.Stderr, "cfo: corrected secret: %s\n", corrected)
			defer crypto.ZeroBytes(corrected)

			// Rewind both sides: the search moved the input, and the failed attempt
			// may have left partial plaintext in the staged output file.
			if _, serr := reader.Seek(0, io.SeekStart); serr != nil {
				return err
			}
			if terr := out.Truncate(0); terr != nil {
				return err
			}
			if _, serr := out.Seek(0, io.SeekStart); serr != nil {
				return err
			}

			dec = cipherforge.NewDecrypter(corrected)
			err = dec.Decrypt(reader, out, nil)
		}
	}

	if err != nil {
		return err
	}

	// The entire payload authenticated. Close the staged file before publishing
	// it: the copy and the rename both read it back, and Windows will not rename
	// a file that is still open.
	if err := out.Close(); err != nil {
		return err
	}

	// Publish the staged plaintext.
	if outputFile == "-" {
		if err := copyFileTo(os.Stdout, writePath); err != nil {
			return err
		}
		os.Remove(writePath)
		published = true
		return nil
	}

	// os.Rename is atomic when src and dst are on the same filesystem.
	if err := os.Rename(writePath, outputFile); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	published = true
	return nil
}

// isAuthenticationFailure reports whether err means the derived key did not
// match the file — which is what a mistyped secret looks like, and the only
// case where searching for a corrected secret can help.
func isAuthenticationFailure(err error) bool {
	return errors.Is(err, cipherforge.ErrAuthenticationFailed) ||
		errors.Is(err, cipherforge.ErrKeyCommitmentFailed)
}

// copyFileTo copies the contents of the file at path to w. It is used to release
// staged plaintext to stdout only once the complete ciphertext has
// authenticated, so a modified segment cannot leak earlier plaintext.
func copyFileTo(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(w, f)
	return err
}

// resolvePassword generates a secret for encryption or prompts for one during decryption.
//
// ciphertextToStdout reports whether the encrypted output is itself destined for
// stdout (-o -). In that case the generated secret is written to stderr instead:
// sharing one stream would leave the secret sitting next to the ciphertext it
// protects, so anyone who captured the stream could decrypt it.
func resolvePassword(operation string, ciphertextToStdout bool) ([]byte, error) {
	if operation == "encrypt" {
		p, err := crypto.GenerateSecret()
		if err != nil {
			return nil, err
		}
		secretDest := os.Stdout
		if ciphertextToStdout {
			secretDest = os.Stderr
		}
		fmt.Fprintf(secretDest, "%s\n", p)
		fmt.Fprintf(os.Stderr, "cfo: Save this generated secret — it cannot be recovered.\n")
		return p, nil
	}

	for {
		p, err := ui.ReadPasswordStarred("Enter generated secret for decryption: ")
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			return p, nil
		}
		ui.PrintError("Generated secret cannot be empty")
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
	// Mirror the TUI menu header: "cfo <version> (<commit>) — ...".
	verLine := fmt.Sprintf("cfo %s", Version)
	if GitCommit != "none" && GitCommit != "" {
		verLine += fmt.Sprintf(" (%s)", GitCommit)
	}
	verLine += " — encrypt and decrypt files with AES-256-GCM and HKDF-SHA256."
	fmt.Printf("%s\n\n", verLine)

	fmt.Println("Usage: cfo -e <file...>")
	fmt.Println("       cfo -d <file...>")
	fmt.Println("       cfo -e <file> -o <out>.cfo")
	fmt.Println("       cfo -e -o <out>.cfo           (reads from stdin)")

	fmt.Println("\nFlags:")
	fmt.Println("  -e                Encrypt — each input file produces <name>.cfo")
	fmt.Println("  -d                Decrypt — each .cfo file produces its original name")
	fmt.Println("  -o <file>         Output filename (use - for stdout)")
	fmt.Println("  -b, --base64      Wrap encrypted output in base64 armor (BEGIN/END markers,")
	fmt.Println("                    68-char lines) for easy copy/paste; also accepts armored")
	fmt.Println("                    input for decryption")
	fmt.Println("  -i, --interactive Launch the full-screen terminal UI")
	fmt.Println("  -q, --quiet       Suppress all non-error output")
	fmt.Println("  -f, --force       Overwrite output file if it already exists")
	fmt.Println("  -h, --help        Show this help text")
	fmt.Println("  -v, --version     Show version information")

	fmt.Println("\nExamples:")
	fmt.Println("  cfo -e document.pdf                Encrypt document.pdf → document.pdf.cfo")
	fmt.Println("  cfo -e *.txt                       Encrypt all .txt files (skips .cfo files)")
	fmt.Println("  cfo -d document.pdf.cfo            Decrypt (prompts for the generated secret)")
	fmt.Println("  cfo -d *.cfo                       Decrypt all .cfo files")
	fmt.Println("  cfo -e backup.tar -o archive.cfo   Encrypt to a custom output name")
	fmt.Println("  cfo -e secret.txt --base64         Encrypt to armored base64 .cfo output")
	fmt.Println("  echo 'Hello' | cfo -e -o out.cfo   Encrypt from stdin")
	fmt.Println("  cfo -d file.cfo -o -               Decrypt to stdout")
	fmt.Println("  cfo                                 Launch the terminal UI (no flags)")

	fmt.Println("\nNotes:")
	fmt.Println("  The generated secret is 45 characters shown in dash-separated groups of")
	fmt.Println("  five — copy it exactly as displayed; it cannot be recovered.")
	fmt.Println("  With -o -, the generated secret is written to stderr so that it never")
	fmt.Println("  shares the stdout stream that carries the ciphertext.")
	fmt.Println("  Keys are derived per file with HKDF-SHA256; there is no password KDF to tune.")
	fmt.Println("  The .cfo file reveals the original filename and approximate plaintext size")
	fmt.Println("  but does not hide the existence of encrypted data.")
	fmt.Println("  File format details: see FILEFORMAT.MD")
	fmt.Println()
}
