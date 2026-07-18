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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
	"github.com/vilshansen/cipherforge-go/internal/ui"
	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
	"golang.org/x/term"
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
// 44 chars × log₂(58) ≈ 257.7 bits ≥ 256-bit key strength.
const characterPool = "123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const passwordLength = 44

// main is the entry point — like Java's public static void main(String[] args).
// Go's main takes no arguments; use os.Args to access command-line arguments.
func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	// Parse command-line arguments.
	// Go pattern: functions return multiple values, with error as the last
	// return. Convention: if error is non-nil, other values are undefined.
	operation, inputPattern, userPassword, outputOverride, quiet, force, atomic, err := getParameters()
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err)) // %v formats any value (like toString())
		os.Exit(1)
	}

	// Expand glob patterns and validate input paths.
	inputFiles, err := expandInputPaths(inputPattern, operation)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	// Validation: stdin ("-") cannot be combined with other files.
	if len(inputFiles) > 1 {
		for _, f := range inputFiles {
			if f == "-" {
				ui.PrintError("stdin (-) cannot be combined with other input files")
				os.Exit(1)
			}
		}
	}
	// Validation: -o requires exactly one input file.
	if outputOverride != "" && len(inputFiles) > 1 {
		ui.PrintError("-o requires a single input file")
		os.Exit(1)
	}
	// Validation: stdin input requires an explicit output path.
	if inputFiles[0] == "-" && outputOverride == "" {
		ui.PrintError("stdin requires -o <output>")
		os.Exit(1)
	}

	// Resolve the password: use the user-supplied one, or generate/ask.
	password, err := resolvePassword(operation, userPassword)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
	// Ensure the password is wiped from memory when main() exits.
	// This defers to the VERY end of main's execution — after all files
	// are processed. The password is shared across all files in batch mode,
	// so we can't zero it between files.
	defer crypto.ZeroBytes(password)

	// Security warning: short user-supplied password + multiple files.
	// The v3 batch optimization means one Argon2id run covers all files.
	if operation == "encrypt" && userPassword != nil && len(userPassword) < 20 && len(inputFiles) > 1 {
		ui.PrintWarning(fmt.Sprintf(
			"Short password (%d chars) with %d files. The v3 batch optimisation derives\n"+
				"                all file keys from one Argon2id run — a weak password puts every\n"+
				"                output file at risk. Consider a longer password or encrypting\n"+
				"                files separately with different passwords.",
			len(userPassword), len(inputFiles)))
	}

	// For encryption, derive the master key ONCE and reuse for all files.
	// This is the two-tier key derivation optimization: one expensive
	// Argon2id call, then fast HKDF per file.
	//
	// Go note: `var masterKey []byte` declares a nil slice.
	// In the if-block below, it gets assigned the derived key.
	// The defer ensures it's zeroed when main() returns.
	var masterKey []byte
	if operation == "encrypt" {
		masterKey = crypto.DeriveMasterKey(password, format.DefaultArgon2Params())
		defer crypto.ZeroBytes(masterKey)
	}

	// Process each input file.
	// `for _, inputFile := range inputFiles` — the underscore discards the
	// index (like `for (String f : files)` in Java).
	var hasErrors bool
	for _, inputFile := range inputFiles {
		// Determine output path: use -o override, or derive from input name.
		outputFile := outputOverride
		if outputFile == "" {
			outputFile = deriveOutputPath(operation, inputFile)
		}
		// Errors are printed but don't stop batch processing.
		if err := processFile(operation, inputFile, outputFile, password, masterKey, quiet, force, atomic); err != nil {
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
func processFile(operation, inputFile, outputFile string, password, masterKey []byte, quiet, force, atomic bool) error {
	// os.Stat returns (FileInfo, error). If err == nil, the file exists.
	if outputFile != "-" && !force {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file %q already exists (use -f to overwrite)", outputFile)
		}
	}
	if operation == "encrypt" {
		return encryptFile(inputFile, outputFile, password, masterKey, quiet)
	}
	return decryptFile(inputFile, outputFile, password, quiet, atomic)
}

// encryptFile handles I/O setup for encryption and delegates to the Encrypter engine.
// On failure, the output file is automatically removed.
func encryptFile(inputFile, outputFile string, password, masterKey []byte, quiet bool) error {
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
	err := enc.Encrypt(in, out, nil) // nil = no progress callback

	if err == nil {
		succeeded = true
	}
	return err
}

// decryptFile handles I/O setup for decryption and delegates to the Decrypter engine.
// Stdin decryption is NOT supported (requires seekable input for trailer HMAC).
// Supports atomic mode: decrypt to temp file, rename on success.
func decryptFile(inputFile, outputFile string, password []byte, quiet, atomic bool) error {
	if inputFile == "-" {
		return fmt.Errorf("decrypt from stdin is not supported (seek required for trailer HMAC)")
	}

	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

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
	err = dec.Decrypt(in, out, nil)

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
		ui.PrintSuccess("Password accepted")
		return userPassword, nil
	}

	// Auto-generate a secure password for encryption.
	if operation == "encrypt" {
		p, err := crypto.GenerateSecurePassword(passwordLength, characterPool)
		if err != nil {
			return nil, err
		}
		fmt.Printf("%s\n", p) // Print password to stdout — user must save it
		fmt.Fprintf(os.Stderr, "cfo: Save this password — it cannot be recovered.\n")
		return p, nil
	}

	// Interactive password prompt for decryption (loop until non-empty).
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

// getParameters parses command-line arguments into structured form.
// Returns 8 values — unusual in Go but acceptable for a small CLI.
func getParameters() (string, []string, []byte, string, bool, bool, bool, error) {
	args := os.Args[1:] // Skip program name (os.Args[0])
	var encryptInputs []string
	var decryptInputs []string
	var explicitPassword []byte
	var outputFile string
	var quiet, force, atomic bool
	passwordSeen := false
	outputSeen := false

	// Manual argument parsing. Go's standard `flag` package handles flags
	// poorly with positional arguments, so we parse manually.
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			showHelp()
			os.Exit(0)
		case "-v", "--version":
			fmt.Printf("cfo %s\n", Version)
			os.Exit(0)
		case "-q", "--quiet":
			quiet = true
		case "-f", "--force":
			force = true
		case "-a", "--atomic":
			atomic = true
		case "-e":
			// Collect all non-flag arguments after -e. "-" is treated as stdin.
			i++
			for i < len(args) && (args[i] == "-" || args[i][0] != '-') {
				encryptInputs = append(encryptInputs, args[i])
				i++
			}
			i--
		case "-d":
			i++
			for i < len(args) && (args[i] == "-" || args[i][0] != '-') {
				decryptInputs = append(decryptInputs, args[i])
				i++
			}
			i--
		case "-o":
			if outputSeen {
				return "", nil, nil, "", false, false, false, fmt.Errorf("-o may only be specified once")
			}
			outputSeen = true
			if i+1 < len(args) && len(args[i+1]) > 0 && (args[i+1] == "-" || args[i+1][0] != '-') {
				i++
				outputFile = args[i]
			} else {
				return "", nil, nil, "", false, false, false, fmt.Errorf("-o requires an output filename")
			}
		case "-p":
			// -p alone = interactive prompt; -p <value> = explicit password
			if passwordSeen {
				return "", nil, nil, "", false, false, false, fmt.Errorf("-p may only be specified once")
			}
			passwordSeen = true
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				explicitPassword = []byte(args[i])
			}
		default:
			return "", nil, nil, "", false, false, false, fmt.Errorf("unknown argument: %s", args[i])
		}
	}

	// Auto-detect stdin: if no files given and stdin is piped, encrypt from stdin.
	if len(encryptInputs) == 0 && len(decryptInputs) == 0 {
		if !term.IsTerminal(int(syscall.Stdin)) {
			encryptInputs = []string{"-"}
		} else {
			return "", nil, nil, "", false, false, false, fmt.Errorf("provide exactly one flag: -e or -d")
		}
	}
	if len(decryptInputs) > 0 && decryptInputs[0] == "-" {
		return "", nil, nil, "", false, false, false, fmt.Errorf("decrypt from stdin is not supported (seek required for trailer HMAC)")
	}
	if len(encryptInputs) > 0 && len(decryptInputs) > 0 {
		return "", nil, nil, "", false, false, false, fmt.Errorf("provide exactly one flag: -e or -d")
	}

	op := "encrypt"
	inputs := encryptInputs
	if len(decryptInputs) > 0 {
		op = "decrypt"
		inputs = decryptInputs
	}

	// If -p was given without a value, prompt interactively.
	if passwordSeen && explicitPassword == nil {
		p, err := resolvePasswordInteractive(op)
		if err != nil {
			return "", nil, nil, "", false, false, false, err
		}
		explicitPassword = p
	}

	return op, inputs, explicitPassword, outputFile, quiet, force, atomic, nil
}

// resolvePasswordInteractive prompts for a password interactively.
// Encryption: prompt twice and confirm they match.
// Decryption: prompt once (correctness verified by HMAC later).
func resolvePasswordInteractive(op string) ([]byte, error) {
	if op == "encrypt" {
		for {
			p1, err := ui.ReadPasswordStarred("Enter password for encryption: ")
			if err != nil {
				return nil, err
			}
			if len(p1) == 0 {
				continue
			}
			// If not a terminal (piped input), skip confirmation.
			if !term.IsTerminal(int(syscall.Stdin)) {
				return p1, nil
			}
			p2, err := ui.ReadPasswordStarred("Confirm password: ")
			if err != nil {
				crypto.ZeroBytes(p1)
				return nil, err
			}
			// bytes.Equal is NOT constant-time — fine for local confirmation.
			if bytes.Equal(p1, p2) {
				crypto.ZeroBytes(p2)
				return p1, nil
			}
			crypto.ZeroBytes(p1)
			crypto.ZeroBytes(p2)
			fmt.Fprintln(os.Stderr, "cfo: Passwords do not match.")
		}
	}
	for {
		p, err := ui.ReadPasswordStarred("Enter password for decryption: ")
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			return p, nil
		}
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
	fmt.Println("  echo 'Hello' | cfo -e -o out.cfo   Encrypt from stdin")
	fmt.Println("  cfo -d file.cfo -o -               Decrypt to stdout")

	fmt.Println("\nNotes:")
	fmt.Println("  The auto-generated password is 44 characters — shown once, cannot be recovered.")
	fmt.Println("  Argon2id KDF uses 256 MiB memory per operation; each takes ~1 second.")
	fmt.Println("  The .cfo file reveals the original filename and approximate plaintext size")
	fmt.Println("  but does not hide the existence of encrypted data.")
	fmt.Println("  File format details: see FILEFORMAT.MD")
	fmt.Println()
}
