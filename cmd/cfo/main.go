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

var Version = "dev"
var GitCommit = "none"

// Clean pool: digits 1-9, uppercase A-Z minus I,O, lowercase a-z minus l.
// 58 unambiguous characters.  44 chars = log₂(58⁴⁴) ≈ 257.7 bits ≥ 256.
const characterPool = "123456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
const passwordLength = 44

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	operation, inputPattern, userPassword, outputOverride, quiet, force, atomic, err := getParameters()
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	inputFiles, err := expandInputPaths(inputPattern, operation)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}

	if outputOverride != "" && len(inputFiles) > 1 {
		ui.PrintError("-o requires a single input file")
		os.Exit(1)
	}

	password, err := resolvePassword(operation, userPassword)
	if err != nil {
		ui.PrintError(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
	defer crypto.ZeroBytes(password)

	// Warn when using a short user-supplied password with multiple files: the
	// v3 batch optimisation means the Argon2id cost is paid once, not per file,
	// so an attacker gets N files' keys for the price of one Argon2id guess.
	if operation == "encrypt" && userPassword != nil && len(userPassword) < 20 && len(inputFiles) > 1 {
		ui.PrintWarning(fmt.Sprintf(
			"Short password (%d chars) with %d files. The v3 batch optimisation derives\n"+
				"                all file keys from one Argon2id run — a weak password puts every\n"+
				"                output file at risk. Consider a longer password or encrypting\n"+
				"                files separately with different passwords.",
			len(userPassword), len(inputFiles)))
	}

	// For encryption, derive master key once and reuse for all files (performance optimization)
	var masterKey []byte
	if operation == "encrypt" {
		masterKey = crypto.DeriveMasterKey(password, format.DefaultArgon2Params())
		defer crypto.ZeroBytes(masterKey)
	}

	for _, inputFile := range inputFiles {
		outputFile := outputOverride
		if outputFile == "" {
			outputFile = deriveOutputPath(operation, inputFile)
		}
		if err := processFile(operation, inputFile, outputFile, password, masterKey, quiet, force, atomic); err != nil {
			ui.PrintError(fmt.Sprintf("Failed to process %s: %v", inputFile, err))
		}
	}
}

func deriveOutputPath(operation, inputFile string) string {
	if operation == "encrypt" {
		return inputFile + ".cfo"
	}
	return strings.TrimSuffix(inputFile, ".cfo")
}

func processFile(operation, inputFile, outputFile string, password, masterKey []byte, quiet, force, atomic bool) error {
	if operation == "decrypt" && !strings.HasSuffix(inputFile, ".cfo") {
		return fmt.Errorf("missing .cfo extension")
	}
	if !force {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file %q already exists (use -f to overwrite)", outputFile)
		}
	}
	if operation == "encrypt" {
		return encryptFile(inputFile, outputFile, password, masterKey, quiet)
	}
	return decryptFile(inputFile, outputFile, password, quiet, atomic)
}

func encryptFile(inputFile, outputFile string, password, masterKey []byte, quiet bool) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	succeeded := false
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(outputFile)
		}
	}()

	if !quiet {
		fmt.Println(filepath.Base(inputFile))
	}

	var enc *cipherforge.Encrypter
	if masterKey != nil {
		enc = cipherforge.NewEncrypterWithMasterKey(password, masterKey)
	} else {
		enc = cipherforge.NewEncrypter(password)
	}
	err = enc.Encrypt(in, out, nil)

	if err == nil {
		succeeded = true
	}
	return err
}

func decryptFile(inputFile, outputFile string, password []byte, quiet, atomic bool) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer in.Close()

	// When --atomic is set, decrypt into a temporary file in the same directory
	// and rename on success.  This prevents partial plaintext from ever
	// appearing at the final output path if decryption fails mid-stream.
	writePath := outputFile
	var out *os.File
	if atomic {
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

	succeeded := false
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(writePath)
		}
	}()

	if !quiet {
		fmt.Println(filepath.Base(inputFile))
	}

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(in, out, nil)

	if err == nil {
		succeeded = true
	}

	// Atomically rename the temp file to the final output path.
	if atomic && succeeded {
		out.Close()
		if err := os.Rename(writePath, outputFile); err != nil {
			os.Remove(writePath)
			return fmt.Errorf("atomic rename failed: %w", err)
		}
	}
	return err
}

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

	if operation == "encrypt" {
		p, err := crypto.GenerateSecurePassword(passwordLength, characterPool)
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

func getParameters() (string, []string, []byte, string, bool, bool, bool, error) {
	args := os.Args[1:]
	var encryptInputs []string
	var decryptInputs []string
	var explicitPassword []byte
	var outputFile string
	var quiet, force, atomic bool
	passwordSeen := false
	outputSeen := false

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
			i++
			for i < len(args) && args[i][0] != '-' {
				encryptInputs = append(encryptInputs, args[i])
				i++
			}
			i--
		case "-d":
			i++
			for i < len(args) && args[i][0] != '-' {
				decryptInputs = append(decryptInputs, args[i])
				i++
			}
			i--
		case "-o":
			if outputSeen {
				return "", nil, nil, "", false, false, false, fmt.Errorf("-o may only be specified once")
			}
			outputSeen = true
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				outputFile = args[i]
			} else {
				return "", nil, nil, "", false, false, false, fmt.Errorf("-o requires an output filename")
			}
		case "-p":
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

	if (len(encryptInputs) > 0 && len(decryptInputs) > 0) || (len(encryptInputs) == 0 && len(decryptInputs) == 0) {
		return "", nil, nil, "", false, false, false, fmt.Errorf("provide exactly one flag: -e or -d")
	}

	op := "encrypt"
	inputs := encryptInputs
	if len(decryptInputs) > 0 {
		op = "decrypt"
		inputs = decryptInputs
	}

	if passwordSeen && explicitPassword == nil {
		p, err := resolvePasswordInteractive(op)
		if err != nil {
			return "", nil, nil, "", false, false, false, err
		}
		explicitPassword = p
	}

	return op, inputs, explicitPassword, outputFile, quiet, force, atomic, nil
}

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
			if !term.IsTerminal(int(syscall.Stdin)) {
				return p1, nil
			}
			p2, err := ui.ReadPasswordStarred("Confirm password: ")
			if err != nil {
				crypto.ZeroBytes(p1)
				return nil, err
			}
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

func expandInputPaths(inputs []string, op string) ([]string, error) {
	var files []string
	for _, input := range inputs {
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

func showHelp() {
	fmt.Printf("cfo %s — encrypt and decrypt files with XChaCha20-Poly1305 and Argon2id.\n\n", Version)

	fmt.Println("Usage: cfo -e <file...>")
	fmt.Println("       cfo -d <file...>")
	fmt.Println("       cfo -e <file> -o <out>.cfo")
	fmt.Println("       cfo -e <file...> -p <pwd>")
	fmt.Println("       cfo -e <file...> -p")

	fmt.Println("\nFlags:")
	fmt.Println("  -e                Encrypt — each input file produces <name>.cfo")
	fmt.Println("  -d                Decrypt — each .cfo file produces its original name")
	fmt.Println("  -o <file>         Output filename (requires a single input file)")
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

	fmt.Println("\nNotes:")
	fmt.Println("  The auto-generated password is 44 characters — shown once, cannot be recovered.")
	fmt.Println("  Argon2id KDF uses 256 MiB memory per operation; each takes ~1 second.")
	fmt.Println("  The .cfo file reveals the original filename and approximate plaintext size")
	fmt.Println("  but does not hide the existence of encrypted data.")
	fmt.Println("  File format details: see FILEFORMAT.MD")
	fmt.Println()
}
