package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
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

	operation, inputPattern, userPassword, outputOverride, quiet, force, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	inputFiles, err := expandInputPaths(inputPattern, operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if outputOverride != "" && len(inputFiles) > 1 {
		fmt.Fprintf(os.Stderr, "Error: -o requires a single input file\n")
		os.Exit(1)
	}

	password, err := resolvePassword(operation, userPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer crypto.ZeroBytes(password)

	for _, inputFile := range inputFiles {
		outputFile := outputOverride
		if outputFile == "" {
			outputFile = deriveOutputPath(operation, inputFile)
		}
		if err := processFile(operation, inputFile, outputFile, password, quiet, force); err != nil {
			fmt.Fprintf(os.Stderr, "\nError processing %s: %v\n", inputFile, err)
		}
	}
}

func deriveOutputPath(operation, inputFile string) string {
	if operation == "encrypt" {
		return inputFile + ".cfo"
	}
	return strings.TrimSuffix(inputFile, ".cfo")
}

func formatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for nn := n / unit; nn >= unit && exp < 3; nn /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}

func processFile(operation, inputFile, outputFile string, password []byte, quiet, force bool) error {
	if operation == "decrypt" && !strings.HasSuffix(inputFile, ".cfo") {
		return fmt.Errorf("missing .cfo extension")
	}
	if !force {
		if _, err := os.Stat(outputFile); err == nil {
			return fmt.Errorf("output file %q already exists (use -f to overwrite)", outputFile)
		}
	}
	if operation == "encrypt" {
		return encryptFile(inputFile, outputFile, password, quiet)
	}
	return decryptFile(inputFile, outputFile, password, quiet)
}

func encryptFile(inputFile, outputFile string, password []byte, quiet bool) error {
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

	info, _ := in.Stat()
	total := info.Size()
	prefix := fmt.Sprintf("Encrypting %s (%s)", filepath.Base(inputFile), formatSize(total))

	enc := cipherforge.NewEncrypter(password)
	err = enc.Encrypt(in, out, func(done int64) {
		if !quiet && total > 0 {
			ui.RunProgressBar(prefix, int((done*100)/total))
		}
	})

	if err == nil {
		if !quiet {
			ui.RunProgressBar(prefix, 100)
			fmt.Println()
		}
		succeeded = true
		if !quiet {
			outInfo, _ := os.Stat(outputFile)
			fmt.Printf("  %s  →  %s  (%s)\n", filepath.Base(inputFile),
				filepath.Base(outputFile), formatSize(outInfo.Size()))
		}
	}
	return err
}

func decryptFile(inputFile, outputFile string, password []byte, quiet bool) error {
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

	info, _ := in.Stat()
	fileSize := info.Size()
	prefix := fmt.Sprintf("Decrypting %s (%s)", filepath.Base(inputFile), formatSize(fileSize))

	// Estimate plaintext size for accurate progress bar.
	estimatedTotal := fileSize
	headerSize := int64(52) // v1 default
	if fileSize >= 40 {
		if _, err := in.Seek(8, io.SeekStart); err == nil {
			var versionBuf [4]byte
			if _, err := io.ReadFull(in, versionBuf[:]); err == nil {
				if binary.BigEndian.Uint32(versionBuf[:]) >= 2 {
					headerSize = 64
				}
			}
		}
		if _, err := in.Seek(-40, io.SeekEnd); err == nil {
			var trailerHead [8]byte
			if _, err := io.ReadFull(in, trailerHead[:]); err == nil {
				segCount := int64(binary.BigEndian.Uint64(trailerHead[:]))
				estimatedTotal = fileSize - headerSize - 40 - segCount*24
			}
		}
		in.Seek(0, io.SeekStart)
	}
	if estimatedTotal <= 0 {
		estimatedTotal = 1
	}

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(in, out, func(done int64) {
		if !quiet && estimatedTotal > 0 {
			ui.RunProgressBar(prefix, int((done*100)/estimatedTotal))
		}
	})

	if err == nil {
		if !quiet {
			ui.RunProgressBar(prefix, 100)
			fmt.Println()
		}
		succeeded = true
	}
	return err
}

func resolvePassword(operation string, userPassword []byte) ([]byte, error) {
	if userPassword != nil {
		if len(userPassword) == 0 {
			return nil, fmt.Errorf("password must not be empty")
		}
		if len(userPassword) < 12 {
			fmt.Fprintf(os.Stderr, "Warning: short password (%d chars).  Consider a longer one.\n\n",
				len(userPassword))
		}
		fmt.Printf("  Supplied password accepted.\n\n")
		return userPassword, nil
	}

	if operation == "encrypt" {
		p, err := crypto.GenerateSecurePassword(passwordLength, characterPool)
		if err != nil {
			return nil, err
		}
		fmt.Println()
		fmt.Println("  ┌────────────────────────────────────────────────┐")
		fmt.Println("  │              ENCRYPTION PASSWORD               │")
		fmt.Println("  │      Save this -- it cannot be recovered.      │")
		fmt.Println("  ├────────────────────────────────────────────────┤")
		fmt.Printf("  │  %s  │\n", p)
		fmt.Println("  └────────────────────────────────────────────────┘")
		fmt.Println()
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
		fmt.Fprintln(os.Stderr, "Error: Password cannot be empty.")
	}
}

func getParameters() (string, []string, []byte, string, bool, bool, error) {
	args := os.Args[1:]
	var encryptInputs []string
	var decryptInputs []string
	var explicitPassword []byte
	var outputFile string
	var quiet, force bool
	passwordSeen := false
	outputSeen := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			showHelp()
			os.Exit(0)
		case "-v", "--version":
			fmt.Printf("Cipherforge v%s (commit: %s)\n", Version, GitCommit)
			os.Exit(0)
		case "-q", "--quiet":
			quiet = true
		case "-f", "--force":
			force = true
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
				return "", nil, nil, "", false, false, fmt.Errorf("-o may only be specified once")
			}
			outputSeen = true
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				outputFile = args[i]
			} else {
				return "", nil, nil, "", false, false, fmt.Errorf("-o requires an output filename")
			}
		case "-p":
			if passwordSeen {
				return "", nil, nil, "", false, false, fmt.Errorf("-p may only be specified once")
			}
			passwordSeen = true
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				explicitPassword = []byte(args[i])
			}
		default:
			return "", nil, nil, "", false, false, fmt.Errorf("unknown argument: %s", args[i])
		}
	}

	if (len(encryptInputs) > 0 && len(decryptInputs) > 0) || (len(encryptInputs) == 0 && len(decryptInputs) == 0) {
		return "", nil, nil, "", false, false, fmt.Errorf("provide exactly one flag: -e or -d")
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
			return "", nil, nil, "", false, false, err
		}
		explicitPassword = p
	}

	return op, inputs, explicitPassword, outputFile, quiet, force, nil
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
			fmt.Fprintln(os.Stderr, "Error: Passwords do not match.")
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
	fmt.Printf("Cipherforge v%s (commit: %s)\n\n", Version, GitCommit)
	fmt.Print("Encrypt and decrypt files using XChaCha20-Poly1305 and Argon2id key derivation.\n\n")
	fmt.Println("Usage:")
	fmt.Println("  cfo -e <file...>              Encrypt one or more files")
	fmt.Println("  cfo -d <file...>              Decrypt one or more .cfo files")
	fmt.Println("  cfo -e <file> -o <out>.cfo    Encrypt to a specific output file")
	fmt.Println("  cfo -e <file...> -p <pwd>     Encrypt with an explicit password")
	fmt.Println("  cfo -e <file...> -p           Encrypt with an interactive password prompt")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -e         Encrypt. Each input file produces <name>.cfo")
	fmt.Println("  -d         Decrypt. Each .cfo file produces its original name")
	fmt.Println("  -o <file>  Output filename (requires a single input file)")
	fmt.Println("  -p [pwd]   Supply a password. Without -p, encryption auto-generates one;")
	fmt.Println("             decryption prompts interactively.")
	fmt.Println("  -q, --quiet    Suppress progress bar and summary output")
	fmt.Println("  -f, --force    Overwrite output file if it already exists")
	fmt.Println("  -h, --help     Show this help text")
	fmt.Println("  -v, --version  Show version information")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  cfo -e document.pdf                 Encrypt document.pdf → document.pdf.cfo")
	fmt.Println("                                      (random password, printed once)")
	fmt.Println("  cfo -e *.txt -p mysecret            Encrypt all .txt files (skips .cfo files)")
	fmt.Println("  cfo -d document.pdf.cfo             Decrypt (prompts for password)")
	fmt.Println("  cfo -d *.cfo -p mysecret            Decrypt all .cfo files")
	fmt.Println("  cfo -e backup.tar -o archive.cfo    Encrypt to a custom output name")
	fmt.Println()
	fmt.Println("Notes:")
	fmt.Println("  • The auto-generated password is 44 characters long and is shown")
	fmt.Println("    only once. Save it — it cannot be recovered.")
	fmt.Println("  • Argon2id KDF uses 1 GiB of memory per operation; encryption and")
	fmt.Println("    decryption each take several seconds.")
	fmt.Println("  • The .cfo file reveals the original filename and approximate plaintext")
	fmt.Println("    size. It does not hide the existence of encrypted data.")
	fmt.Println("  • File format details: see FILEFORMAT.MD")
}
