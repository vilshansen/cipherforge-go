package main

import (
	"bytes"
	"fmt"
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

const characterPool = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
const passwordLength = 55

func main() {
	if len(os.Args) < 2 {
		showHelp()
		os.Exit(1)
	}

	operation, inputPattern, userPassword, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	inputFiles, err := expandInputPaths(inputPattern, operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	password, err := resolvePassword(operation, userPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer crypto.ZeroBytes(password)

	for _, inputFile := range inputFiles {
		if err := processFile(operation, inputFile, password); err != nil {
			fmt.Fprintf(os.Stderr, "\nError processing %s: %v\n", inputFile, err)
		}
	}
}

func processFile(operation, inputFile string, password []byte) error {
	var outputFile string
	if operation == "encrypt" {
		outputFile = inputFile + ".cfo"
		return encryptFile(inputFile, outputFile, password)
	}

	if !strings.HasSuffix(inputFile, ".cfo") {
		return fmt.Errorf("missing .cfo extension")
	}
	outputFile = strings.TrimSuffix(inputFile, ".cfo")
	return decryptFile(inputFile, outputFile, password)
}

func encryptFile(inputFile, outputFile string, password []byte) error {
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
	prefix := fmt.Sprintf("Encrypting %s", filepath.Base(inputFile))

	enc := cipherforge.NewEncrypter(password)
	err = enc.Encrypt(in, out, func(done int64) {
		if total > 0 {
			ui.RunProgressBar(prefix, int((done*100)/total))
		}
	})

	if err == nil {
		ui.RunProgressBar(prefix, 100)
		fmt.Println()
		succeeded = true
	}
	return err
}

func decryptFile(inputFile, outputFile string, password []byte) error {
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
	prefix := fmt.Sprintf("Decrypting %s", filepath.Base(inputFile))

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(in, out, func(done int64) {
		if total > 0 {
			ui.RunProgressBar(prefix, int((done*100)/total))
		}
	})

	if err == nil {
		ui.RunProgressBar(prefix, 100)
		fmt.Println()
		succeeded = true
	}
	return err
}

func resolvePassword(operation string, userPassword []byte) ([]byte, error) {
	if userPassword != nil {
		if len(userPassword) == 0 {
			return nil, fmt.Errorf("password must not be empty")
		}
		if operation == "encrypt" {
			fmt.Printf("Using supplied password for encryption.\n")
		}
		return userPassword, nil
	}

	if operation == "encrypt" {
		p, err := crypto.GenerateSecurePassword(passwordLength, characterPool)
		if err != nil {
			return nil, err
		}
		fmt.Printf("Encryption password (save this — it cannot be recovered):\n%s\n", p)
		return p, nil
	}

	for {
		p, err := ui.ReadPasswordFromTerminal("Enter password for decryption: ")
		if err != nil {
			return nil, err
		}
		if len(p) > 0 {
			return p, nil
		}
		fmt.Fprintln(os.Stderr, "Error: Password cannot be empty.")
	}
}

func getParameters() (string, []string, []byte, error) {
	args := os.Args[1:]
	var encryptInputs []string
	var decryptInputs []string
	var explicitPassword []byte
	passwordSeen := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
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
		case "-p":
			if passwordSeen {
				return "", nil, nil, fmt.Errorf("-p may only be specified once")
			}
			passwordSeen = true
			if i+1 < len(args) && args[i+1][0] != '-' {
				i++
				explicitPassword = []byte(args[i])
			}
		default:
			return "", nil, nil, fmt.Errorf("unknown argument: %s", args[i])
		}
	}

	if (len(encryptInputs) > 0 && len(decryptInputs) > 0) || (len(encryptInputs) == 0 && len(decryptInputs) == 0) {
		return "", nil, nil, fmt.Errorf("provide exactly one flag: -e or -d")
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
			return "", nil, nil, err
		}
		explicitPassword = p
	}

	return op, inputs, explicitPassword, nil
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
		matches, _ := filepath.Glob(input)
		for _, match := range matches {
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
	fmt.Printf("Cipherforge v%s (commit: %s)\n", Version, GitCommit)
	fmt.Println("Usage: cfo -e <file> | -d <file> [-p password]")
}
