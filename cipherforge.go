package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"github.com/vilshansen/cipherforge-go/fileutils"
	"golang.org/x/term"
)

func main() {
	// Standard entry-point check: if no flags or arguments are passed,
	// show the full technical documentation defined in constants.
	if len(os.Args) < 2 {
		helpText := fmt.Sprintf(constants.HelpText, constants.Version, constants.GitCommit)
		fmt.Print(helpText)
		os.Exit(1)
	}

	// Global panic recovery to ensure the terminal state is preserved
	// and helpful errors are shown even during catastrophic failures.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: %v\n", r)
		}
	}()

	operation, inputPattern, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Password is held as a byte slice to prevent it from being interned
	// in the Go string heap, allowing us to manually clear it later.
	password, err := resolvePassword(operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// CRITICAL: Ensure the password is zeroed out in RAM as soon as the
	// program finishes processing the file queue.
	defer cryptoutils.ZeroBytes(password)

	// wildcard/glob expansion allows for batch processing (e.g., *.txt)
	inputFiles, err := fileutils.ExpandInputPath(inputPattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	for _, inputFile := range inputFiles {
		var outputFilePath string

		if operation == "encrypt" {
			outputFilePath = inputFile + constants.FileExtension
			err = fileutils.EncryptFile(inputFile, outputFilePath, password)
		} else {
			// Decryption Safety: Check extension before attempting Argon2id key derivation.
			if !strings.HasSuffix(inputFile, constants.FileExtension) {
				fmt.Fprintf(os.Stderr, "Skipping %s: missing %s extension\n",
					inputFile, constants.FileExtension)
				continue
			}

			outputFilePath = strings.TrimSuffix(inputFile, constants.FileExtension)

			// Logic guard: If for some reason the suffix trim fails,
			// append .decrypted to avoid overwriting the source encrypted file.
			if outputFilePath == inputFile || outputFilePath == "" {
				outputFilePath = outputFilePath + ".decrypted"
			}

			err = fileutils.DecryptFile(inputFile, outputFilePath, password)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError processing %s: %v\n", inputFile, err)
			continue
		}
	}
}

// resolvePassword bifurcates the workflow: encryption generates a new, high-entropy
// password, while decryption prompts for manual entry.
func resolvePassword(operation string) ([]byte, error) {
	switch operation {
	case "encrypt":
		securePass, err := cryptoutils.GenerateSecurePassword(constants.PasswordLength)
		if err != nil {
			return nil, err
		}
		// The only time the password is shown in plaintext.
		fmt.Printf("Your secure, auto-generated password used for encryption:\n%s\n", securePass)
		return securePass, nil

	case "decrypt":
		for {
			p, err := readPasswordFromTerminal("Enter password for decryption: ")
			if err != nil {
				return nil, err
			}

			if len(p) > 0 {
				return p, nil
			}
			fmt.Fprintln(os.Stderr, "Error: Password cannot be empty. Please try again.")
		}
	}
	return nil, fmt.Errorf("internal error: invalid operation")
}

// readPasswordFromTerminal disables terminal local-echo using ioctl/syscalls,
// preventing the password from appearing on the screen or in shell history.
func readPasswordFromTerminal(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)

	// Check if Stdin is actually a terminal
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stdout, prompt)
		bytePassword, err := term.ReadPassword(fd)
		fmt.Println()
		return bytePassword, err
	}

	// Fallback for automation: Read from Stdin directly (pipes/redirection)
	var password string
	_, err := fmt.Scanln(&password)
	return []byte(strings.TrimSpace(password)), err
}

// getParameters enforces mutually exclusive flags.
func getParameters() (operation string, inputPattern string, err error) {
	encryptFlag := flag.String("e", "", "Encrypt file(s)")
	decryptFlag := flag.String("d", "", "Decrypt file(s)")

	flag.Parse()

	// Validation: The user must intend to either encrypt OR decrypt, never both or neither.
	if (*encryptFlag != "" && *decryptFlag != "") || (*encryptFlag == "" && *decryptFlag == "") {
		return "", "", fmt.Errorf("you must provide exactly one flag: -e (encrypt) or -d (decrypt)")
	}

	if *encryptFlag != "" {
		return "encrypt", *encryptFlag, nil
	}
	return "decrypt", *decryptFlag, nil
}
