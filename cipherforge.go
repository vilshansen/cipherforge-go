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
	// Display help if no arguments provided
	if len(os.Args) < 2 {
		helpText := fmt.Sprintf(constants.HelpText, constants.Version, constants.GitCommit)
		fmt.Print(helpText)
		os.Exit(1)
	}

	// Global panic recovery for stability
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: %v\n", r)
		}
	}()

	// Parse flags and determine operation
	operation, inputPattern, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Resolve password as []byte to ensure it can be wiped from RAM
	password, err := resolvePassword(operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	// Securely overwrite the password in memory when main returns
	defer cryptoutils.ZeroBytes(password)

	// Identify all files matching the input pattern
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
			// Ensure we are only attempting to decrypt files with the correct extension
			if !strings.HasSuffix(inputFile, constants.FileExtension) {
				fmt.Fprintf(os.Stderr, "Skipping %s: missing %s extension\n",
					inputFile, constants.FileExtension)
				continue
			}

			// Generate output filename by stripping the extension
			outputFilePath = strings.TrimSuffix(inputFile, constants.FileExtension)

			// Prevent accidental overwrite if suffix stripping fails or output is empty
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

// resolvePassword handles both automated generation and secure terminal input
func resolvePassword(operation string) ([]byte, error) {
	switch operation {
	case "encrypt":
		securePass, err := cryptoutils.GenerateSecurePassword(constants.PasswordLength)
		if err != nil {
			return nil, err
		}
		// Print the generated password once so the user can record it
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

// readPasswordFromTerminal uses syscalls to read input without echoing to the screen
func readPasswordFromTerminal(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)

	// Set the terminal to raw mode for the duration of the password read
	fd := int(syscall.Stdin)
	bytePassword, err := term.ReadPassword(fd)
	fmt.Println() // Move cursor to next line after hidden input

	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return bytePassword, nil
}

// getParameters extracts the command line flags
func getParameters() (operation string, inputPattern string, err error) {
	encryptFlag := flag.String("e", "", "Encrypt file(s)")
	decryptFlag := flag.String("d", "", "Decrypt file(s)")

	flag.Parse()

	// Ensure exactly one operation is selected
	if (*encryptFlag != "" && *decryptFlag != "") || (*encryptFlag == "" && *decryptFlag == "") {
		return "", "", fmt.Errorf("you must provide exactly one flag: -e (encrypt) or -d (decrypt)")
	}

	if *encryptFlag != "" {
		return "encrypt", *encryptFlag, nil
	}
	return "decrypt", *decryptFlag, nil
}
