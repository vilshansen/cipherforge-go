package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/cryptoutils"
	"github.com/vilshansen/cipherforge-go/fileutils"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		helpText := fmt.Sprintf(constants.HelpText, constants.Version, constants.GitCommit)
		fmt.Print(helpText)
		os.Exit(1)
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal error: %v\n", r)
		}
	}()

	operation, inputPattern, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting parameters: %v\n", err)
		os.Exit(1)
	}

	password, err := resolvePassword(operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting password: %v\n", err)
		os.Exit(1)
	}

	inputFiles, err := fileutils.ExpandInputPath(inputPattern)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting file input path: %v\n", err)
		os.Exit(1)
	}

	// Behandl hver fil
	for _, inputFile := range inputFiles {

		// Bestem outputfilnavnet baseret på inputfilnavnet og outputmappen
		var currentOutputFile string

		// Hvis flere filer, brug outputDir som mappe og konstruer filnavn
		if operation == "encrypt" {
			currentOutputFile = filepath.Join(filepath.Dir(inputFile), filepath.Base(inputFile)+".cfo")
			fmt.Printf("\rEncrypting %s -> %s", inputFile, currentOutputFile)
		} else {
			currentOutputFile = filepath.Join(filepath.Dir(inputFile), strings.TrimSuffix(filepath.Base(inputFile), ".cfo"))
			fmt.Printf("\rDecrypting %s -> %s", inputFile, currentOutputFile)
		}

		_, err := os.Stat(inputFile)
		if errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, " (input file not found, skipping)\n")
			continue // Spring denne fil over og fortsæt
		}

		_, err = os.Stat(currentOutputFile)
		// If err is nil, the file/path exists.
		if err == nil {
			fmt.Fprintf(os.Stderr, " (output file exists, skipping)\n")
			continue // Spring denne fil over og fortsæt
		}

		fmt.Println()

		switch operation {
		case "encrypt":
			if err := fileutils.EncryptFile(inputFile, currentOutputFile, password); err != nil {
				fmt.Fprintf(os.Stderr, "Error encrypting %s: %v\n", inputFile, err)
			}
		case "decrypt":
			if err := fileutils.DecryptFile(inputFile, currentOutputFile, password); err != nil {
				fmt.Fprintf(os.Stderr, "Error decrypting %s: %v\n", inputFile, err)
			}
		default:
			fmt.Fprintf(os.Stderr, "invalid operation. Use -e (encrypt) or -d (decrypt)")
		}
	}
	fmt.Println()
}

// Helper to read password securely without echoing
func readPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)
	// Get terminal file descriptor for secure reading
	fd := int(syscall.Stdin)
	bytePassword, err := term.ReadPassword(fd)
	fmt.Println() // Print newline after secure input

	if err != nil {
		return "", err
	}
	// Use TrimSpace to clean up any potential leading/trailing whitespace
	return strings.TrimSpace(string(bytePassword)), nil
}

// Handles interactive password prompting and generation logic
func resolvePassword(operation string) (string, error) {
	switch operation {
	case "encrypt":
		// User entered blank, generate secure password
		fmt.Println("Generating secure, random password...")
		securePass, err := cryptoutils.GenerateSecurePassword(constants.PasswordLength)
		if err != nil {
			return "", err
		}
		// Display the generated password for the user to save it
		fmt.Printf("Your auto-generated password is: %s\n", securePass)
		return string(securePass), nil
	case "decrypt":
		for { // Loop until a non-blank password is provided
			p, err := readPasswordFromTerminal("Enter password for decryption: ")
			if err != nil {
				return "", err
			}

			if p != "" {
				return p, nil
			}
			// If p is blank, warn the user and continue the loop
			fmt.Fprintln(os.Stderr, "Error: The password cannot be empty during decryption. Please try again.")
		}
	}
	// Should be unreachable
	return "", fmt.Errorf("internal error: invalid operation")
}

func getParameters() (operation string, inputPattern string, err error) {
	// Define flags
	encryptFlag := flag.String("e", "", "Encrypt file")
	decryptFlag := flag.String("d", "", "Decrypt file")

	// Parse flags
	flag.Parse()

	if *encryptFlag == *decryptFlag {
		return "", "", fmt.Errorf("must specify either -e (encrypt) or -d (decrypt), but not both")
	}

	if *encryptFlag != "" {
		inputPattern = *encryptFlag
		operation = "encrypt"
	} else if *decryptFlag != "" {
		inputPattern = *decryptFlag
		operation = "decrypt"
	}

	return
}
