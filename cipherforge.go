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
	if len(os.Args) < 2 {
		helpText := fmt.Sprintf(constants.HelpText, constants.Version, constants.GitCommit)
		fmt.Print(helpText)
		os.Exit(1)
	}

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal fejl: %v\n", r)
		}
	}()

	operation, inputFile, outputFile, password, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fejl ved hentning af parametre: %v\n", err)
		os.Exit(1)
	}

	// If password was not specified via -p flag, resolve it interactively
	if password == "" {
		resolvedPassword, err := resolvePassword(operation)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fejl ved kodeordshåndtering: %v\n", err)
			os.Exit(1)
		}
		password = resolvedPassword
	}

	switch operation {
	case "encrypt":
		if err := fileutils.EncryptFile(inputFile, outputFile, password); err != nil {
			fmt.Fprintf(os.Stderr, "Fejl ved kryptering: %v\n", err)
			os.Exit(1)
		}
	case "decrypt":
		if err := fileutils.DecryptFile(inputFile, outputFile, password); err != nil {
			fmt.Fprintf(os.Stderr, "Fejl ved dekryptering: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "ugyldig operation. Brug -ef (encrypt) eller -df (decrypt)")
	}
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
	if operation == "encrypt" {
		fmt.Println("Indtast kodeord til kryptering, eller tryk ENTER for at generere et stærkt kodeord:")
		p, err := readPasswordFromTerminal("Kodeord: ")
		if err != nil {
			return "", err
		}

		if p == "" {
			// User entered blank, generate secure password
			fmt.Println("Intet kodeord angivet. Genererer sikkert, tilfældigt kodeord...")
			securePass, err := cryptoutils.GenerateSecurePassword(constants.PasswordLength)
			if err != nil {
				return "", err
			}
			// Display the generated password for the user to save it
			fmt.Printf("Dit autogenererede kodeord er: %s\n", securePass)
			return string(securePass), nil
		}

		// User entered a password, prompt for verification
		pVerify, err := readPasswordFromTerminal("Bekræft kodeord: ")
		if err != nil {
			return "", err
		}
		if p != pVerify {
			return "", fmt.Errorf("de to indtastede kodeord stemmer ikke overens")
		}
		return p, nil

	} else if operation == "decrypt" {
		for { // Loop until a non-blank password is provided
			fmt.Println("Indtast kodeord til dekryptering:")
			p, err := readPasswordFromTerminal("Kodeord: ")
			if err != nil {
				return "", err
			}

			if p != "" {
				return p, nil
			}
			// If p is blank, warn the user and continue the loop
			fmt.Fprintln(os.Stderr, "Fejl: Kodeordet må ikke være tomt ved dekryptering. Prøv igen.")
		}
	}
	// Should be unreachable
	return "", fmt.Errorf("intern fejl: ugyldig operation")
}

func getParameters() (operation string, inputFile string, outputFile string, password string, err error) {
	// Define flags
	encryptFlag := flag.Bool("ef", false, "Encrypt file")
	decryptFlag := flag.Bool("df", false, "Decrypt file")
	inputFileFlag := flag.String("i", "", "Input file")
	outputFileFlag := flag.String("o", "", "Output file")
	pwdFlag := flag.String("p", "", "Password (optional)")

	// Parse flags
	flag.Parse()

	if (*encryptFlag && *decryptFlag) || (!*encryptFlag && !*decryptFlag) {
		return "", "", "", "", fmt.Errorf("must specify either -ef (encrypt) or -df (decrypt), but not both")
	}

	if *inputFileFlag == "" || *outputFileFlag == "" {
		return "", "", "", "", fmt.Errorf("input and output files must be specified with -i and -o flags")
	}

	if *encryptFlag {
		operation = "encrypt"
	} else if *decryptFlag {
		operation = "decrypt"
	}

	inputFile = *inputFileFlag
	outputFile = *outputFileFlag
	password = *pwdFlag
	return
}
