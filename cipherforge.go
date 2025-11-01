package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vilshansen/cipherforge-go/constants"
	"github.com/vilshansen/cipherforge-go/fileutils"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Print(constants.HelpText)
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
