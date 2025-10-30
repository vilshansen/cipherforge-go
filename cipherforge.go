package main

import (
	"fmt"
	"os"

	"github.com/vilshansen/cipherforge-go/fileutils"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("CipherForge: Kryptering og dekryptering af filer med XChaCha20-Poly1305 og scrypt nøgleafledning.\n"+
			"\n"+
			"Kryptér og dekrypter filer ved hjælp af de stærkeste moderne kryptografiske standarder.\n"+
			"\n"+
			"Kryptering: %s -ef <input_fil> <output_fil> [-p <kodeord>]\n"+
			"Dekryptering: %s -df <input_fil> <output_fil> [-p <kodeord>]\n"+
			"\n"+
			"Angivelse af kodeord er valgfrit. Hvis intet kodeord angives ved kryptering, vil et tilfældigt, stærkt\n"+
			"kodeord blive genereret for brugeren.\n"+
			"\n"+
			"Fuld kildekode til programmet findes på https://github.com/vilshansen/cipherforge-go/\n", os.Args[0], os.Args[0])
		return
	}

	operation := os.Args[1]

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal fejl: %v\n", r)
		}
	}()

	var err error
	if operation == "-ef" {
		if len(os.Args) < 4 {
			err = fmt.Errorf("brug: %s -ef <input_fil> <output_fil> [-p <kodeord>]", os.Args[0])
		} else {
			inputFile := os.Args[2]
			outputFile := os.Args[3]
			var password string
			for i := 4; i < len(os.Args); i++ {
				if os.Args[i] == "-p" && i+1 < len(os.Args) {
					password = os.Args[i+1]
					break
				}
			}
			err = fileutils.EncryptFile(inputFile, outputFile, password)
		}
	} else if operation == "-df" {
		if len(os.Args) < 4 {
			err = fmt.Errorf("brug: %s -df <input_fil> <output_fil> [-p <kodeord>]", os.Args[0])
		} else {
			inputFile := os.Args[2]
			outputFile := os.Args[3]
			var password string
			for i := 4; i < len(os.Args); i++ {
				if os.Args[i] == "-p" && i+1 < len(os.Args) {
					password = os.Args[i+1]
					break
				}
			}
			err = fileutils.DecryptFile(inputFile, outputFile, password)
		}
	} else {
		err = fmt.Errorf("ugyldig operation. Brug -ef (encrypt) eller -df (decrypt)")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fejl: %v\n", err)
		os.Exit(1)
	}
}
