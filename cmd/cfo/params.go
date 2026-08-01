package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/ui"
	"golang.org/x/term"
)

// params holds parsed command-line configuration.
type params struct {
	Operation   string   // "encrypt" or "decrypt"
	Inputs      []string // expanded input file paths
	Password    []byte   // explicit password from -p, or nil
	Output      string   // -o override, or ""
	Quiet       bool
	Force       bool
	Atomic      bool
	Base64      bool // wrap I/O in base64 transport encoding
	Interactive bool // launch TUI instead of CLI mode
}

// getParameters parses command-line arguments.
func getParameters() (params, error) {
	var p params
	args := os.Args[1:]
	var encryptInputs, decryptInputs []string
	var passwordSeen, outputSeen bool

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			showHelp()
			os.Exit(0)
		case "-v", "--version":
			fmt.Printf("cfo %s\n", Version)
			os.Exit(0)
		case "-q", "--quiet":
			p.Quiet = true
		case "-f", "--force":
			p.Force = true
		case "-a", "--atomic":
			p.Atomic = true
		case "-b", "--base64":
			p.Base64 = true
		case "-i", "--interactive":
			p.Interactive = true
		case "-e":
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
				return params{}, fmt.Errorf("-o may only be specified once")
			}
			outputSeen = true
			i++
			if i >= len(args) || (args[i] != "-" && args[i][0] == '-') {
				return params{}, fmt.Errorf("-o requires an output filename")
			}
			p.Output = args[i]
		case "-p":
			if passwordSeen {
				return params{}, fmt.Errorf("-p may only be specified once")
			}
			passwordSeen = true
			i++
			if i < len(args) && args[i][0] != '-' {
				p.Password = []byte(args[i])
			} else {
				i-- // was -p without value; let resolvePasswordInteractive handle it
			}
		default:
			return params{}, fmt.Errorf("unknown argument: %s", args[i])
		}
	}

	// Determine operation and inputs.
	switch {
	case len(encryptInputs) > 0 && len(decryptInputs) > 0:
		return params{}, fmt.Errorf("provide exactly one flag: -e or -d")
	case len(decryptInputs) > 0:
		p.Operation = "decrypt"
		p.Inputs = decryptInputs
	case len(encryptInputs) > 0:
		p.Operation = "encrypt"
		p.Inputs = encryptInputs
	case !term.IsTerminal(int(syscall.Stdin)):
		p.Operation = "encrypt"
		p.Inputs = []string{"-"}
	default:
		// No flags and interactive terminal: launch TUI.
		if term.IsTerminal(int(syscall.Stdin)) {
			p.Interactive = true
		} else {
			return params{}, fmt.Errorf("provide exactly one flag: -e or -d")
		}
	}

	// Decrypt from stdin is not supported.
	if p.Operation == "decrypt" && len(p.Inputs) > 0 && p.Inputs[0] == "-" {
		return params{}, fmt.Errorf("decrypt from stdin is not supported (seek required for trailer HMAC)")
	}

	// Resolve interactive -p (no value given).
	if passwordSeen && p.Password == nil {
		pwd, err := resolvePasswordInteractive(p.Operation)
		if err != nil {
			return params{}, err
		}
		p.Password = pwd
	}

	return p, nil
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
		ui.PrintError("Password cannot be empty")
	}
}
