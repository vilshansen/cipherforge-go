package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/term"
)

// params holds parsed command-line configuration.
type params struct {
	Operation   string   // "encrypt" or "decrypt"
	Inputs      []string // expanded input file paths
	Output      string   // -o override, or ""
	Quiet       bool
	Force       bool
	Base64      bool // wrap I/O in base64 transport encoding
	Interactive bool // launch TUI instead of CLI mode
}

// getParameters parses command-line arguments.
func getParameters() (params, error) {
	var p params
	args := os.Args[1:]
	var encryptInputs, decryptInputs []string
	var outputSeen bool

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

	return p, nil
}
