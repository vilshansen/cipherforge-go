package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
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

	operation, inputPattern, userPassword, err := getParameters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// wildcard/glob expansion allows for batch processing (e.g., *.txt)
	inputFiles, err := fileutils.ExpandInputPaths(inputPattern, operation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if len(inputFiles) == 0 {
		fmt.Fprintf(os.Stderr, "No files found for: %v\n", inputPattern)
		os.Exit(1)
	}

	// Password is held as a byte slice to prevent it from being interned
	// in the Go string heap, allowing us to manually clear it later.
	password, err := resolvePassword(operation, userPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// CRITICAL: Ensure the password is zeroed out in RAM as soon as the
	// program finishes processing the file queue.
	defer cryptoutils.ZeroBytes(password)

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

// resolvePassword selects the password based on the operation and whether the
// caller supplied one via -p.
//
//   - userPassword != nil → use it directly for both encrypt and decrypt.
//     For encryption the password is echoed back so the user knows what was used.
//   - userPassword == nil, encrypt → auto-generate a high-entropy password and
//     print it (existing behaviour).
//   - userPassword == nil, decrypt → prompt the terminal silently (existing
//     behaviour).
func resolvePassword(operation string, userPassword []byte) ([]byte, error) {
	// -p with an inline value: use it as-is for both modes.
	if userPassword != nil {
		if len(userPassword) == 0 {
			return nil, fmt.Errorf("password supplied via -p must not be empty")
		}
		if operation == "encrypt" {
			fmt.Printf("Using supplied password for encryption.\n")
		}
		return userPassword, nil
	}

	switch operation {
	case "encrypt":
		// -p without an inline value: prompt interactively with star-echo and confirmation.
		// This branch is only reached when userPassword is nil AND -p was NOT present at all.
		securePass, err := cryptoutils.GenerateSecurePassword(constants.PasswordLength)
		if err != nil {
			return nil, err
		}
		// The only time the auto-generated password is shown in plaintext.
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

// resolvePasswordInteractive is called when the user passes -p without an
// inline value. It prompts with starred echo; for encryption it asks twice
// and requires the two entries to match.
func resolvePasswordInteractive(operation string) ([]byte, error) {
	switch operation {
	case "encrypt":
		for {
			p1, err := readPasswordStarred("Enter password for encryption: ")
			if err != nil {
				return nil, err
			}
			if len(p1) == 0 {
				fmt.Fprintln(os.Stderr, "Error: Password cannot be empty. Please try again.")
				continue
			}

			// Skip confirmation when stdin is not a terminal (e.g. piped input
			// in scripts or tests): there is no risk of a typo and the pipe
			// would be exhausted by the second read anyway.
			if !term.IsTerminal(int(syscall.Stdin)) {
				return p1, nil
			}

			p2, err := readPasswordStarred("Confirm password: ")
			if err != nil {
				cryptoutils.ZeroBytes(p1)
				return nil, err
			}

			if !bytes.Equal(p1, p2) {
				cryptoutils.ZeroBytes(p1)
				cryptoutils.ZeroBytes(p2)
				fmt.Fprintln(os.Stderr, "Error: Passwords do not match. Please try again.")
				continue
			}

			cryptoutils.ZeroBytes(p2)
			return p1, nil
		}

	case "decrypt":
		for {
			p, err := readPasswordStarred("Enter password for decryption: ")
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

	// Fallback for automation. Use bufio.Reader to read into a byte slice
	// instead of fmt.Scanln (which uses strings).
	reader := bufio.NewReader(os.Stdin)

	// Read until newline
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}

	// If EOF arrived with no data the pipe/stdin is exhausted; returning an
	// empty slice would cause callers with retry loops to block forever on
	// the next read, so we surface it as an explicit error instead.
	if err == io.EOF && len(line) == 0 {
		return nil, fmt.Errorf("unexpected end of input")
	}

	// Trim newline characters (\n or \r\n) from the byte slice
	password := bytes.TrimRight(line, "\r\n")

	return password, nil
}

// readPasswordStarred reads a password from the terminal character-by-character,
// printing a '*' for each printable keypress and honouring backspace/delete.
// It puts the terminal into raw mode for the duration of the read, so signals
// such as Ctrl-C (SIGINT) are handled manually.
//
// When stdin is not a terminal (e.g. piped input in tests), it falls back to
// the silent readPasswordFromTerminal path so automated workflows are unaffected.
func readPasswordStarred(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)

	if !term.IsTerminal(fd) {
		// Non-terminal fallback: silent read (same as existing decrypt path).
		return readPasswordFromTerminal(prompt)
	}

	// Switch terminal to raw mode so we receive every keypress immediately
	// without the OS line-discipline buffering or echoing it.
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to set raw terminal mode: %w", err)
	}

	// Always restore the terminal, even on error.
	defer term.Restore(fd, oldState)

	fmt.Fprint(os.Stdout, prompt)

	var password []byte
	buf := make([]byte, 1)

	for {
		_, err := os.Stdin.Read(buf)
		if err != nil {
			cryptoutils.ZeroBytes(password)
			return nil, fmt.Errorf("error reading input: %w", err)
		}

		b := buf[0]

		switch {
		case b == '\r' || b == '\n':
			// Enter: finish input.
			fmt.Print("\r\n")
			return password, nil

		case b == 3:
			// Ctrl-C: restore terminal then exit cleanly.
			fmt.Print("\r\n")
			cryptoutils.ZeroBytes(password)
			// term.Restore is called via defer; print a newline for clarity.
			return nil, fmt.Errorf("interrupted")

		case b == 127 || b == '\b':
			// Backspace / DEL: remove the last character and erase the star.
			if len(password) > 0 {
				cryptoutils.ZeroBytes(password[len(password)-1:])
				password = password[:len(password)-1]
				// Move cursor back, overwrite the star with a space, move back again.
				fmt.Print("\b \b")
			}

		case b >= 32 && b < 127:
			// Printable ASCII: append the byte and echo a star.
			password = append(password, b)
			fmt.Print("*")

		default:
			// Ignore all other control characters (arrows, function keys, etc.).
		}
	}
}

// getParameters enforces mutually exclusive flags and returns input args as []string.
// It also handles the optional -p flag:
//
//   - "-p somevalue"  → userPassword is set to []byte("somevalue")
//   - "-p" alone      → interactive starred-echo prompt is invoked immediately
//     and the resulting password is returned as userPassword.
//   - absent          → userPassword is nil (caller keeps existing behaviour).
func getParameters() (operation string, inputs []string, userPassword []byte, err error) {
	args := os.Args[1:]

	var encryptInputs []string
	var decryptInputs []string
	var explicitPassword []byte // nil = not supplied
	passwordSeen := false

	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch arg {
		case "-e":
			// collect all following non-flag args
			i++
			for i < len(args) && len(args[i]) > 0 && args[i][0] != '-' {
				encryptInputs = append(encryptInputs, args[i])
				i++
			}
			i--

		case "-d":
			// collect all following non-flag args
			i++
			for i < len(args) && len(args[i]) > 0 && args[i][0] != '-' {
				decryptInputs = append(decryptInputs, args[i])
				i++
			}
			i--

		case "-p":
			if passwordSeen {
				return "", nil, nil, fmt.Errorf("-p may only be specified once")
			}
			passwordSeen = true

			// Peek at the next token: if it exists and doesn't look like a flag,
			// treat it as the inline password value.
			if i+1 < len(args) && len(args[i+1]) > 0 && args[i+1][0] != '-' {
				i++
				explicitPassword = []byte(args[i])
			}
			// If no inline value follows, explicitPassword stays nil; we will
			// invoke the interactive prompt once we know the operation.

		default:
			return "", nil, nil, fmt.Errorf("unknown argument: %s", arg)
		}
	}

	// validation: exactly one mode
	if (len(encryptInputs) > 0 && len(decryptInputs) > 0) ||
		(len(encryptInputs) == 0 && len(decryptInputs) == 0) {
		return "", nil, nil, fmt.Errorf("you must provide exactly one flag: -e (encrypt) or -d (decrypt)")
	}

	var op string
	var inputs_ []string
	if len(encryptInputs) > 0 {
		op = "encrypt"
		inputs_ = encryptInputs
	} else {
		op = "decrypt"
		inputs_ = decryptInputs
	}

	// If -p was given without an inline value, run the interactive starred prompt now,
	// before we return to main, so the password is collected once for all files.
	if passwordSeen && explicitPassword == nil {
		interactivePass, err := resolvePasswordInteractive(op)
		if err != nil {
			return "", nil, nil, fmt.Errorf("password entry failed: %w", err)
		}
		explicitPassword = interactivePass
	}

	return op, inputs_, explicitPassword, nil
}
