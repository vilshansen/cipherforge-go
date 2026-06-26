package ui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"golang.org/x/term"
)

// PrintSuccess prints nothing — tar style is silent on success.
func PrintSuccess(msg string) {}

// PrintWarning prints a warning to stderr in tar style.
func PrintWarning(msg string) {
	fmt.Fprintf(os.Stderr, "cfo: warning: %s\n", msg)
}

// PrintError prints an error to stderr in tar style.
func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "cfo: %s\n", msg)
}

// PrintHeader prints a plain section header (no ANSI, no decorations).
func PrintHeader(title string) {
	fmt.Printf("\n%s\n", title)
}

// PrintInfo prints an informational line.
func PrintInfo(key string, value string) {
	fmt.Printf("  %s %s\n", key, value)
}

// ReadPasswordFromTerminal reads a password from terminal (hidden on input).
func ReadPasswordFromTerminal(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		bytePassword, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		return bytePassword, err
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	if err == io.EOF && len(line) == 0 {
		return nil, fmt.Errorf("unexpected end of input")
	}
	return bytes.TrimRight(line, "\r\n"), nil
}

// ReadPasswordStarred reads a password with star masking (prompts go to stderr).
func ReadPasswordStarred(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)
	if !term.IsTerminal(fd) {
		return ReadPasswordFromTerminal(prompt)
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to set raw terminal mode: %w", err)
	}
	defer term.Restore(fd, oldState)
	fmt.Fprint(os.Stderr, prompt)
	var password []byte
	buf := make([]byte, 1)
	for {
		_, err := os.Stdin.Read(buf)
		if err != nil {
			crypto.ZeroBytes(password)
			return nil, fmt.Errorf("failed to read password input: %w", err)
		}
		b := buf[0]
		switch {
		case b == '\r' || b == '\n':
			fmt.Fprint(os.Stderr, "\r\n")
			return password, nil
		case b == 3:
			fmt.Fprint(os.Stderr, "\r\n")
			crypto.ZeroBytes(password)
			return nil, fmt.Errorf("cancelled by user")
		case b == 127 || b == '\b':
			if len(password) > 0 {
				crypto.ZeroBytes(password[len(password)-1:])
				password = password[:len(password)-1]
				fmt.Fprint(os.Stderr, "\b \b")
			}
		case b >= 32 && b < 127:
			password = append(password, b)
			fmt.Fprint(os.Stderr, "*")
		}
	}
}
