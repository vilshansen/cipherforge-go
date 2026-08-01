// Package ui provides terminal I/O utilities for the Cipherforge CLI:
// formatted output messages and password prompts with star masking.
//
// # Go Language Notes for Java Developers
//
//   - `fmt.Fprintf(os.Stderr, ...)` writes to stderr (like System.err.printf).
//     Prompts and warnings go to stderr so they don't interfere with stdout piping.
//
//   - `term.IsTerminal(fd)` detects whether a file descriptor is a TTY
//     (like Java's `System.console() != null`). Used to decide between
//     interactive star-masked input and plain stdin pipe reads.
//
//   - `term.MakeRaw(fd)` puts the terminal in raw mode (disables line
//     buffering, echo). Like Java's Console.readPassword() but with more
//     control. The old terminal state is restored via defer.
//
//   - `syscall.Stdin` is the integer file descriptor for stdin (0).
//     In Go, you pass the fd to terminal functions rather than using
//     the *os.File directly.
//
//   - `switch` without an expression is cleaner than long if-else chains:
//     switch {
//     case b == '\r':
//     ...
//     case b == 3:
//     ...
//     }
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

// PrintWarning prints a warning to stderr in tar style:
//
//	cfo: warning: <message>
//
// Warnings go to stderr so they don't corrupt stdout when piping.
func PrintWarning(msg string) {
	fmt.Fprintf(os.Stderr, "cfo: warning: %s\n", msg)
}

// PrintError prints an error to stderr in tar style:
//
//	cfo: <message>
func PrintError(msg string) {
	fmt.Fprintf(os.Stderr, "cfo: %s\n", msg)
}

// PrintHeader prints a plain section header (no ANSI, no decorations).
func PrintHeader(title string) {
	fmt.Printf("\n%s\n", title)
}

// PrintInfo prints an informational key-value line.
func PrintInfo(key string, value string) {
	fmt.Printf("  %s %s\n", key, value)
}

// ReadPasswordFromTerminal reads a password from the terminal with hidden input.
//
// Two modes:
//  1. Interactive terminal: uses term.ReadPassword (like Java's
//     Console.readPassword() — input is not echoed).
//  2. Piped/non-terminal stdin: reads a single line with echo (used for
//     scripting: `echo "pwd" | cfo -d file.cfo`).
//
// The prompt goes to stderr so it doesn't contaminate stdout.
func ReadPasswordFromTerminal(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin) // syscall.Stdin = 0 (the Unix fd for stdin)
	if term.IsTerminal(fd) {
		// Interactive mode: use ReadPassword which disables echo.
		fmt.Fprint(os.Stderr, prompt)
		bytePassword, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // Newline after password input
		return bytePassword, err
	}

	// Non-interactive mode (piped input): read a line normally.
	// bufio.NewReader wraps an io.Reader with a buffer (like BufferedReader).
	reader := bufio.NewReader(os.Stdin)
	// ReadBytes('\n') reads until newline (like BufferedReader.readLine()
	// but returns the delimiter). Returns io.EOF on end of input.
	line, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	if err == io.EOF && len(line) == 0 {
		return nil, fmt.Errorf("unexpected end of input")
	}
	// Strip trailing newline(s): \r\n (Windows) or \n (Unix).
	// Use TrimSuffix (not TrimRight) to avoid stripping trailing
	// newlines that are legitimately part of the password.
	line = bytes.TrimSuffix(line, []byte("\r\n"))
	line = bytes.TrimSuffix(line, []byte("\n"))
	return line, nil
}

// ReadPasswordStarred reads a password with star masking (one * per character).
//
// This provides visual feedback during typing (unlike term.ReadPassword which
// is completely silent) while still hiding the actual password.
//
// Implementation: puts the terminal in raw mode (disables line buffering and
// echo), then reads one byte at a time and prints a * for each character.
//
// Terminal raw mode details:
//   - term.MakeRaw(fd) disables canonical mode (line buffering) and echo.
//     The old terminal state is captured and restored via defer, ensuring
//     the terminal is returned to normal even if an error occurs.
//   - Raw mode means we receive each keypress immediately as a byte,
//     rather than waiting for Enter and getting the whole line at once.
//
// Special keys handled:
//   - Enter (CR or LF): finishes input and returns the password
//   - Ctrl+C (byte 3): cancels input, wipes the password buffer, returns error
//   - Backspace (127 or \b): removes the last character, prints "\b \b" to
//     erase the * from the screen and zeroes the removed byte in the buffer
//   - Printable ASCII (32–126): appends to password, prints a *
//
// Non-ASCII input (e.g., UTF-8 multi-byte characters) is silently ignored
// because the check `b >= 32 && b < 127` only passes single-byte characters.
// This is intentional — passwords are expected to be ASCII for portability.
//
// All prompts and * output go to stderr so they don't affect stdout piping.
func ReadPasswordStarred(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)
	// If stdin is not a terminal (pipe/redirect), fall back to plain read.
	if !term.IsTerminal(fd) {
		return ReadPasswordFromTerminal(prompt)
	}

	// Put terminal in raw mode: disable canonical processing and echo.
	// oldState is the original terminal settings (like termios struct).
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to set raw terminal mode: %w", err)
	}
	// Restore terminal settings when the function returns.
	// This runs even on error/panic — the user's terminal is never
	// left in raw mode.
	defer term.Restore(fd, oldState)

	// Print the prompt to stderr.
	fmt.Fprint(os.Stderr, prompt)

	var password []byte
	buf := make([]byte, 1) // Single-byte buffer for reading one char at a time

	for {
		// Read one byte from stdin in raw mode.
		// os.Stdin.Read reads raw keypresses — no line buffering, no echo.
		_, err := os.Stdin.Read(buf)
		if err != nil {
			// On any read error, wipe the in-progress password and return.
			crypto.ZeroBytes(password)
			return nil, fmt.Errorf("failed to read password input: %w", err)
		}
		b := buf[0]

		// Switch without an expression — cleaner than if-else chains.
		// Each case is evaluated in order. No fallthrough.
		switch {
		case b == '\r' || b == '\n':
			// Enter key — finish input.
			// Print \r\n to move to the next line (raw mode doesn't do this).
			fmt.Fprint(os.Stderr, "\r\n")
			return password, nil

		case b == 3:
			// Ctrl+C (ASCII ETX = 0x03) — cancel input.
			fmt.Fprint(os.Stderr, "\r\n")
			crypto.ZeroBytes(password)
			return nil, fmt.Errorf("cancelled by user")

		case b == 127 || b == '\b':
			// Backspace (DEL = 127 or BS = 8).
			// Remove the last character from the password buffer.
			if len(password) > 0 {
				// Zero the last byte BEFORE removing it from the slice.
				// password[len(password)-1:] is a 1-byte slice at the end.
				crypto.ZeroBytes(password[len(password)-1:])
				// Reslice to remove the last byte.
				password = password[:len(password)-1]
				// "\b \b" = backspace, space (overwrite *), backspace.
				// This visually erases the * on screen.
				fmt.Fprint(os.Stderr, "\b \b")
			}

		case b >= 32 && b < 127:
			// Printable ASCII character — append to password.
			// append() grows the slice if needed (allocates new backing array).
			password = append(password, b)
			// Print * for visual feedback.
			fmt.Fprint(os.Stderr, "*")
		}
		// Bytes outside 32–126 (control chars, high bytes) are silently ignored.
	}
}
