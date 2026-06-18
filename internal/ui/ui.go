package ui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"golang.org/x/term"
)

// ANSI color codes (matches dnf style)
const (
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorCyan    = "\033[36m"
	ColorRed     = "\033[31m"
	ColorGray    = "\033[90m"
)

// Progress represents progress state for dnf-style output
type Progress struct {
	startTime time.Time
	lastUpdate time.Time
	total     int64
	done      int64
}

// RunProgressBar displays a dnf-style progress bar with percentage
func RunProgressBar(prefix string, percent int) {
	const barWidth = 20
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := (percent * barWidth) / 100
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", barWidth-filled)
	
	// dnf style: use color and cleaner formatting
	fmt.Printf("\r%s%-45s %s[%-20s]%s %3d%%", 
		ColorCyan, prefix, ColorGreen, bar, ColorReset, percent)
}

// ProgressComplete finishes the progress bar and prints a summary
func ProgressComplete(prefix string, totalSize string) {
	fmt.Printf("\r%s%-45s %s[%-20s]%s 100%%\n", 
		ColorCyan, prefix, ColorGreen, strings.Repeat("=", 20), ColorReset)
	fmt.Printf("%s%s✓%s %s\n", ColorGreen, ColorBold, ColorReset, totalSize)
}

// PrintSuccess prints a green success message (dnf style)
func PrintSuccess(msg string) {
	fmt.Printf("%s✓%s %s\n", ColorGreen, ColorReset, msg)
}

// PrintWarning prints a yellow warning message (dnf style)
func PrintWarning(msg string) {
	fmt.Printf("%s⚠%s %s\n", ColorYellow, ColorReset, msg)
}

// PrintError prints a red error message (dnf style)
func PrintError(msg string) {
	fmt.Printf("%s✗%s %s\n", ColorRed, ColorReset, msg)
}

// PrintHeader prints a section header (dnf style)
func PrintHeader(title string) {
	fmt.Printf("\n%s%s==%s %s %s==%s\n", ColorBold, ColorCyan, ColorReset, title, ColorCyan, ColorReset)
}

// PrintInfo prints an informational line with padding
func PrintInfo(key string, value string) {
	fmt.Printf("  %s%-20s%s %s\n", ColorGray, key, ColorReset, value)
}

// ReadPasswordFromTerminal reads a password from terminal (hidden on input)
func ReadPasswordFromTerminal(prompt string) ([]byte, error) {
	fd := int(syscall.Stdin)
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stdout, prompt)
		bytePassword, err := term.ReadPassword(fd)
		fmt.Println()
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

// ReadPasswordStarred reads a password with star masking (dnf style)
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
	fmt.Fprint(os.Stdout, prompt)
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
			fmt.Print("\r\n")
			return password, nil
		case b == 3:
			fmt.Print("\r\n")
			crypto.ZeroBytes(password)
			return nil, fmt.Errorf("cancelled by user")
		case b == 127 || b == '\b':
			if len(password) > 0 {
				crypto.ZeroBytes(password[len(password)-1:])
				password = password[:len(password)-1]
				fmt.Print("\b \b")
			}
		case b >= 32 && b < 127:
			password = append(password, b)
			fmt.Print("*")
		}
	}
}
