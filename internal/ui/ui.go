package ui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"golang.org/x/term"
)

func RunProgressBar(prefix string, percent int) {
	const barWidth = 20
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	filled := (percent * barWidth) / 100
	bar := strings.Repeat("#", filled) + strings.Repeat(".", barWidth-filled)
	fmt.Printf("\r%-50s [%s] %3d%%", prefix, bar, percent)
}

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
