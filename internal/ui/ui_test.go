package ui

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// captureStderr runs f and returns whatever it wrote to stderr.
func captureStderr(f func()) string {
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		// ReadAll is safe here because we close w after f() returns.
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	f()
	w.Close()
	os.Stderr = orig
	return <-done
}

func TestPrintWarning(t *testing.T) {
	out := captureStderr(func() {
		PrintWarning("something went wrong")
	})
	if !strings.Contains(out, "cfo: warning: something went wrong") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestPrintError(t *testing.T) {
	out := captureStderr(func() {
		PrintError("fatal issue")
	})
	if !strings.Contains(out, "cfo: fatal issue") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestPrintHeader(t *testing.T) {
	// PrintHeader writes to stdout, not stderr. Capture stdout.
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	PrintHeader("My Header")
	w.Close()
	os.Stdout = orig
	out := <-done
	if !strings.Contains(out, "\nMy Header\n") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestPrintInfo(t *testing.T) {
	orig := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		buf.ReadFrom(r)
		done <- buf.String()
	}()
	PrintInfo("Key:", "Value")
	w.Close()
	os.Stdout = orig
	out := <-done
	if !strings.Contains(out, "Key: Value") {
		t.Errorf("unexpected output: %q", out)
	}
}

func TestReadPasswordFromTerminalNonTTY(t *testing.T) {
	// When stdin is not a terminal (pipe), ReadPasswordFromTerminal reads
	// a full line. Inject input via a pipe.
	input := "my-password\n"
	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		w.Write([]byte(input))
		w.Close()
	}()
	defer func() { os.Stdin = origStdin }()

	pwd, err := ReadPasswordFromTerminal("Prompt: ")
	if err != nil {
		t.Fatalf("ReadPasswordFromTerminal failed: %v", err)
	}
	if string(pwd) != "my-password" {
		t.Errorf("got %q, want %q", pwd, "my-password")
	}
}

func TestReadPasswordFromTerminalEmptyEOF(t *testing.T) {
	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	w.Close() // close immediately = EOF with no data
	defer func() { os.Stdin = origStdin }()

	_, err := ReadPasswordFromTerminal("Prompt: ")
	if err == nil {
		t.Fatal("expected error on empty EOF")
	}
	if err.Error() != "unexpected end of input" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadPasswordFromTerminalCRLF(t *testing.T) {
	// Windows-style line endings: \r\n
	input := "pass\r\n"
	origStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() {
		w.Write([]byte(input))
		w.Close()
	}()
	defer func() { os.Stdin = origStdin }()

	pwd, err := ReadPasswordFromTerminal("Prompt: ")
	if err != nil {
		t.Fatalf("ReadPasswordFromTerminal failed: %v", err)
	}
	if string(pwd) != "pass" {
		t.Errorf("got %q, want %q", pwd, "pass")
	}
}
