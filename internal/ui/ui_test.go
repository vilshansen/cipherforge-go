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

// TestReadPasswordLinePreallocates is the CF-2026-01 regression test. The buffer
// must be pre-allocated so that reading a secret never reallocates: a
// reallocation abandons a heap array holding a prefix of the secret, and Go
// offers no way to reach that array to zero it.
func TestReadPasswordLinePreallocates(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("a-one-time-secret\n"))
	if err != nil {
		t.Fatalf("readPasswordLine: %v", err)
	}
	if string(got) != "a-one-time-secret" {
		t.Errorf("got %q, want %q", got, "a-one-time-secret")
	}
	if cap(got) < maxPasswordInput {
		t.Errorf("capacity = %d, want at least %d; append would reallocate and strand secret bytes", cap(got), maxPasswordInput)
	}
}

// TestReadPasswordLineLongInputStillWorks checks that input longer than the
// pre-allocation is read in full. A longer secret is the user's choice and is
// not rejected; the buffer simply grows.
func TestReadPasswordLineLongInputStillWorks(t *testing.T) {
	long := strings.Repeat("x", maxPasswordInput+64)
	got, err := readPasswordLine(strings.NewReader(long + "\n"))
	if err != nil {
		t.Fatalf("readPasswordLine: %v", err)
	}
	if string(got) != long {
		t.Errorf("got %d bytes, want %d", len(got), len(long))
	}
}

func TestReadPasswordLineEOFWithoutNewline(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("no-newline"))
	if err != nil {
		t.Fatalf("readPasswordLine: %v", err)
	}
	if string(got) != "no-newline" {
		t.Errorf("got %q, want %q", got, "no-newline")
	}
}

func TestReadPasswordLineStripsCR(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("pass\r\n"))
	if err != nil {
		t.Fatalf("readPasswordLine: %v", err)
	}
	if string(got) != "pass" {
		t.Errorf("got %q, want %q", got, "pass")
	}
}

func TestReadPasswordLineEmptyEOF(t *testing.T) {
	_, err := readPasswordLine(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error on empty EOF")
	}
	if err.Error() != "unexpected end of input" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadPasswordLineBareNewline(t *testing.T) {
	got, err := readPasswordLine(strings.NewReader("\n"))
	if err != nil {
		t.Fatalf("readPasswordLine: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %q, want an empty line", got)
	}
}
