package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/armor"
	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

// TestArmorVersionMatchesApp verifies the init() wiring that stamps the app
// version into the ASCII-armor Version header.
func TestArmorVersionMatchesApp(t *testing.T) {
	want := "Version: Cipherforge " + Version
	if armor.Version != want {
		t.Errorf("armor.Version = %q, want %q", armor.Version, want)
	}
}

func TestGetParameters(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name       string
		args       []string
		wantOp     string
		wantFiles  []string
		wantOutput string
		wantErr    bool
	}{
		{
			name:      "encrypt single file",
			args:      []string{"cfo", "-e", "test.txt"},
			wantOp:    "encrypt",
			wantFiles: []string{"test.txt"},
			wantErr:   false,
		},
		{
			name:      "decrypt single file",
			args:      []string{"cfo", "-d", "test.txt.cfo"},
			wantOp:    "decrypt",
			wantFiles: []string{"test.txt.cfo"},
			wantErr:   false,
		},
		{
			name:    "missing flags",
			args:    []string{"cfo", "test.txt"},
			wantErr: true,
		},
		{
			name:    "both flags",
			args:    []string{"cfo", "-e", "f1", "-d", "f2"},
			wantErr: true,
		},
		{
			name:    "-p removed",
			args:    []string{"cfo", "-e", "test.txt", "-p", "mysecret"},
			wantErr: true,
		},
		{
			name:       "encrypt with -o output",
			args:       []string{"cfo", "-e", "test.txt", "-o", "out.cfo"},
			wantOp:     "encrypt",
			wantFiles:  []string{"test.txt"},
			wantOutput: "out.cfo",
			wantErr:    false,
		},
		{
			name:       "decrypt with -o output",
			args:       []string{"cfo", "-d", "test.cfo", "-o", "out.txt"},
			wantOp:     "decrypt",
			wantFiles:  []string{"test.cfo"},
			wantOutput: "out.txt",
			wantErr:    false,
		},
		{
			name:    "-o specified twice",
			args:    []string{"cfo", "-e", "f1", "-o", "a.cfo", "-o", "b.cfo"},
			wantErr: true,
		},
		{
			name:    "-o without filename",
			args:    []string{"cfo", "-e", "f1", "-o", "-p"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			p, err := getParameters()
			if (err != nil) != tt.wantErr {
				t.Errorf("getParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if p.Operation != tt.wantOp {
				t.Errorf("op = %v, want %v", p.Operation, tt.wantOp)
			}
			if len(p.Inputs) != len(tt.wantFiles) {
				t.Errorf("files = %v, want %v", p.Inputs, tt.wantFiles)
			}
			if p.Output != tt.wantOutput {
				t.Errorf("output = %q, want %q", p.Output, tt.wantOutput)
			}
		})
	}
}

func TestExpandInputPaths(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cfo-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	f1 := filepath.Join(tmpDir, "file1.txt")
	os.WriteFile(f1, []byte("test"), 0644)

	// Create a .cfo file to test skip behavior during encrypt.
	cfoFile := filepath.Join(tmpDir, "already.cfo")
	os.WriteFile(cfoFile, []byte("not a real cfo"), 0644)

	tests := []struct {
		name    string
		inputs  []string
		op      string
		wantLen int
		wantErr bool
	}{
		{
			name:    "literal file",
			inputs:  []string{f1},
			op:      "encrypt",
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "glob pattern",
			inputs:  []string{filepath.Join(tmpDir, "*.txt")},
			op:      "encrypt",
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "no files found",
			inputs:  []string{filepath.Join(tmpDir, "*.nonexistent")},
			op:      "encrypt",
			wantErr: true,
		},
		{
			name:    "stdin passthrough",
			inputs:  []string{"-"},
			op:      "encrypt",
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "cfo skip during encrypt",
			inputs:  []string{cfoFile},
			op:      "encrypt",
			wantErr: true, // no files found because .cfo is skipped
		},
		{
			name:    "cfo accepted during decrypt",
			inputs:  []string{cfoFile},
			op:      "decrypt",
			wantLen: 1,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := expandInputPaths(tt.inputs, tt.op)
			if (err != nil) != tt.wantErr {
				t.Errorf("expandInputPaths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(files) != tt.wantLen {
				t.Errorf("len(files) = %d, want %d", len(files), tt.wantLen)
			}
			// Check stdin passthrough.
			if tt.name == "stdin passthrough" && !tt.wantErr {
				if files[0] != "-" {
					t.Errorf("stdin not passed through: got %q", files[0])
				}
			}
		})
	}
}

func TestDeriveOutputPath(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		inputFile string
		want      string
	}{
		{"encrypt", "encrypt", "doc.txt", "doc.txt.cfo"},
		{"encrypt with path", "encrypt", "/tmp/doc.txt", "/tmp/doc.txt.cfo"},
		{"decrypt", "decrypt", "doc.txt.cfo", "doc.txt"},
		{"decrypt nested", "decrypt", "a/b.txt.cfo", "a/b.txt"},
		{"decrypt no cfo suffix", "decrypt", "doc.txt", "doc.txt.dec"},
		{"encrypt stdin", "encrypt", "-", "-"},
		{"decrypt stdin", "decrypt", "-", "-"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveOutputPath(tt.op, tt.inputFile)
			if got != tt.want {
				t.Errorf("deriveOutputPath(%q, %q) = %q, want %q", tt.op, tt.inputFile, got, tt.want)
			}
		})
	}
}

// TestBooleanFlags verifies every boolean CLI flag is parsed and applied.
func TestBooleanFlags(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name string
		args []string
		get  func(p params) bool
	}{
		{"-q", []string{"cfo", "-e", "f1", "-q"}, func(p params) bool { return p.Quiet }},
		{"--quiet", []string{"cfo", "-e", "f1", "--quiet"}, func(p params) bool { return p.Quiet }},
		{"-f", []string{"cfo", "-d", "f.cfo", "-f"}, func(p params) bool { return p.Force }},
		{"--force", []string{"cfo", "-d", "f.cfo", "--force"}, func(p params) bool { return p.Force }},
		{"-b", []string{"cfo", "-e", "f1", "-b"}, func(p params) bool { return p.Base64 }},
		{"--base64", []string{"cfo", "-e", "f1", "--base64"}, func(p params) bool { return p.Base64 }},
		{"-i", []string{"cfo", "-i"}, func(p params) bool { return p.Interactive }},
		{"--interactive", []string{"cfo", "--interactive"}, func(p params) bool { return p.Interactive }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			p, err := getParameters()
			if err != nil {
				t.Fatalf("getParameters() error = %v", err)
			}
			if !tt.get(p) {
				t.Errorf("flag not applied for args %v", tt.args)
			}
		})
	}
}

// TestShowHelp verifies the -h/--help output includes every documented option.
func TestShowHelp(t *testing.T) {
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	showHelp()
	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"cfo " + Version,
		"Usage: cfo",
		"-e ",
		"-d ",
		"-o ",
		"-b, --base64",
		"-i, --interactive",
		"-q, --quiet",
		"-f, --force",
		"-h, --help",
		"-v, --version",
		"45 characters",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing %q", want)
		}
	}

	// The -p flag was removed in v7, so the help text must not advertise it.
	if strings.Contains(out, "-p ") {
		t.Error("help output still advertises the removed -p flag")
	}
}

// TestMain lets us re-exec the test binary to exercise os.Exit paths
// (the -h/--help and -v/--version flags).
func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		sep := -1
		for i, a := range os.Args {
			if a == "--" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(os.Args) {
			os.Exit(2)
		}
		os.Args = append([]string{"cfo"}, os.Args[sep+1:]...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestHelperProcess is the subprocess entry point selected via
// -test.run=TestHelperProcess; the actual work happens in TestMain.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	t.Fatal("TestMain should have handled the helper invocation")
}

// TestHelpVersionFlags runs the real binary for -h/--help and -v/--version,
// which call os.Exit, verifying they succeed and print the expected output.
func TestHelpVersionFlags(t *testing.T) {
	for _, tc := range []struct {
		flag    string
		wantOut string
	}{
		{"-h", "Usage: cfo"},
		{"--help", "Usage: cfo"},
		{"-v", "cfo " + Version},
		{"--version", "cfo " + Version},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--", tc.flag)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s: exit error: %v (output %q)", tc.flag, err, out)
			}
			if !strings.Contains(string(out), tc.wantOut) {
				t.Errorf("%s: output %q missing %q", tc.flag, out, tc.wantOut)
			}
		})
	}
}

// TestResolvePasswordKeepsSecretOffCiphertextStream is the CF70-001 regression
// test. When the ciphertext itself is written to stdout (-o -), the generated
// secret must not be written to that same stream: anyone holding the captured
// stream would otherwise hold the secret that protects it.
func TestResolvePasswordKeepsSecretOffCiphertextStream(t *testing.T) {
	secret, stdoutBytes, stderrBytes := resolvePasswordCaptured(t, true)

	if len(secret) != crypto.SecretDisplayLength {
		t.Fatalf("secret length = %d, want %d", len(secret), crypto.SecretDisplayLength)
	}
	if bytes.Contains(stdoutBytes, secret) {
		t.Errorf("CF70-001: generated secret leaked into the stdout ciphertext stream")
	}
	if !bytes.Contains(stderrBytes, secret) {
		t.Errorf("generated secret must be written to stderr; stderr was %q", stderrBytes)
	}
}

// TestResolvePasswordWritesSecretToStdoutForFileOutput guards the documented
// behaviour scripts rely on: with a file output target the generated secret is
// printed to stdout so the caller can capture it.
func TestResolvePasswordWritesSecretToStdoutForFileOutput(t *testing.T) {
	secret, stdoutBytes, _ := resolvePasswordCaptured(t, false)

	if !bytes.Contains(stdoutBytes, secret) {
		t.Errorf("for file output the generated secret must stay on stdout; stdout was %q", stdoutBytes)
	}
}

// resolvePasswordCaptured runs resolvePassword with both output streams
// redirected and returns the generated secret along with what each stream saw.
func resolvePasswordCaptured(t *testing.T, ciphertextToStdout bool) (secret, stdoutBytes, stderrBytes []byte) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	secret, resolveErr := resolvePassword("encrypt", ciphertextToStdout)

	os.Stdout, os.Stderr = origOut, origErr
	outW.Close()
	errW.Close()

	if resolveErr != nil {
		t.Fatalf("resolvePassword failed: %v", resolveErr)
	}

	stdoutBytes, _ = io.ReadAll(outR)
	stderrBytes, _ = io.ReadAll(errR)
	return secret, stdoutBytes, stderrBytes
}

// TestDecryptToStdoutEmitsNothingOnLateSegmentFailure is the CF70-002
// regression test. Corrupting a later segment must not let the earlier,
// already-authenticated plaintext segments reach stdout: a consumer of stdout
// must never receive plaintext from a ciphertext that ultimately fails
// authentication.
func TestDecryptToStdoutEmitsNothingOnLateSegmentFailure(t *testing.T) {
	secret := []byte("stdout-staging-regression-secret")
	plaintext := bytes.Repeat([]byte("A"), format.SegmentSize+4096) // two segments

	cipherPath := encryptForTest(t, plaintext, secret)

	data, err := os.ReadFile(cipherPath)
	if err != nil {
		t.Fatal(err)
	}

	// Flip one byte inside the *second* segment's ciphertext, leaving the first
	// segment and the authenticated trailer untouched. The segment length prefix
	// written by the encrypter gives the offset of the next segment.
	firstLen := binary.BigEndian.Uint64(data[format.HeaderSize : format.HeaderSize+8])
	secondCiphertext := format.HeaderSize + 8 + int(firstLen) + 8
	data[secondCiphertext+100] ^= 0xFF

	if err := os.WriteFile(cipherPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	emitted, decryptErr := decryptToStdout(t, cipherPath, secret)

	if decryptErr == nil {
		t.Fatal("expected decryption of the modified ciphertext to fail")
	}
	// The trailer HMAC and key-commitment checks must still pass — otherwise the
	// failure would happen before any plaintext could be produced and the test
	// would not actually exercise a late-segment failure.
	if errors.Is(decryptErr, cipherforge.ErrAuthenticationFailed) {
		t.Fatalf("test is not exercising a late-segment failure: %v", decryptErr)
	}
	if len(emitted) != 0 {
		t.Fatalf("CF70-002: %d bytes of plaintext reached stdout before authentication failed", len(emitted))
	}
}

// TestDecryptToStdoutEmitsFullPlaintextOnSuccess guards against over-correcting:
// an intact multi-segment file must still stream completely to stdout.
func TestDecryptToStdoutEmitsFullPlaintextOnSuccess(t *testing.T) {
	secret := []byte("stdout-staging-success-secret")
	plaintext := bytes.Repeat([]byte("B"), format.SegmentSize+4096) // two segments

	cipherPath := encryptForTest(t, plaintext, secret)

	emitted, decryptErr := decryptToStdout(t, cipherPath, secret)

	if decryptErr != nil {
		t.Fatalf("decryption failed: %v", decryptErr)
	}
	if !bytes.Equal(emitted, plaintext) {
		t.Fatalf("stdout plaintext = %d bytes, want %d bytes", len(emitted), len(plaintext))
	}
}

// encryptForTest encrypts plaintext to a .cfo file in a temp dir and returns
// the ciphertext path. Several segments are produced when plaintext exceeds
// format.SegmentSize.
func encryptForTest(t *testing.T, plaintext, secret []byte) string {
	t.Helper()

	dir := t.TempDir()
	plainPath := filepath.Join(dir, "large.bin")
	cipherPath := filepath.Join(dir, "large.bin.cfo")

	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := encryptFile(plainPath, cipherPath, secret, true, false); err != nil {
		t.Fatalf("encryptFile failed: %v", err)
	}
	return cipherPath
}

// decryptToStdout runs decryptFile against stdout and returns everything that
// reached stdout. The pipe is drained on a goroutine so that a regression
// cannot deadlock the test by filling the pipe buffer.
func decryptToStdout(t *testing.T, cipherPath string, secret []byte) ([]byte, error) {
	t.Helper()

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	origOut := os.Stdout
	os.Stdout = outW

	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		done <- b
	}()

	decryptErr := decryptFile(cipherPath, "-", secret, true, false)

	os.Stdout = origOut
	outW.Close()
	return <-done, decryptErr
}

// TestDecryptFileRepairsSingleCharacterSecretTypo verifies that a mistyped
// secret is corrected automatically: the file's key-commitment tag lets the CLI
// find the intended secret rather than failing the decryption.
func TestDecryptFileRepairsSingleCharacterSecretTypo(t *testing.T) {
	secret := []byte("8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k")
	plaintext := []byte("recover this")

	cipherPath := encryptForTest(t, plaintext, secret)

	// One character wrong: the final "k" typed as "q".
	typo := []byte("8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3q")
	outPath := filepath.Join(t.TempDir(), "recovered.bin")

	var decryptErr error
	stderrBytes := captureStderr(t, func() {
		decryptErr = decryptFile(cipherPath, outPath, typo, false, false)
	})

	if decryptErr != nil {
		t.Fatalf("decryptFile with a one-character typo = %v, want success", decryptErr)
	}
	if !bytes.Contains(stderrBytes, []byte("corrected secret")) {
		t.Errorf("expected a correction notice on stderr, got %q", stderrBytes)
	}
	if !bytes.Contains(stderrBytes, secret) {
		t.Errorf("expected the corrected secret on stderr, got %q", stderrBytes)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("decrypted %q, want %q", got, plaintext)
	}
}

// TestDecryptFileLeavesAnUnrecoverableSecretAlone guards the other side: when no
// nearby variant authenticates, the original failure is reported and no output
// file is produced.
func TestDecryptFileLeavesAnUnrecoverableSecretAlone(t *testing.T) {
	secret := []byte("8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k")
	cipherPath := encryptForTest(t, []byte("payload"), secret)

	wrong := []byte("Zq7vT-bN2wX-9kPmR-4sJhL-cF6yD-gK8uE-aW3nZ-xV5tB-mQ2rS")
	outPath := filepath.Join(t.TempDir(), "should-not-exist.bin")

	var decryptErr error
	stderrBytes := captureStderr(t, func() {
		decryptErr = decryptFile(cipherPath, outPath, wrong, false, false)
	})

	if decryptErr == nil {
		t.Fatal("expected decryption with an unrelated secret to fail")
	}
	if bytes.Contains(stderrBytes, []byte("corrected secret")) {
		t.Errorf("no correction should be reported, got %q", stderrBytes)
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Errorf("failed decryption must not create the output file (stat err = %v)", err)
	}
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what it
// wrote. The pipe is drained on a goroutine so a large message cannot deadlock.
func captureStderr(t *testing.T, fn func()) []byte {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	orig := os.Stderr
	os.Stderr = w

	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()

	fn()

	os.Stderr = orig
	w.Close()
	return <-done
}
