package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/internal/armor"
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
		name           string
		args           []string
		wantOp         string
		wantFiles      []string
		wantOutput     string
		wantPwdPresent bool
		wantErr        bool
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
			name:           "encrypt with -p password",
			args:           []string{"cfo", "-e", "test.txt", "-p", "mysecret"},
			wantOp:         "encrypt",
			wantFiles:      []string{"test.txt"},
			wantPwdPresent: true,
			wantErr:        false,
		},
		{
			name:           "decrypt with -p password",
			args:           []string{"cfo", "-d", "test.txt.cfo", "-p", "mysecret"},
			wantOp:         "decrypt",
			wantFiles:      []string{"test.txt.cfo"},
			wantPwdPresent: true,
			wantErr:        false,
		},
		{
			name:    "-p specified twice",
			args:    []string{"cfo", "-e", "f1", "-p", "a", "-p", "b"},
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
			if tt.wantPwdPresent && p.Password == nil {
				t.Error("expected non-nil password from -p flag")
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
		"-p ",
		"-b, --base64",
		"-i, --interactive",
		"-q, --quiet",
		"-f, --force",
		"-h, --help",
		"-v, --version",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("help output missing %q", want)
		}
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
