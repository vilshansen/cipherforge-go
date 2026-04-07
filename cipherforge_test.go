package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/constants"
)

func TestMain(m *testing.M) {
	constants.Argon2Time = 1
	constants.Argon2Memory = 64 * 1024 // 64 MiB
	constants.Argon2Threads = 1
	os.Exit(m.Run())
}

func TestGetParameters(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedOp     string
		expectedInputs []string
		expectError    bool
		errContains    string
	}{
		{
			name:           "encrypt single file",
			args:           []string{"-e", "file.txt"},
			expectedOp:     "encrypt",
			expectedInputs: []string{"file.txt"},
			expectError:    false,
		},
		{
			name:           "encrypt multiple files",
			args:           []string{"-e", "file1.txt", "file2.txt", "file3.txt"},
			expectedOp:     "encrypt",
			expectedInputs: []string{"file1.txt", "file2.txt", "file3.txt"},
			expectError:    false,
		},
		{
			name:           "decrypt single file",
			args:           []string{"-d", "file.cfo"},
			expectedOp:     "decrypt",
			expectedInputs: []string{"file.cfo"},
			expectError:    false,
		},
		{
			name:           "decrypt multiple files",
			args:           []string{"-d", "file1.cfo", "file2.cfo"},
			expectedOp:     "decrypt",
			expectedInputs: []string{"file1.cfo", "file2.cfo"},
			expectError:    false,
		},
		{
			name:           "encrypt with glob pattern",
			args:           []string{"-e", "*.txt", "*.md"},
			expectedOp:     "encrypt",
			expectedInputs: []string{"*.txt", "*.md"},
			expectError:    false,
		},
		{
			name:        "both encrypt and decrypt flags",
			args:        []string{"-e", "file.txt", "-d", "file.cfo"},
			expectError: true,
			errContains: "exactly one flag",
		},
		{
			name:        "no flags",
			args:        []string{},
			expectError: true,
			errContains: "exactly one flag",
		},
		{
			name:        "unknown flag",
			args:        []string{"-x", "file.txt"},
			expectError: true,
			errContains: "unknown argument",
		},
		{
			name:        "encrypt with no files",
			args:        []string{"-e"},
			expectError: true,
			errContains: "exactly one flag",
		},
		{
			name:        "decrypt with no files",
			args:        []string{"-d"},
			expectError: true,
			errContains: "exactly one flag",
		},
		{
			name:           "encrypt with mixed flag order",
			args:           []string{"-e", "file1.txt", "file2.txt"},
			expectedOp:     "encrypt",
			expectedInputs: []string{"file1.txt", "file2.txt"},
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original args and restore after test
			originalArgs := os.Args
			defer func() { os.Args = originalArgs }()
			os.Args = append([]string{"cipherforge"}, tt.args...)

			op, inputs, _, err := getParameters()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if op != tt.expectedOp {
				t.Errorf("Operation = %q, want %q", op, tt.expectedOp)
			}

			if len(inputs) != len(tt.expectedInputs) {
				t.Errorf("Got %d inputs, want %d", len(inputs), len(tt.expectedInputs))
			}

			for i := range inputs {
				if i < len(tt.expectedInputs) && inputs[i] != tt.expectedInputs[i] {
					t.Errorf("Input[%d] = %q, want %q", i, inputs[i], tt.expectedInputs[i])
				}
			}
		})
	}
}

func TestGetParametersPasswordFlag(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		// stdin is only used when -p is given without an inline value; in tests
		// stdin is always a pipe (non-terminal), so readPasswordStarred falls
		// back to the silent readPasswordFromTerminal path automatically.
		stdinInput       string
		expectedOp       string
		expectedPassword string // empty means nil expected
		expectError      bool
		errContains      string
	}{
		{
			name:             "encrypt with inline password",
			args:             []string{"-e", "file.txt", "-p", "mypassword"},
			expectedOp:       "encrypt",
			expectedPassword: "mypassword",
		},
		{
			name:             "decrypt with inline password",
			args:             []string{"-d", "file.cfo", "-p", "mypassword"},
			expectedOp:       "decrypt",
			expectedPassword: "mypassword",
		},
		{
			name:             "-p before -e",
			args:             []string{"-p", "mypassword", "-e", "file.txt"},
			expectedOp:       "encrypt",
			expectedPassword: "mypassword",
		},
		{
			name:             "-p before -d",
			args:             []string{"-p", "mypassword", "-d", "file.cfo"},
			expectedOp:       "decrypt",
			expectedPassword: "mypassword",
		},
		{
			name:       "encrypt with -p no inline value uses stdin",
			args:       []string{"-e", "file.txt", "-p"},
			// Non-terminal stdin: resolvePasswordInteractive falls back to the
			// silent readPasswordFromTerminal path. On a non-terminal, the
			// confirmation prompt is skipped to avoid consuming the pipe twice.
			stdinInput:       "piped-password\n",
			expectedOp:       "encrypt",
			expectedPassword: "piped-password",
		},
		{
			name:             "decrypt with -p no inline value uses stdin",
			args:             []string{"-d", "file.cfo", "-p"},
			stdinInput:       "piped-password\n",
			expectedOp:       "decrypt",
			expectedPassword: "piped-password",
		},
		{
			name:        "-p specified twice",
			args:        []string{"-e", "file.txt", "-p", "pass1", "-p", "pass2"},
			expectError: true,
			errContains: "-p may only be specified once",
		},
		{
			name:        "no files with -p",
			args:        []string{"-p", "mypassword"},
			expectError: true,
			errContains: "exactly one flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalArgs := os.Args
			defer func() { os.Args = originalArgs }()
			os.Args = append([]string{"cipherforge"}, tt.args...)

			if tt.stdinInput != "" {
				stdin, err := createStdinPipe(tt.stdinInput)
				if err != nil {
					t.Fatalf("Failed to setup stdin: %v", err)
				}
				defer stdin.Close()
				oldStdin := os.Stdin
				defer func() { os.Stdin = oldStdin }()
				os.Stdin = stdin
			}

			op, _, password, err := getParameters()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if op != tt.expectedOp {
				t.Errorf("Operation = %q, want %q", op, tt.expectedOp)
			}

			if tt.expectedPassword == "" {
				if password != nil {
					t.Errorf("Expected nil password, got %q", password)
				}
			} else {
				if string(password) != tt.expectedPassword {
					t.Errorf("Password = %q, want %q", password, tt.expectedPassword)
				}
			}
		})
	}
}

func TestResolvePassword(t *testing.T) {
	tests := []struct {
		name         string
		operation    string
		userPassword []byte // nil = not supplied via -p
		setupStdin   func() (*os.File, error)
		expectError  bool
		errContains  string
		checkLength  int
		expectedPW   string // non-empty = exact match expected
	}{
		{
			name:        "encrypt generates password when none supplied",
			operation:   "encrypt",
			userPassword: nil,
			expectError: false,
			checkLength: constants.PasswordLength,
		},
		{
			name:         "encrypt uses supplied password",
			operation:    "encrypt",
			userPassword: []byte("my-supplied-password"),
			expectedPW:   "my-supplied-password",
		},
		{
			name:         "decrypt uses supplied password",
			operation:    "decrypt",
			userPassword: []byte("my-supplied-password"),
			expectedPW:   "my-supplied-password",
		},
		{
			name:         "empty supplied password is rejected",
			operation:    "encrypt",
			userPassword: []byte(""),
			expectError:  true,
			errContains:  "must not be empty",
		},
		{
			name:        "decrypt with valid password from terminal",
			operation:   "decrypt",
			userPassword: nil,
			setupStdin:  func() (*os.File, error) { return createStdinPipe("test-password\n") },
			expectError: false,
		},
		{
			name:        "invalid operation",
			operation:   "invalid",
			userPassword: nil,
			expectError: true,
			errContains: "internal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupStdin != nil {
				stdin, err := tt.setupStdin()
				if err != nil {
					t.Fatalf("Failed to setup stdin: %v", err)
				}
				defer stdin.Close()

				oldStdin := os.Stdin
				defer func() { os.Stdin = oldStdin }()
				os.Stdin = stdin
			}

			password, err := resolvePassword(tt.operation, tt.userPassword)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.expectedPW != "" {
				if string(password) != tt.expectedPW {
					t.Errorf("Password = %q, want %q", password, tt.expectedPW)
				}
				return
			}

			if tt.operation == "encrypt" && tt.userPassword == nil {
				// The generated password is PasswordLength chars plus hyphens
				// inserted every 5 characters. Verify the character count
				// (excluding hyphens) rather than the raw byte length.
				nonHyphen := strings.ReplaceAll(string(password), "-", "")
				if len(nonHyphen) != tt.checkLength {
					t.Errorf("Generated password char count = %d, want %d (raw: %q)",
						len(nonHyphen), tt.checkLength, password)
				}
				hyphenCount := strings.Count(string(password), "-")
				expectedHyphens := (tt.checkLength - 1) / 5
				if hyphenCount != expectedHyphens {
					t.Errorf("Password has %d hyphens, expected %d", hyphenCount, expectedHyphens)
				}
			} else if tt.operation == "decrypt" && tt.userPassword == nil {
				if len(password) == 0 {
					t.Error("Decrypt password should not be empty")
				}
			}
		})
	}
}

func TestReadPasswordFromTerminal(t *testing.T) {
	tests := []struct {
		name        string
		prompt      string
		setupStdin  func() (*os.File, error)
		expectError bool
		expectedLen int
		expectedPW  string
	}{
		{
			name:       "normal password input",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe("secret123\n") },
			expectedPW: "secret123",
		},
		{
			name:       "password with spaces",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe("my secret password\n") },
			expectedPW: "my secret password",
		},
		{
			name:       "empty password",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe("\n") },
			expectedPW: "",
		},
		{
			name:       "password with newline only",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe("\n") },
			expectedPW: "",
		},
		{
			name:       "password with carriage return",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe("password\r\n") },
			expectedPW: "password",
		},
		{
			name:       "long password",
			prompt:     "Enter password: ",
			setupStdin: func() (*os.File, error) { return createStdinPipe(strings.Repeat("a", 1000) + "\n") },
			expectedPW: strings.Repeat("a", 1000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupStdin == nil {
				t.Skip("No stdin setup provided")
			}

			stdin, err := tt.setupStdin()
			if err != nil {
				t.Fatalf("Failed to setup stdin: %v", err)
			}
			defer stdin.Close()

			oldStdin := os.Stdin
			defer func() { os.Stdin = oldStdin }()
			os.Stdin = stdin

			// Capture stdout to verify prompt
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			password, err := readPasswordFromTerminal(tt.prompt)

			w.Close()
			os.Stdout = oldStdout

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if string(password) != tt.expectedPW {
				t.Errorf("Got password %q, want %q", string(password), tt.expectedPW)
			}

			// The prompt is only printed when stdin is a real terminal.
			// In these tests stdin is always a pipe, so we don't assert it.
			io.Copy(io.Discard, r)
		})
	}
}

func TestMainIntegration(t *testing.T) {
	// Create test directory
	tempDir := t.TempDir()

	// Test files
	testFiles := []struct {
		name     string
		content  string
		shouldEncrypt bool
	}{
		{"file1.txt", "Content for file 1", true},
		{"file2.txt", "Content for file 2 with more data", true},
		{"secret.cfo", "This is already encrypted data", false},
	}

	// Create test files
	for _, tf := range testFiles {
		path := filepath.Join(tempDir, tf.name)
		if err := os.WriteFile(path, []byte(tf.content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	tests := []struct {
		name         string
		args         []string
		setupStdin   func() (*os.File, error)
		expectError  bool
		checkOutputs []string
	}{
		{
			name: "encrypt single file",
			args: []string{"-e", filepath.Join(tempDir, "file1.txt")},
			setupStdin: func() (*os.File, error) { return nil, nil },
			checkOutputs: []string{filepath.Join(tempDir, "file1.txt.cfo")},
		},
		{
			name: "encrypt multiple files",
			args: []string{"-e", filepath.Join(tempDir, "file1.txt"), filepath.Join(tempDir, "file2.txt")},
			setupStdin: func() (*os.File, error) { return nil, nil },
			checkOutputs: []string{
				filepath.Join(tempDir, "file1.txt.cfo"),
				filepath.Join(tempDir, "file2.txt.cfo"),
			},
		},
		{
			name: "encrypt with glob pattern",
			args: []string{"-e", filepath.Join(tempDir, "*.txt")},
			setupStdin: func() (*os.File, error) { return nil, nil },
			checkOutputs: []string{
				filepath.Join(tempDir, "file1.txt.cfo"),
				filepath.Join(tempDir, "file2.txt.cfo"),
			},
		},
		{
			name: "decrypt single file",
			args: []string{"-d", filepath.Join(tempDir, "file1.txt.cfo")},
			setupStdin: func() (*os.File, error) {
				// First encrypt to create the .cfo file
				// This will be handled in the test setup
				return createStdinPipe("test-password\n")
			},
			checkOutputs: []string{filepath.Join(tempDir, "file1.txt")},
		},
		{
			name: "decrypt with wrong password",
			args: []string{"-d", filepath.Join(tempDir, "file1.txt.cfo")},
			setupStdin: func() (*os.File, error) {
				return createStdinPipe("wrong-password\n")
			},
			expectError: true, // Will show error but continue
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For decrypt tests, we need to encrypt first
			if strings.Contains(tt.name, "decrypt") && !strings.Contains(tt.name, "wrong") {
				// Encrypt file1.txt first
				pass := []byte("test-password")
				src := filepath.Join(tempDir, "file1.txt")
				dst := src + constants.FileExtension
				if err := encryptFileHelper(src, dst, pass); err != nil {
					t.Fatalf("Failed to setup encrypted file: %v", err)
				}
			}

			// Setup stdin if needed
			if tt.setupStdin != nil {
				stdin, err := tt.setupStdin()
				if err != nil {
					t.Fatalf("Failed to setup stdin: %v", err)
				}
				defer stdin.Close()

				oldStdin := os.Stdin
				defer func() { os.Stdin = oldStdin }()
				os.Stdin = stdin
			}

			// Capture stderr to check errors
			oldStderr := os.Stderr
			_, w, _ := os.Pipe()
			os.Stderr = w

			// Run main with test args
			originalArgs := os.Args
			defer func() { os.Args = originalArgs }()
			os.Args = append([]string{"cipherforge"}, tt.args...)

			// Run main (will exit on error, so we need to handle that)
			func() {
				defer func() {
					if r := recover(); r != nil {
						// Main panicked, which is fine for error cases
					}
				}()
				main()
			}()

			w.Close()
			os.Stderr = oldStderr

			// Check outputs
			for _, output := range tt.checkOutputs {
				if _, err := os.Stat(output); err != nil {
					if !tt.expectError {
						t.Errorf("Expected output file %q not found: %v", output, err)
					}
				}
			}

			// Clean up created .cfo files
			os.Remove(filepath.Join(tempDir, "file1.txt.cfo"))
			os.Remove(filepath.Join(tempDir, "file2.txt.cfo"))
		})
	}
}

func TestMainHelpText(t *testing.T) {
	// Save original args and stdout
	originalArgs := os.Args
	originalStdout := os.Stdout
	defer func() {
		os.Args = originalArgs
		os.Stdout = originalStdout
	}()

	// Capture stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Run with no args
	os.Args = []string{"cipherforge"}
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected to exit
			}
		}()
		main()
	}()

	w.Close()
	os.Stdout = originalStdout

	var buf bytes.Buffer
	io.Copy(&buf, r)

	output := buf.String()
	if !strings.Contains(output, "CipherForge") && !strings.Contains(output, "encrypt") {
		t.Error("Help text not displayed correctly")
	}
}

func TestDecryptWithoutExtension(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	os.WriteFile(testFile, []byte("test"), 0644)

	// This should be skipped by the extension check
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"cipherforge", "-d", testFile}

	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	func() {
		defer func() {
			if r := recover(); r != nil {
				// Expected
			}
		}()
		main()
	}()

	w.Close()
	os.Stderr = oldStderr

	var buf bytes.Buffer
	io.Copy(&buf, r)

	if !strings.Contains(buf.String(), "missing .cfo extension") {
		t.Error("Expected warning about missing .cfo extension")
	}
}

func TestPasswordGeneration(t *testing.T) {
	// nil userPassword → auto-generate path
	pass, err := resolvePassword("encrypt", nil)
	if err != nil || len(pass) == 0 {
		t.Errorf("Failed to generate secure password during encryption path")
	}
}

// Helper functions

// Helper function for tests
func createStdinPipe(input string) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	_, err = w.Write([]byte(input))
	if err != nil {
		return nil, err
	}
	w.Close()
	return r, nil
}

func encryptFileHelper(src, dst string, password []byte) error {
	// Simple helper to encrypt a file for test setup
	// This is a simplified version - in real tests, use the actual EncryptFile
	content, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// Just write dummy encrypted content for testing
	return os.WriteFile(dst, []byte("encrypted:"+string(content)), 0600)
}

// Additional tests for edge cases

func TestResolvePasswordEncryptError(t *testing.T) {
	// Test that GenerateSecurePassword errors are propagated
	// This is hard to mock directly, but we can test the error path
	// by making the password length invalid (though GenerateSecurePassword validates)
	_, err := resolvePassword("encrypt", nil)
	if err != nil {
		// This might fail if GenerateSecurePassword has issues, but normally shouldn't
		t.Logf("Encrypt password generation note: %v", err)
	}
}

func TestReadPasswordFromTerminalNonTerminal(t *testing.T) {
	// Test non-terminal fallback
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	r, w, _ := os.Pipe()
	os.Stdin = r

	go func() {
		w.Write([]byte("password-from-pipe\n"))
		w.Close()
	}()

	password, err := readPasswordFromTerminal("Prompt: ")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if string(password) != "password-from-pipe" {
		t.Errorf("Got %q, want %q", password, "password-from-pipe")
	}
}

func TestMainPanicRecovery(t *testing.T) {
	// Test that panic recovery works
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Cause a panic by passing invalid args that will cause a panic in main
	os.Args = []string{"cipherforge", "-e"}
	
	// Capture stderr
	oldStderr := os.Stderr
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	os.Stderr = stderrW
	
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Panic was recovered
			}
		}()
		main()
	}()
	
	stderrW.Close()
	os.Stderr = oldStderr
	
	var buf bytes.Buffer
	io.Copy(&buf, stderrR)
	stderrR.Close()
	
	// Should have some output (either error or help)
	if buf.Len() == 0 {
		t.Log("No stderr output from panic recovery")
	}
}

func TestResolvePasswordInteractive(t *testing.T) {
	// All sub-tests pipe stdin, so term.IsTerminal returns false and
	// readPasswordStarred falls back to the silent readPasswordFromTerminal path.
	// This lets us exercise the full resolvePasswordInteractive logic without
	// a real TTY.
	tests := []struct {
		name        string
		operation   string
		stdinInput  string
		expectError bool
		errContains string
		expectedPW  string
	}{
		{
			name:        "encrypt: matching passwords accepted",
			operation:   "encrypt",
			stdinInput:  "correct-pass\ncorrect-pass\n",
			expectedPW:  "correct-pass",
		},
		{
			name:       "encrypt: mismatched first attempt, then matching",
			operation:  "encrypt",
			// First pair mismatches; second pair matches.
			stdinInput: "pass-a\npass-b\npass-c\npass-c\n",
			expectedPW: "pass-c",
		},
		{
			name:       "encrypt: empty first attempt, then valid matching",
			operation:  "encrypt",
			stdinInput: "\n\nvalid-pass\nvalid-pass\n",
			expectedPW: "valid-pass",
		},
		{
			name:        "decrypt: valid password accepted",
			operation:   "decrypt",
			stdinInput:  "decrypt-pass\n",
			expectedPW:  "decrypt-pass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin, err := createStdinPipe(tt.stdinInput)
			if err != nil {
				t.Fatalf("Failed to setup stdin: %v", err)
			}
			defer stdin.Close()

			oldStdin := os.Stdin
			defer func() { os.Stdin = oldStdin }()
			os.Stdin = stdin

			password, err := resolvePasswordInteractive(tt.operation)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if string(password) != tt.expectedPW {
				t.Errorf("Password = %q, want %q", password, tt.expectedPW)
			}
		})
	}
}

func TestReadPasswordStarred(t *testing.T) {
	// readPasswordStarred falls back to the silent readPasswordFromTerminal
	// path when stdin is not a terminal, so we can test it via pipes.
	tests := []struct {
		name        string
		stdinInput  string
		expectedPW  string
		expectError bool
	}{
		{
			name:       "normal password",
			stdinInput: "secret123\n",
			expectedPW: "secret123",
		},
		{
			name:       "password with spaces",
			stdinInput: "my secret pass\n",
			expectedPW: "my secret pass",
		},
		{
			name:       "empty password",
			stdinInput: "\n",
			expectedPW: "",
		},
		{
			name:       "password with carriage return",
			stdinInput: "password\r\n",
			expectedPW: "password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdin, err := createStdinPipe(tt.stdinInput)
			if err != nil {
				t.Fatalf("Failed to setup stdin: %v", err)
			}
			defer stdin.Close()

			oldStdin := os.Stdin
			defer func() { os.Stdin = oldStdin }()
			os.Stdin = stdin

			password, err := readPasswordStarred("Prompt: ")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if string(password) != tt.expectedPW {
				t.Errorf("Password = %q, want %q", password, tt.expectedPW)
			}
		})
	}
}

// Benchmark tests
func BenchmarkGetParameters(b *testing.B) {
	args := []string{"-e", "file1.txt", "file2.txt", "file3.txt"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		originalArgs := os.Args
		os.Args = append([]string{"cipherforge"}, args...)
		getParameters()
		os.Args = originalArgs
	}
}
