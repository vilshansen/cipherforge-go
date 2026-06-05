package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetParameters(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tests := []struct {
		name      string
		args      []string
		wantOp    string
		wantFiles []string
		wantErr   bool
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			op, files, _, err := getParameters()
			if (err != nil) != tt.wantErr {
				t.Errorf("getParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if op != tt.wantOp {
					t.Errorf("op = %v, want %v", op, tt.wantOp)
				}
				if len(files) != len(tt.wantFiles) {
					t.Errorf("files = %v, want %v", files, tt.wantFiles)
				}
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

	tests := []struct {
		name    string
		inputs  []string
		wantLen int
		wantErr bool
	}{
		{
			name:    "literal file",
			inputs:  []string{f1},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "glob pattern",
			inputs:  []string{filepath.Join(tmpDir, "*.txt")},
			wantLen: 1,
			wantErr: false,
		},
		{
			name:    "no files found",
			inputs:  []string{filepath.Join(tmpDir, "*.nonexistent")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := expandInputPaths(tt.inputs, "encrypt")
			if (err != nil) != tt.wantErr {
				t.Errorf("expandInputPaths() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(files) != tt.wantLen {
				t.Errorf("len(files) = %d, want %d", len(files), tt.wantLen)
			}
		})
	}
}

func TestProcessFilePaths(t *testing.T) {
	tests := []struct {
		name      string
		op        string
		inputFile string
		wantError bool
	}{
		{"encrypt valid", "encrypt", "test.txt", false},
		{"decrypt valid", "decrypt", "test.txt.cfo", false},
		{"decrypt invalid ext", "decrypt", "test.txt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We only test the path logic here, not the actual encryption/decryption
			// which would require files.
			if tt.op == "decrypt" && !strings.HasSuffix(tt.inputFile, ".cfo") {
				if err := processFile(tt.op, tt.inputFile, nil); err == nil {
					t.Errorf("expected error for decrypting %s", tt.inputFile)
				}
			}
		})
	}
}
