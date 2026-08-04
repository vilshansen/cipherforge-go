package tui
package tui

import (
	"strings"
	"testing"
)

func TestWrap64(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"short", "hello", "hello"},
		{"exact wrap", strings.Repeat("A", 68), strings.Repeat("A", 68)},
		{"one wrap", strings.Repeat("A", 100), strings.Repeat("A", 68) + "\n" + strings.Repeat("A", 32)},
		{"two wraps", strings.Repeat("A", 150), strings.Repeat("A", 68) + "\n" + strings.Repeat("A", 68) + "\n" + strings.Repeat("A", 14)},
		{"empty", "", ""},
		{"multibyte", "héllo世界", "héllo世界"}, // no wrapping needed
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrap64(tt.input)
			if got != tt.want {
				t.Errorf("wrap64(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestBuildResults(t *testing.T) {
	r := buildResults("encrypt", "in.txt", "out.cfo", nil, "pwd123", "base64out", true)
	if !r.success {
		t.Error("expected success when err is nil")
	}
	if r.genPassword != "pwd123" {
		t.Errorf("genPassword = %q, want %q", r.genPassword, "pwd123")
	}
	if r.outputText != "base64out" {
		t.Errorf("outputText = %q, want %q", r.outputText, "base64out")
	}
	if !r.textMode {
		t.Error("textMode should be true")
	}

	r2 := buildResults("decrypt", "in.cfo", "out.txt", nil, "", "", false)
	if !r2.success {
		t.Error("expected success")
	}
	if r2.textMode {
		t.Error("textMode should be false")
	}
	if r2.genPassword != "" {
		t.Errorf("genPassword should be empty, got %q", r2.genPassword)
	}
}

func TestDeriveOutputPathTUI(t *testing.T) {
	tests := []struct {
		op    string
		input string
		want  string
	}{
		{"encrypt", "doc.pdf", "doc.pdf.cfo"},
		{"decrypt", "doc.pdf.cfo", "doc.pdf"},
		{"decrypt", "doc.pdf", "doc.pdf.dec"},
		{"encrypt", "file", "file.cfo"},
		{"decrypt", "archive.tar.gz.cfo", "archive.tar.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.op+"_"+tt.input, func(t *testing.T) {
			got := deriveOutputPathTUI(tt.op, tt.input)
			if got != tt.want {
				t.Errorf("deriveOutputPathTUI(%q, %q) = %q, want %q", tt.op, tt.input, got, tt.want)
			}
		})
	}
}
