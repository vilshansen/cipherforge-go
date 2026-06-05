package ui

import (
	"testing"
)

func TestRunProgressBar(t *testing.T) {
	// Best-effort test for RunProgressBar: ensure it doesn't panic.
	tests := []struct {
		name    string
		prefix  string
		percent int
	}{
		{"0%", "Test", 0},
		{"50%", "Test", 50},
		{"100%", "Test", 100},
		{"Negative", "Test", -10},
		{"Over 100", "Test", 110},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RunProgressBar(tt.prefix, tt.percent)
		})
	}
}
