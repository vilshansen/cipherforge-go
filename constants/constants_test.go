package constants

import "testing"

func TestConstants(t *testing.T) {
	if SegmentSize != 1048576 {
		t.Errorf("SegmentSize changed! Expected 1MB, got %d", SegmentSize)
	}
	if SaltSize != 16 {
		t.Errorf("SaltSize must be 16 for Argon2id, got %d", SaltSize)
	}
}
