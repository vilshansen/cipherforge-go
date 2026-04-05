package constants

import "testing"

func TestCoreSizes(t *testing.T) {
	if XNonceSize != 24 {
		t.Errorf("XNonceSize must be 24, got %d", XNonceSize)
	}

	if SegmentSize != 1048576 {
		t.Errorf("SegmentSize must be 1MiB, got %d", SegmentSize)
	}

	if SaltSize != 16 {
		t.Errorf("SaltSize must be 16, got %d", SaltSize)
	}

	if HMACSize != 32 {
		t.Errorf("HMACSize must be 32, got %d", HMACSize)
	}

	expectedTrailer := 8 + HMACSize
	if TrailerSize != expectedTrailer {
		t.Errorf("TrailerSize must be 8 + HMACSize (%d), got %d", expectedTrailer, TrailerSize)
	}
}

func TestMagicAndVersion(t *testing.T) {
	// Magic must be exactly 8 bytes.
	if MagicSize != 8 {
		t.Errorf("MagicSize must be 8, got %d", MagicSize)
	}
	if len(Magic) != MagicSize {
		t.Errorf("len(Magic) must equal MagicSize (%d), got %d", MagicSize, len(Magic))
	}

	// First byte must be 0xC1 to match the 0xC1PHRF0RGE signature.
	if Magic[0] != 0xC1 {
		t.Errorf("Magic[0] must be 0xC1, got 0x%02X", Magic[0])
	}

	// Version field is 4 bytes.
	if VersionSize != 4 {
		t.Errorf("VersionSize must be 4, got %d", VersionSize)
	}

	// Initial format version must be 1.
	if FileVersion != 1 {
		t.Errorf("FileVersion must be 1, got %d", FileVersion)
	}
}

func TestPasswordConfig(t *testing.T) {
	if PasswordLength < 52 {
		t.Errorf("PasswordLength too small for full entropy, got %d", PasswordLength)
	}

	if len(CharacterPool) != 32 {
		t.Errorf("CharacterPool must have 32 characters, got %d", len(CharacterPool))
	}

	// Ensure no ambiguous characters (sanity check)
	for _, c := range "ILO" {
		if containsRune(CharacterPool, c) {
			t.Errorf("CharacterPool contains ambiguous character: %c", c)
		}
	}
}

func TestFileExtension(t *testing.T) {
	if FileExtension != ".cfo" {
		t.Errorf("FileExtension changed, got %s", FileExtension)
	}
}

func TestArgon2Params(t *testing.T) {
	if Argon2Time < 4 {
		t.Errorf("Argon2Time too low, got %d", Argon2Time)
	}

	if Argon2Memory < 1024*1024 {
		t.Errorf("Argon2Memory too low, got %d", Argon2Memory)
	}

	if Argon2Threads < 1 {
		t.Errorf("Argon2Threads must be >= 1, got %d", Argon2Threads)
	}
}

func TestHelpTextFormatting(t *testing.T) {
	if HelpTextShort == "" {
		t.Error("HelpTextShort must not be empty")
	}

	if HelpText == "" {
		t.Error("HelpText must not be empty")
	}

	if len(HelpText) <= len(HelpTextShort) {
		t.Error("HelpText should extend HelpTextShort")
	}
}

func TestVersionDefaults(t *testing.T) {
	if Version != "unknown" {
		t.Errorf("Default Version must be 'unknown', got %s", Version)
	}

	if GitCommit != "unknown" {
		t.Errorf("Default GitCommit must be 'unknown', got %s", GitCommit)
	}
}

// --- helpers ---

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}