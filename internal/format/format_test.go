package format

import (
	"bytes"
	"testing"
)

func TestSerialization(t *testing.T) {
	buf := &bytes.Buffer{}
	val64 := uint64(0x1122334455667788)
	if err := WriteUint64(buf, val64); err != nil {
		t.Fatalf("WriteUint64 failed: %v", err)
	}
	got64, err := ReadUint64(buf)
	if err != nil {
		t.Fatalf("ReadUint64 failed: %v", err)
	}
	if got64 != val64 {
		t.Errorf("got %x, want %x", got64, val64)
	}

	buf.Reset()
	val32 := uint32(0x11223344)
	if err := WriteUint32(buf, val32); err != nil {
		t.Fatalf("WriteUint32 failed: %v", err)
	}
	got32, err := ReadUint32(buf)
	if err != nil {
		t.Fatalf("ReadUint32 failed: %v", err)
	}
	if got32 != val32 {
		t.Errorf("got %x, want %x", got32, val32)
	}
}

func TestConstants(t *testing.T) {
	if Magic != "\xC1\x50\x48\x52\x46\x30\x52\x47\x45" {
		t.Errorf("unexpected Magic: %q", Magic)
	}
	if MagicSize != 9 {
		t.Errorf("unexpected MagicSize: %d", MagicSize)
	}
	if FileVersion != 7 {
		t.Errorf("FileVersion = %d, want 7", FileVersion)
	}
	if HeaderSize != 35 {
		t.Errorf("HeaderSize = %d, want 35", HeaderSize)
	}
}

func TestTrailerSize(t *testing.T) {
	// v6 trailer is 8 bytes (segment count) + 32 bytes (HMAC-SHA256) +
	// 32 bytes (key commitment) = 72 bytes
	if TrailerSize != 8+HMACSize+KeyCommitSize {
		t.Errorf("TrailerSize = %d, want %d", TrailerSize, 8+HMACSize+KeyCommitSize)
	}
}

func TestReadUint64Truncated(t *testing.T) {
	// Only 4 bytes available — should fail.
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x01})
	_, err := ReadUint64(buf)
	if err == nil {
		t.Fatal("expected error for truncated uint64 input")
	}
}

func TestReadUint32Truncated(t *testing.T) {
	// Only 2 bytes available — should fail.
	buf := bytes.NewReader([]byte{0x00, 0x01})
	_, err := ReadUint32(buf)
	if err == nil {
		t.Fatal("expected error for truncated uint32 input")
	}
}

func TestSegmentSizeConstant(t *testing.T) {
	if SegmentSize != 1048576 {
		t.Errorf("SegmentSize = %d, want 1048576", SegmentSize)
	}
}

func TestVersionSizeConstant(t *testing.T) {
	if VersionSize != 4 {
		t.Errorf("VersionSize = %d, want 4", VersionSize)
	}
}

func TestHMACSizeConstant(t *testing.T) {
	if HMACSize != 32 {
		t.Errorf("HMACSize = %d, want 32", HMACSize)
	}
}
