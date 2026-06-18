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

func TestArgon2ParamsRoundTrip(t *testing.T) {
	original := Argon2Params{
		Time:    3,
		Memory:  256 * 1024, // 256 MiB
		Threads: 2,
	}

	buf := &bytes.Buffer{}
	if err := WriteArgon2Params(buf, original); err != nil {
		t.Fatalf("WriteArgon2Params failed: %v", err)
	}

	if buf.Len() != Argon2ParamSize {
		t.Errorf("serialized size = %d, want %d", buf.Len(), Argon2ParamSize)
	}

	got, err := ReadArgon2Params(buf)
	if err != nil {
		t.Fatalf("ReadArgon2Params failed: %v", err)
	}

	if got.Time != original.Time {
		t.Errorf("Time = %d, want %d", got.Time, original.Time)
	}
	if got.Memory != original.Memory {
		t.Errorf("Memory = %d, want %d", got.Memory, original.Memory)
	}
	if got.Threads != original.Threads {
		t.Errorf("Threads = %d, want %d", got.Threads, original.Threads)
	}
}

func TestDefaultArgon2Params(t *testing.T) {
	p := DefaultArgon2Params()
	if p.Time != 4 {
		t.Errorf("Time = %d, want 4", p.Time)
	}
	if p.Memory != 1024*1024 {
		t.Errorf("Memory = %d, want %d", p.Memory, 1024*1024)
	}
	if p.Threads != 4 {
		t.Errorf("Threads = %d, want 4", p.Threads)
	}
}

func TestPayloadOffset(t *testing.T) {
	tests := []struct {
		version uint32
		want    int64
	}{
		{1, 52},
		{2, 64},
		{3, 64}, // unknown future versions use v2 layout
	}
	for _, tt := range tests {
		got := PayloadOffset(tt.version)
		if got != tt.want {
			t.Errorf("PayloadOffset(%d) = %d, want %d", tt.version, got, tt.want)
		}
	}
}

func TestConstants(t *testing.T) {
	if Magic != "\xC1\x50\x48\x52\x46\x30\x52\x47" {
		t.Errorf("unexpected Magic: %q", Magic)
	}
	if MagicSize != 8 {
		t.Errorf("unexpected MagicSize: %d", MagicSize)
	}
	if FileVersion != 3 {
		t.Errorf("FileVersion = %d, want 3", FileVersion)
	}
	if Argon2ParamSize != 12 {
		t.Errorf("Argon2ParamSize = %d, want 12", Argon2ParamSize)
	}
	if HeaderSize != 64 {
		t.Errorf("HeaderSize = %d, want 64", HeaderSize)
	}
}
