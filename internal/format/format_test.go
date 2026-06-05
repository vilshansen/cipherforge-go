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
	if Magic != "\xC1\x50\x48\x52\x46\x30\x52\x47" {
		t.Errorf("unexpected Magic: %q", Magic)
	}
	if MagicSize != 8 {
		t.Errorf("unexpected MagicSize: %d", MagicSize)
	}
}
