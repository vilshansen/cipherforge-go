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
	if p.Time != 5 {
		t.Errorf("Time = %d, want 5", p.Time)
	}
	if p.Memory != 256*1024 {
		t.Errorf("Memory = %d, want %d", p.Memory, 256*1024)
	}
	if p.Threads != 4 {
		t.Errorf("Threads = %d, want 4", p.Threads)
	}
}

func TestConstants(t *testing.T) {
	if Magic != "\xC1\x50\x48\x52\x46\x30\x52\x47\x45" {
		t.Errorf("unexpected Magic: %q", Magic)
	}
	if MagicSize != 9 {
		t.Errorf("unexpected MagicSize: %d", MagicSize)
	}
	if FileVersion != 4 {
		t.Errorf("FileVersion = %d, want 4", FileVersion)
	}
	if Argon2ParamSize != 12 {
		t.Errorf("Argon2ParamSize = %d, want 12", Argon2ParamSize)
	}
	if HeaderSize != 65 {
		t.Errorf("HeaderSize = %d, want 65", HeaderSize)
	}
	if MaxArgon2Time != 10 {
		t.Errorf("MaxArgon2Time = %d, want 10", MaxArgon2Time)
	}
	if MaxArgon2Memory != 16*1024*1024 {
		t.Errorf("MaxArgon2Memory = %d, want %d", MaxArgon2Memory, 16*1024*1024)
	}
}

func TestReadArgon2ParamsBoundary(t *testing.T) {
	tests := []struct {
		name    string
		params  Argon2Params
		wantErr bool
	}{
		{"production defaults", DefaultArgon2Params(), false},
		{"minimal valid", Argon2Params{Time: 1, Memory: 1, Threads: 1}, false},
		{"max time", Argon2Params{Time: MaxArgon2Time, Memory: 1024, Threads: 1}, false},
		{"time exceeds max", Argon2Params{Time: MaxArgon2Time + 1, Memory: 1024, Threads: 1}, true},
		{"memory exceeds max", Argon2Params{Time: 1, Memory: MaxArgon2Memory + 1, Threads: 1}, true},
		{"zero time", Argon2Params{Time: 0, Memory: 1024, Threads: 1}, true},
		{"zero memory", Argon2Params{Time: 1, Memory: 0, Threads: 1}, true},
		{"zero threads", Argon2Params{Time: 1, Memory: 1024, Threads: 0}, true},
		{"all zero", Argon2Params{Time: 0, Memory: 0, Threads: 0}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			if err := WriteArgon2Params(buf, tt.params); err != nil {
				t.Fatalf("WriteArgon2Params failed: %v", err)
			}
			_, err := ReadArgon2Params(buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadArgon2Params() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTrailerSize(t *testing.T) {
	// Trailer is 8 bytes (segment count) + 32 bytes (HMAC-SHA256) = 40 bytes
	if TrailerSize != 8+HMACSize {
		t.Errorf("TrailerSize = %d, want %d", TrailerSize, 8+HMACSize)
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

func TestReadArgon2ParamsTruncated(t *testing.T) {
	// Provide fewer than 12 bytes — should fail.
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x04, 0x00})
	_, err := ReadArgon2Params(buf)
	if err == nil {
		t.Fatal("expected error for truncated Argon2 params")
	}
}

func TestMaxArgon2MemoryBoundary(t *testing.T) {
	// Exactly at the limit should succeed.
	params := Argon2Params{Time: 5, Memory: MaxArgon2Memory, Threads: 4}
	buf := &bytes.Buffer{}
	if err := WriteArgon2Params(buf, params); err != nil {
		t.Fatalf("WriteArgon2Params failed: %v", err)
	}
	got, err := ReadArgon2Params(buf)
	if err != nil {
		t.Fatalf("ReadArgon2Params failed at max memory boundary: %v", err)
	}
	if got.Memory != MaxArgon2Memory {
		t.Errorf("Memory = %d, want %d", got.Memory, MaxArgon2Memory)
	}
}

func TestMaxThreadsValue(t *testing.T) {
	// Threads can go up to 255 (uint8 max) — the validation only checks > 0.
	params := Argon2Params{Time: 5, Memory: 1024, Threads: 255}
	buf := &bytes.Buffer{}
	if err := WriteArgon2Params(buf, params); err != nil {
		t.Fatalf("WriteArgon2Params failed: %v", err)
	}
	got, err := ReadArgon2Params(buf)
	if err != nil {
		t.Fatalf("ReadArgon2Params failed with max threads: %v", err)
	}
	if got.Threads != 255 {
		t.Errorf("Threads = %d, want 255", got.Threads)
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

func TestReadArgon2ParamsReservedBytesIgnored(t *testing.T) {
	// The 3 reserved bytes after threads should be read and ignored,
	// regardless of their values. Write non-zero reserved bytes.
	params := Argon2Params{Time: 3, Memory: 1024, Threads: 2}
	buf := &bytes.Buffer{}
	WriteUint32(buf, params.Time)
	WriteUint32(buf, params.Memory)
	// Write threads + non-zero reserved bytes.
	buf.Write([]byte{params.Threads, 0xFF, 0xEE, 0xDD})

	got, err := ReadArgon2Params(buf)
	if err != nil {
		t.Fatalf("ReadArgon2Params failed: %v", err)
	}
	if got.Time != params.Time || got.Memory != params.Memory || got.Threads != params.Threads {
		t.Error("reserved bytes affected param reading")
	}
}
