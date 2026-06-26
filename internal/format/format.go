package format

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic       = "\xC1\x50\x48\x52\x46\x30\x52\x47"
	MagicSize   = 8
	FileVersion = uint32(3)
	VersionSize = 4
	XNonceSize  = 24
	SaltSize    = 16
	HMACSize    = 32

	// Argon2ParamSize is the on-disk size of the serialised Argon2Params struct:
	// 4 (time) + 4 (memory) + 1 (threads) + 3 (reserved).
	Argon2ParamSize = 12

	// Maximum acceptable Argon2id parameters when reading from a file header.
	// These ceilings prevent a crafted file from causing resource exhaustion
	// during key derivation.
	MaxArgon2Time   = 10
	MaxArgon2Memory = 16 * 1024 * 1024 // 16 GiB in KiB

	TrailerSize = 8 + HMACSize
	SegmentSize = 1048576

	// HeaderSize is the full v3 header size: magic + version + salt + seed + params.
	HeaderSize = MagicSize + VersionSize + SaltSize + XNonceSize + Argon2ParamSize // 64

	// V1HeaderSize is the legacy v1 header size for backward-compatible reads.
	V1HeaderSize = MagicSize + VersionSize + SaltSize + XNonceSize // 52

	SegmentNonceContext   = "cipherforge-segment-nonce-v1"
	TrailerHMACContext    = "cipherforge-trailer-hmac-v1"
	TrailerHMACContextV2  = "cipherforge-trailer-hmac-v2"
	TrailerHMACContextV3  = "cipherforge-trailer-hmac-v3"
	MasterKeySalt         = "cipherforge-master-key-v1"
	FileKeyContext        = "cipherforge-file-key-v1"
)

// Argon2Params holds the tunable parameters for the Argon2id KDF.
// Memory is stored in KiB; Time is the number of passes; Threads is the
// degree of parallelism.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultArgon2Params returns the production-hardened defaults (5 passes,
// 256 MiB memory, 4 threads). These are used when decrypting v1 files that
// carry no embedded parameters.
//
// Rationale for 256 MiB (down from 1 GiB in earlier versions):
//
// For auto-generated 44-char passwords (~258 bits), the KDF parameters are
// cryptographically irrelevant — the keyspace is physically unsearchable.
// For user-supplied passwords, 256 MiB is the threshold that forces even a
// custom-ASIC attacker into external DRAM (rather than on-die SRAM), which
// is where Argon2id's memory-hardness imposes real economic cost. Above
// 256 MiB, returns diminish: 1 GiB quadruples attacker per-core memory cost
// but also quadruples user wait time. Five passes (up from 4) compensates
// for the reduced memory by making time-memory tradeoff attacks more
// expensive, at negligible runtime cost. The result is ~1 s per derivation
// on modern hardware while keeping brute-force cost above $200K in ASIC
// silicon even for a weak 8-character password.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    5,
		Memory:  256 * 1024, // 256 MiB in KiB
		Threads: 4,
	}
}

// WriteArgon2Params serialises p to w in big-endian format followed by
// three reserved zero bytes for forward compatibility.
func WriteArgon2Params(w io.Writer, p Argon2Params) error {
	if err := WriteUint32(w, p.Time); err != nil {
		return fmt.Errorf("argon2 params time: %w", err)
	}
	if err := WriteUint32(w, p.Memory); err != nil {
		return fmt.Errorf("argon2 params memory: %w", err)
	}
	var tail [4]byte
	tail[0] = p.Threads
	// bytes 1-3 stay zero (reserved)
	if _, err := w.Write(tail[:]); err != nil {
		return fmt.Errorf("argon2 params threads+reserved: %w", err)
	}
	return nil
}

// ReadArgon2Params deserialises an Argon2Params from r.  The three
// reserved bytes are read and discarded.
func ReadArgon2Params(r io.Reader) (Argon2Params, error) {
	var p Argon2Params
	time, err := ReadUint32(r)
	if err != nil {
		return p, fmt.Errorf("argon2 params time: %w", err)
	}
	mem, err := ReadUint32(r)
	if err != nil {
		return p, fmt.Errorf("argon2 params memory: %w", err)
	}
	var tail [4]byte
	if _, err := io.ReadFull(r, tail[:]); err != nil {
		return p, fmt.Errorf("argon2 params threads+reserved: %w", err)
	}
	p.Time = time
	p.Memory = mem
	p.Threads = tail[0]
	if p.Time == 0 || p.Memory == 0 || p.Threads == 0 {
		return p, fmt.Errorf("argon2 params must be non-zero: time=%d memory=%d threads=%d",
			p.Time, p.Memory, p.Threads)
	}
	if p.Time > MaxArgon2Time || p.Memory > MaxArgon2Memory {
		return p, fmt.Errorf("argon2 params exceed safety limits: time=%d (max %d) memory=%d KiB (max %d KiB)",
			p.Time, MaxArgon2Time, p.Memory, MaxArgon2Memory)
	}
	return p, nil
}

// PayloadOffset returns the byte offset where the payload starts for a
// given format version.  v1 = 52, v2 = 64.
func PayloadOffset(version uint32) int64 {
	if version <= 1 {
		return int64(V1HeaderSize)
	}
	return int64(HeaderSize)
}

func WriteUint64(w io.Writer, v uint64) error {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func WriteUint32(w io.Writer, v uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	_, err := w.Write(buf[:])
	return err
}

func ReadUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf[:]), nil
}

func ReadUint32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}
