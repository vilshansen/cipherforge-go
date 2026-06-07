package format

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic       = "\xC1\x50\x48\x52\x46\x30\x52\x47"
	MagicSize   = 8
	FileVersion = uint32(2)
	VersionSize = 4
	XNonceSize  = 24
	SaltSize    = 16
	HMACSize    = 32

	// Argon2ParamSize is the on-disk size of the serialised Argon2Params struct:
	// 4 (time) + 4 (memory) + 1 (threads) + 3 (reserved).
	Argon2ParamSize = 12

	TrailerSize = 8 + HMACSize
	SegmentSize = 1048576

	// HeaderSize is the full v2 header size: magic + version + salt + seed + params.
	HeaderSize = MagicSize + VersionSize + SaltSize + XNonceSize + Argon2ParamSize // 64

	// V1HeaderSize is the legacy v1 header size for backward-compatible reads.
	V1HeaderSize = MagicSize + VersionSize + SaltSize + XNonceSize // 52

	SegmentNonceContext  = "cipherforge-segment-nonce-v1"
	TrailerHMACContext   = "cipherforge-trailer-hmac-v1"
	TrailerHMACContextV2 = "cipherforge-trailer-hmac-v2"
)

// Argon2Params holds the tunable parameters for the Argon2id KDF.
// Memory is stored in KiB; Time is the number of passes; Threads is the
// degree of parallelism.
type Argon2Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultArgon2Params returns the production-hardened defaults (4 passes,
// 1 GiB memory, 4 threads).  These are used when decrypting v1 files that
// carry no embedded parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Time:    4,
		Memory:  1024 * 1024, // 1 GiB in KiB
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
