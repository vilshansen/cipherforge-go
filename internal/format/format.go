package format

import (
	"encoding/binary"
	"io"
)

const (
	Magic       = "\xC1\x50\x48\x52\x46\x30\x52\x47"
	MagicSize   = 8
	FileVersion = uint32(1)
	VersionSize = 4
	XNonceSize  = 24
	SaltSize    = 16
	HMACSize    = 32
	TrailerSize = 8 + HMACSize
	SegmentSize = 1048576

	SegmentNonceContext = "cipherforge-segment-nonce-v1"
	TrailerHMACContext  = "cipherforge-trailer-hmac-v1"
)

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
