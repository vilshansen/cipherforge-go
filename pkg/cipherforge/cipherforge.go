package cipherforge

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Encrypter handles the encryption of a stream in segments.
type Encrypter struct {
	password  []byte
	params    format.Argon2Params
	masterKey []byte // optional: pre-derived master key for batch encryption
}

// NewEncrypter creates an Encrypter with the given password and production-hardened
// Argon2id parameters.
func NewEncrypter(password []byte) *Encrypter {
	return &Encrypter{
		password: password,
		params:   format.DefaultArgon2Params(),
	}
}

// NewEncrypterWithParams creates an Encrypter with custom Argon2id parameters.
func NewEncrypterWithParams(password []byte, params format.Argon2Params) *Encrypter {
	return &Encrypter{password: password, params: params}
}

// NewEncrypterWithMasterKey creates an Encrypter with a pre-derived master key for batch encryption.
// This skips the expensive Argon2id derivation, making encryption of multiple files much faster.
func NewEncrypterWithMasterKey(password []byte, masterKey []byte) *Encrypter {
	return &Encrypter{
		password:  password,
		params:    format.DefaultArgon2Params(),
		masterKey: masterKey,
	}
}

func (e *Encrypter) Encrypt(r io.Reader, w io.Writer, progress func(int64)) error {
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}

	segmentSeed := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(crypto.RandReader(), segmentSeed); err != nil {
		return err
	}

	// v3: Use optimized key derivation (master key + HKDF)
	var masterKey []byte
	var shouldZeroMasterKey bool
	if e.masterKey != nil {
		// Use pre-derived master key (batch encryption optimization)
		masterKey = e.masterKey
		shouldZeroMasterKey = false
	} else {
		// Derive master key on demand
		masterKey = crypto.DeriveMasterKey(e.password, e.params)
		shouldZeroMasterKey = true
	}
	if shouldZeroMasterKey {
		defer crypto.ZeroBytes(masterKey)
	}

	encKey, macKey := crypto.DeriveKeysFromMaster(masterKey, salt)
	defer crypto.ZeroBytes(encKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	bufIn := bufio.NewReaderSize(r, format.SegmentSize)
	bufOut := bufio.NewWriterSize(w, format.SegmentSize+aead.Overhead()+8)
	defer bufOut.Flush()

	// Header (v3 layout: 64 bytes).
	if _, err := bufOut.Write([]byte(format.Magic)); err != nil {
		return err
	}
	if err := format.WriteUint32(bufOut, format.FileVersion); err != nil {
		return err
	}
	if _, err := bufOut.Write(salt); err != nil {
		return err
	}
	if _, err := bufOut.Write(segmentSeed); err != nil {
		return err
	}
	if err := format.WriteArgon2Params(bufOut, e.params); err != nil {
		return err
	}

	plaintextBuf := make([]byte, format.SegmentSize)
	ciphertextBuf := make([]byte, 0, format.SegmentSize+aead.Overhead())
	aad := make([]byte, 16)
	var segmentCount uint64
	var bytesDone int64

	for {
		n, err := io.ReadFull(bufIn, plaintextBuf)
		if n > 0 {
			nonce, err := deriveSegmentNonce(segmentSeed, segmentCount)
			if err != nil {
				return err
			}

			buildAAD(aad, segmentCount, uint64(n))
			ciphertextBuf = aead.Seal(ciphertextBuf[:0], nonce, plaintextBuf[:n], aad)

			if err := format.WriteUint64(bufOut, uint64(len(ciphertextBuf))); err != nil {
				return err
			}
			if _, err := bufOut.Write(ciphertextBuf); err != nil {
				return err
			}

			segmentCount++
			bytesDone += int64(n)
			if progress != nil {
				progress(bytesDone)
			}
		}

		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if err := format.WriteUint64(bufOut, segmentCount); err != nil {
		return err
	}

	trailer := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount, e.params, format.FileVersion)
	crypto.ZeroBytes(macKey)
	if _, err := bufOut.Write(trailer); err != nil {
		return err
	}

	return nil
}

// Decrypter handles the decryption of a stream in segments.
type Decrypter struct {
	password []byte
}

func NewDecrypter(password []byte) *Decrypter {
	return &Decrypter{password: password}
}

func (d *Decrypter) Decrypt(r io.ReadSeeker, w io.Writer, progress func(int64)) error {
	magic := make([]byte, format.MagicSize)
	if _, err := io.ReadFull(r, magic); err != nil {
		return err
	}
	if string(magic) != format.Magic {
		return fmt.Errorf("not a valid .cfo file")
	}

	version, err := format.ReadUint32(r)
	if err != nil {
		return err
	}

	// v3 is the minimum supported version (v1 and v2 are no longer supported)
	if version < 3 {
		return fmt.Errorf("unsupported file version %d (v3+ required, use v2.1.0 to decrypt v1/v2 files)", version)
	}
	if version > format.FileVersion {
		return fmt.Errorf("file version %d is newer than this binary (v%d)", version, format.FileVersion)
	}

	salt := make([]byte, format.SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return err
	}

	segmentSeed := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(r, segmentSeed); err != nil {
		return err
	}

	// v3 requires Argon2id parameters in the header
	params, err := format.ReadArgon2Params(r)
	if err != nil {
		return err
	}

	// v3: Use optimized key derivation (master key + HKDF)
	masterKey := crypto.DeriveMasterKey(d.password, params)
	defer crypto.ZeroBytes(masterKey)

	encKey, macKey := crypto.DeriveKeysFromMaster(masterKey, salt)
	defer crypto.ZeroBytes(encKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if fileSize < int64(format.TrailerSize) {
		return fmt.Errorf("file too small to be a .cfo file")
	}

	trailerOffset := fileSize - int64(format.TrailerSize)
	if _, err := r.Seek(trailerOffset, io.SeekStart); err != nil {
		return err
	}

	trailerBuf := make([]byte, format.TrailerSize)
	if _, err := io.ReadFull(r, trailerBuf); err != nil {
		return err
	}

	segmentCount := binary.BigEndian.Uint64(trailerBuf[:8])
	storedHMAC := trailerBuf[8:]

	expectedHMAC := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount, params, version)
	if !hmac.Equal(storedHMAC, expectedHMAC) {
		crypto.ZeroBytes(macKey)
		return fmt.Errorf("authentication failed")
	}
	crypto.ZeroBytes(macKey)

	payloadOffset := format.HeaderSize
	if _, err := r.Seek(int64(payloadOffset), io.SeekStart); err != nil {
		return err
	}

	bufIn := bufio.NewReaderSize(r, format.SegmentSize+aead.Overhead()+8)
	bufOut := bufio.NewWriterSize(w, format.SegmentSize)
	defer bufOut.Flush()

	var bytesRead int64
	ciphertextBuf := make([]byte, format.SegmentSize+aead.Overhead())
	aad := make([]byte, 16)

	for i := uint64(0); i < segmentCount; i++ {
		segmentLen, err := format.ReadUint64(bufIn)
		if err != nil {
			return err
		}

		if segmentLen > uint64(format.SegmentSize+aead.Overhead()) {
			return fmt.Errorf("corrupt segment")
		}

		if _, err := io.ReadFull(bufIn, ciphertextBuf[:segmentLen]); err != nil {
			return err
		}

		nonce, err := deriveSegmentNonce(segmentSeed, i)
		if err != nil {
			return err
		}

		if segmentLen < uint64(aead.Overhead()) {
			return fmt.Errorf("corrupt segment")
		}
		plaintextLen := segmentLen - uint64(aead.Overhead())
		buildAAD(aad, i, plaintextLen)

		plaintext, err := aead.Open(ciphertextBuf[:0], nonce, ciphertextBuf[:segmentLen], aad)
		if err != nil {
			return err
		}

		if _, err := bufOut.Write(plaintext); err != nil {
			return err
		}

		bytesRead += int64(len(plaintext))
		if progress != nil {
			progress(bytesRead)
		}
	}

	return nil
}

// Internal helpers.

func buildAAD(dst []byte, segmentIndex, plaintextLen uint64) {
	binary.BigEndian.PutUint64(dst[:8], segmentIndex)
	binary.BigEndian.PutUint64(dst[8:], plaintextLen)
}

func deriveSegmentNonce(segmentSeed []byte, segmentCounter uint64) ([]byte, error) {
	contextBytes := []byte(format.SegmentNonceContext)
	info := make([]byte, len(contextBytes)+8)
	copy(info, contextBytes)
	binary.BigEndian.PutUint64(info[len(contextBytes):], segmentCounter)

	r := hkdf.New(sha256.New, segmentSeed, nil, info)
	nonce := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func computeTrailerHMAC(macKey, salt, segmentSeed []byte, segmentCount uint64, params format.Argon2Params, version uint32) []byte {
	h := hmac.New(sha256.New, macKey)

	if version <= 1 {
		// v1: context || salt || segmentSeed || segmentCount
		h.Write([]byte(format.TrailerHMACContext))
		h.Write(salt)
		h.Write(segmentSeed)
	} else if version == 2 {
		// v2: context-v2 || salt || segmentSeed || time || memory || threads || reserved || segmentCount
		h.Write([]byte(format.TrailerHMACContextV2))
		h.Write(salt)
		h.Write(segmentSeed)
		var buf [8]byte
		binary.BigEndian.PutUint32(buf[0:4], params.Time)
		binary.BigEndian.PutUint32(buf[4:8], params.Memory)
		h.Write(buf[:])
		h.Write([]byte{params.Threads, 0, 0, 0})
	} else {
		// v3+: context-v3 || salt || segmentSeed || time || memory || threads || reserved || segmentCount
		h.Write([]byte(format.TrailerHMACContextV3))
		h.Write(salt)
		h.Write(segmentSeed)
		var buf [8]byte
		binary.BigEndian.PutUint32(buf[0:4], params.Time)
		binary.BigEndian.PutUint32(buf[4:8], params.Memory)
		h.Write(buf[:])
		h.Write([]byte{params.Threads, 0, 0, 0})
	}

	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], segmentCount)
	h.Write(countBuf[:])
	return h.Sum(nil)
}
