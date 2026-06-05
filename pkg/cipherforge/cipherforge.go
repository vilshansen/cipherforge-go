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
	password []byte
}

func NewEncrypter(password []byte) *Encrypter {
	return &Encrypter{password: password}
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

	encKey, macKey := crypto.DeriveKeys(e.password, salt)
	defer crypto.ZeroBytes(encKey)
	defer crypto.ZeroBytes(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	bufIn := bufio.NewReaderSize(r, format.SegmentSize)
	bufOut := bufio.NewWriterSize(w, format.SegmentSize+aead.Overhead()+8)
	defer bufOut.Flush()

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

	trailer, err := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount)
	if err != nil {
		return err
	}
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
	if version != format.FileVersion {
		return fmt.Errorf("unsupported version")
	}

	salt := make([]byte, format.SaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return err
	}

	segmentSeed := make([]byte, format.XNonceSize)
	if _, err := io.ReadFull(r, segmentSeed); err != nil {
		return err
	}

	encKey, macKey := crypto.DeriveKeys(d.password, salt)
	defer crypto.ZeroBytes(encKey)
	defer crypto.ZeroBytes(macKey)

	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return err
	}

	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return err
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

	expectedHMAC, err := computeTrailerHMAC(macKey, salt, segmentSeed, segmentCount)
	if err != nil {
		return err
	}
	if !hmac.Equal(storedHMAC, expectedHMAC) {
		return fmt.Errorf("authentication failed")
	}

	if _, err := r.Seek(int64(format.MagicSize+format.VersionSize+format.SaltSize+format.XNonceSize), io.SeekStart); err != nil {
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

// Internal helpers ported exactly from fileutils.go

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

func computeTrailerHMAC(macKey, salt, segmentSeed []byte, segmentCount uint64) ([]byte, error) {
	h := hmac.New(sha256.New, macKey)
	h.Write([]byte(format.TrailerHMACContext))
	h.Write(salt)
	h.Write(segmentSeed)
	var countBuf [8]byte
	binary.BigEndian.PutUint64(countBuf[:], segmentCount)
	h.Write(countBuf[:])
	return h.Sum(nil), nil
}
