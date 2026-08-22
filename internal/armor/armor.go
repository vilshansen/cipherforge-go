// Package armor provides GPG-style ASCII armor for base64-encoded Cipherforge
// output. The base64 body is wrapped at a fixed column width and surrounded by
// recognizable BEGIN/END marker lines, so ciphertext can be copied and pasted
// like an OpenPGP message. Like GPG, the armor includes a Version header line
// and a CRC-24 checksum line before the footer.
//
// Decoding requires armored input; bare (un-armored) base64 is rejected.
package armor

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	// BlockWidth is the number of base64 characters per body line.
	BlockWidth = 68

	// Header and Footer delimit the armored body.
	Header = "-----BEGIN CIPHERFORGE MESSAGE-----"
	Footer = "-----END CIPHERFORGE MESSAGE-----"

	// Version is a GPG-style header line identifying the armor emitter.
	Version = "Version: Cipherforge 1"
)

// CRC-24 (OpenPGP) parameters.
const (
	crc24Init = 0xB704CE
	crc24Poly = 0x864CFB
)

// crc24Update folds one byte into a running CRC-24 value.
func crc24Update(crc uint32, b byte) uint32 {
	crc ^= uint32(b) << 16
	for i := 0; i < 8; i++ {
		crc <<= 1
		if crc&0x1000000 != 0 {
			crc ^= crc24Poly
		}
	}
	return crc & 0xFFFFFF
}

// crc24 returns the OpenPGP CRC-24 of data.
func crc24(data []byte) uint32 {
	crc := uint32(crc24Init)
	for _, b := range data {
		crc = crc24Update(crc, b)
	}
	return crc
}

// checksumLine returns the gpg-style "=XXXX" line for the given CRC-24 value.
func checksumLine(sum uint32) string {
	b := []byte{byte(sum >> 16), byte(sum >> 8), byte(sum)}
	return "=" + base64.StdEncoding.EncodeToString(b)
}

// lineWriter inserts a newline every width columns.
type lineWriter struct {
	w     io.Writer
	col   int
	width int
}

func (lw *lineWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if lw.col >= lw.width {
			if _, err := io.WriteString(lw.w, "\n"); err != nil {
				return 0, err
			}
			lw.col = 0
		}
		n := len(p)
		if room := lw.width - lw.col; n > room {
			n = room
		}
		if _, err := lw.w.Write(p[:n]); err != nil {
			return 0, err
		}
		lw.col += n
		p = p[n:]
	}
	return total, nil
}

// crcWriter updates a running CRC-24 over written bytes and forwards them.
type crcWriter struct {
	w   io.Writer
	crc uint32
}

func (cw *crcWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		cw.crc = crc24Update(cw.crc, b)
	}
	return cw.w.Write(p)
}

// encodeWriter streams base64-encoded, line-wrapped armor to the underlying
// writer. Write appends body data; Close emits the footer and must be called
// to finish the block.
type encodeWriter struct {
	w       io.Writer
	started bool
	closed  bool
	lw      *lineWriter
	buf     *bufio.Writer
	b64     io.WriteCloser
	crc     *crcWriter
}

func (ew *encodeWriter) init() error {
	if ew.started {
		return nil
	}
	ew.started = true
	if _, err := io.WriteString(ew.w, Header+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(ew.w, Version+"\n\n"); err != nil {
		return err
	}
	ew.lw = &lineWriter{w: ew.w, width: BlockWidth}
	ew.buf = bufio.NewWriter(ew.lw)
	ew.crc = &crcWriter{w: ew.buf, crc: crc24Init}
	ew.b64 = base64.NewEncoder(base64.StdEncoding, ew.crc)
	return nil
}

func (ew *encodeWriter) Write(p []byte) (int, error) {
	if err := ew.init(); err != nil {
		return 0, err
	}
	return ew.b64.Write(p)
}

func (ew *encodeWriter) Close() error {
	if ew.closed {
		return nil
	}
	ew.closed = true
	if err := ew.init(); err != nil {
		return err
	}
	if err := ew.b64.Close(); err != nil {
		return err
	}
	if err := ew.buf.Flush(); err != nil {
		return err
	}
	// End the final body line, then emit the CRC-24 checksum and footer.
	if _, err := io.WriteString(ew.w, "\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(ew.w, checksumLine(ew.crc.crc)+"\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(ew.w, Footer+"\n"); err != nil {
		return err
	}
	return nil
}

// EncodeWriter returns a WriteCloser that wraps written bytes in ASCII armor.
// Call Close to emit the footer and flush all output.
func EncodeWriter(w io.Writer) io.WriteCloser {
	return &encodeWriter{w: w}
}

// EncodeBytes returns data wrapped in ASCII armor as a string.
func EncodeBytes(data []byte) (string, error) {
	var buf bytes.Buffer
	ew := EncodeWriter(&buf)
	if _, err := ew.Write(data); err != nil {
		return "", err
	}
	if err := ew.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// DecodeBytes decodes armored base64 back into bytes.
func DecodeBytes(data []byte) ([]byte, error) {
	body, sum, err := armorBody(data)
	if err != nil {
		return nil, err
	}
	if sum != "" {
		if want := checksumLine(crc24([]byte(body))); want != sum {
			return nil, fmt.Errorf("armor checksum mismatch (corrupt or altered input)")
		}
	}
	return base64.StdEncoding.DecodeString(body)
}

// DecodeString decodes armored base64 back into bytes.
func DecodeString(s string) ([]byte, error) {
	return DecodeBytes([]byte(s))
}

// armorBody strips the armor markers, header lines, and the trailing
// checksum line, returning the raw base64 body and any gpg-style "=XXXX"
// checksum ("" if absent). Input must be armored.
func armorBody(data []byte) (body, checksum string, err error) {
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, "-----BEGIN") {
		return "", "", fmt.Errorf("input is not armored (missing %q header)", Header)
	}

	var bodyLines []string
	inBody := false
	seenBlank := false
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-----BEGIN"):
			inBody = true
		case strings.HasPrefix(line, "-----END"):
			inBody = false
		case inBody && line == "":
			seenBlank = true
		case inBody && seenBlank && strings.HasPrefix(line, "="):
			checksum = line
		case inBody && seenBlank:
			bodyLines = append(bodyLines, line)
		case inBody && !seenBlank && !strings.Contains(line, ":"):
			// No blank separator seen yet: treat base64-looking lines as
			// body while skipping header lines such as "Version: ...".
			bodyLines = append(bodyLines, line)
		}
	}
	return strings.Join(bodyLines, ""), checksum, nil
}
