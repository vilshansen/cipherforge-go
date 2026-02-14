package headers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/constants"
)

type FileHeader struct {
	MagicMarker  string
	XChaChaNonce []byte
}

func GetFileHeaderBytes(header FileHeader) []byte {
	var buf bytes.Buffer
	magicMarker := []byte(header.MagicMarker)

	// Skriv Magic Marker
	buf.Write(magicMarker)

	// Skriv XNonce (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.XChaChaNonce)))
	buf.Write(header.XChaChaNonce)

	return buf.Bytes()
}

func WriteFileHeader(headerData []byte, output io.Writer) error {
	n, err := output.Write(headerData)
	if n != len(headerData) || err != nil {
		return fmt.Errorf("fejl ved skrivning af header: %w", err)
	}
	return nil
}

// readHeader læser og validerer metadata fra filen.
func ReadFileHeader(input io.Reader) (FileHeader, error) {
	header := FileHeader{}
	if _, err := readMagicMarker(input, &header); err != nil {
		return header, err
	}

	if _, err := readNonce(input, &header); err != nil {
		return header, err
	}

	return header, nil
}

func readNonce(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var nonceLen uint32
	if err := binary.Read(input, binary.BigEndian, &nonceLen); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af længde på nonce: %w", err)
	}
	if nonceLen != constants.XNonceSize {
		return fileHeader, fmt.Errorf("ugyldig længde på nonce: %d, forventet %d", nonceLen, constants.XNonceSize)
	}
	fileHeader.XChaChaNonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(input, fileHeader.XChaChaNonce); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af nonce: %w", err)
	}
	return fileHeader, nil
}

func readMagicMarker(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	magic := make([]byte, len(constants.MagicMarker))
	if _, err := io.ReadFull(input, magic); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af magic marker: %w", err)
	}
	fileHeader.MagicMarker = string(magic)
	if fileHeader.MagicMarker != constants.MagicMarker {
		return fileHeader, fmt.Errorf("unknown file format. Expected: %s, Found: %s", constants.MagicMarker, fileHeader.MagicMarker)
	}
	return fileHeader, nil
}
