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
	Argon2Salt   []byte
	XChaChaNonce []byte
	FileName     string
}

func GetHeaderBytes(header FileHeader) []byte {
	var buf bytes.Buffer
	magicMarker := []byte(header.MagicMarker)

	// Skriv Magic Marker
	buf.Write(magicMarker)

	// Skriv Salt (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.Argon2Salt)))
	buf.Write(header.Argon2Salt)

	// Skriv XNonce (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.XChaChaNonce)))
	buf.Write(header.XChaChaNonce)

	// Skriv Originalt Filnavn (som UTF-8 streng, Længde + Data)
	fileNameBytes := []byte(header.FileName)
	binary.Write(&buf, binary.BigEndian, uint32(len(fileNameBytes)))
	buf.Write(fileNameBytes)

	return buf.Bytes()
}

func WriteHeader(header FileHeader, output io.Writer) (int64, error) {
	headerData := GetHeaderBytes(header)
	n, err := output.Write(headerData)
	if err != nil {
		return 0, fmt.Errorf("fejl ved skrivning af header: %w", err)
	}

	return int64(n), nil
}

// readHeader læser og validerer metadata fra filen.
func ReadHeader(input io.Reader) (FileHeader, error) {
	header := FileHeader{}
	magic := make([]byte, len(constants.MagicMarker))
	if _, err := io.ReadFull(input, magic); err != nil {
		return header, fmt.Errorf("fejl ved læsning af magic marker: %w", err)
	}
	header.MagicMarker = string(magic)
	if header.MagicMarker != constants.MagicMarker {
		return header, fmt.Errorf("ukendt filformat. Forventet: %s, Fundet: %s", constants.MagicMarker, header.MagicMarker)
	}
	var saltLen uint32
	if err := binary.Read(input, binary.BigEndian, &saltLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af længde på salt: %w", err)
	}
	header.Argon2Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(input, header.Argon2Salt); err != nil {
		return header, fmt.Errorf("fejl ved læsning af salt: %w", err)
	}
	var nonceLen uint32
	if err := binary.Read(input, binary.BigEndian, &nonceLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af længde på nonce: %w", err)
	}
	if nonceLen != constants.XNonceSize {
		return header, fmt.Errorf("ugyldig længde på nonce: %d, forventet %d", nonceLen, constants.XNonceSize)
	}
	header.XChaChaNonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(input, header.XChaChaNonce); err != nil {
		return header, fmt.Errorf("fejl ved læsning af nonce: %w", err)
	}
	var nameLen uint32
	if err := binary.Read(input, binary.BigEndian, &nameLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af længde på filnavn: %w", err)
	}
	fileNameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(input, fileNameBytes); err != nil {
		return header, fmt.Errorf("fejl ved læsning af filnavn: %w", err)
	}
	header.FileName = string(fileNameBytes)

	return header, nil
}
