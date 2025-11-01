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

func GetFileHeaderBytes(header FileHeader) []byte {
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

func WriteFileHeader(header FileHeader, output io.Writer) (int64, error) {
	headerData := GetFileHeaderBytes(header)
	n, err := output.Write(headerData)
	if err != nil {
		return 0, fmt.Errorf("fejl ved skrivning af header: %w", err)
	}

	return int64(n), nil
}

// readHeader læser og validerer metadata fra filen.
func ReadFileHeader(input io.Reader) (FileHeader, error) {
	header := FileHeader{}
	if _, err := readMagicMarker(input, &header); err != nil {
		return header, err
	}

	if _, err := readSalt(input, &header); err != nil {
		return header, err
	}

	if _, err := readNonce(input, &header); err != nil {
		return header, err
	}

	if _, err := readFileName(input, &header); err != nil {
		return header, err
	}

	return header, nil
}

func readFileName(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var nameLen uint32
	if err := binary.Read(input, binary.BigEndian, &nameLen); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af længde på filnavn: %w", err)
	}
	fileNameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(input, fileNameBytes); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af filnavn: %w", err)
	}
	fileHeader.FileName = string(fileNameBytes)

	return fileHeader, nil
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

func readSalt(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var saltLen uint32
	if err := binary.Read(input, binary.BigEndian, &saltLen); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af længde på salt: %w", err)
	}
	fileHeader.Argon2Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(input, fileHeader.Argon2Salt); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af salt: %w", err)
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
		return fileHeader, fmt.Errorf("ukendt filformat. Forventet: %s, Fundet: %s", constants.MagicMarker, fileHeader.MagicMarker)
	}
	return fileHeader, nil
}
