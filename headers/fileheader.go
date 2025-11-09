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
	ScryptSalt   []byte
	ScryptN      int
	ScryptR      int
	ScryptP      int
	XChaChaNonce []byte
}

func GetFileHeaderBytes(header FileHeader) []byte {
	var buf bytes.Buffer
	magicMarker := []byte(header.MagicMarker)

	// Skriv Magic Marker
	buf.Write(magicMarker)

	// Skriv Salt (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.ScryptSalt)))
	buf.Write(header.ScryptSalt)

	// Skriv scrypt N
	binary.Write(&buf, binary.BigEndian, int32(header.ScryptN))

	// Skriv scrypt R
	binary.Write(&buf, binary.BigEndian, int32(header.ScryptR))

	// Skriv scrypt P
	binary.Write(&buf, binary.BigEndian, int32(header.ScryptP))

	// Skriv XNonce (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.XChaChaNonce)))
	buf.Write(header.XChaChaNonce)

	return buf.Bytes()
}

func WriteFileHeader(header FileHeader, output io.Writer) error {
	headerData := GetFileHeaderBytes(header)
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

	if _, err := readSalt(input, &header); err != nil {
		return header, err
	}

	if _, err := readScryptN(input, &header); err != nil {
		return header, err
	}

	if _, err := readScryptR(input, &header); err != nil {
		return header, err
	}

	if _, err := readScryptP(input, &header); err != nil {
		return header, err
	}

	if _, err := readNonce(input, &header); err != nil {
		return header, err
	}

	return header, nil
}

func readScryptN(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var ScryptN uint32
	if err := binary.Read(input, binary.BigEndian, &ScryptN); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af scrypt N: %w", err)
	}
	fileHeader.ScryptN = int(ScryptN)
	return fileHeader, nil
}

func readScryptR(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var ScryptR uint32
	if err := binary.Read(input, binary.BigEndian, &ScryptR); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af scrypt R: %w", err)
	}
	fileHeader.ScryptR = int(ScryptR)
	return fileHeader, nil
}

func readScryptP(input io.Reader, fileHeader *FileHeader) (*FileHeader, error) {
	var ScryptP uint32
	if err := binary.Read(input, binary.BigEndian, &ScryptP); err != nil {
		return fileHeader, fmt.Errorf("fejl ved læsning af scrypt P: %w", err)
	}
	fileHeader.ScryptP = int(ScryptP)
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
	fileHeader.ScryptSalt = make([]byte, saltLen)
	if _, err := io.ReadFull(input, fileHeader.ScryptSalt); err != nil {
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
