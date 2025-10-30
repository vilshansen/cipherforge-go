package headers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/constants"
)

type FileHeader struct {
	Magic    string
	ScryptN  int
	ScryptR  int
	ScryptP  int
	Salt     []byte
	Nonce    []byte
	FileName string
}

func GetHeaderBytes(header FileHeader) []byte {
	var buf bytes.Buffer
	magic := []byte(header.Magic)

	// Skriv Magic Marker
	buf.Write(magic)

	// Skriv Scrypt Parametre (Big Endian)
	binary.Write(&buf, binary.BigEndian, uint32(header.ScryptN))
	binary.Write(&buf, binary.BigEndian, uint32(header.ScryptR))
	binary.Write(&buf, binary.BigEndian, uint32(header.ScryptP))

	// Skriv Salt (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.Salt)))
	buf.Write(header.Salt)

	// Skriv XNonce (Længde + Data)
	binary.Write(&buf, binary.BigEndian, uint32(len(header.Nonce)))
	buf.Write(header.Nonce)

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
	header.Magic = string(magic)
	if header.Magic != constants.MagicMarker {
		return header, fmt.Errorf("ukendt filformat. Forventet: %s, Fundet: %s", constants.MagicMarker, header.Magic)
	}
	var n, r, p uint32
	if err := binary.Read(input, binary.BigEndian, &n); err != nil {
		return header, fmt.Errorf("fejl ved læsning af scrypt N: %w", err)
	}
	if err := binary.Read(input, binary.BigEndian, &r); err != nil {
		return header, fmt.Errorf("fejl ved læsning af scrypt R: %w", err)
	}
	if err := binary.Read(input, binary.BigEndian, &p); err != nil {
		return header, fmt.Errorf("fejl ved læsning af scrypt P: %w", err)
	}
	header.ScryptN = int(n)
	header.ScryptR = int(r)
	header.ScryptP = int(p)
	var saltLen uint32
	if err := binary.Read(input, binary.BigEndian, &saltLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af længde på salt: %w", err)
	}
	header.Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(input, header.Salt); err != nil {
		return header, fmt.Errorf("fejl ved læsning af salt: %w", err)
	}
	var nonceLen uint32
	if err := binary.Read(input, binary.BigEndian, &nonceLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af længde på nonce: %w", err)
	}
	if nonceLen != constants.XNonceSize {
		return header, fmt.Errorf("ugyldig længde på nonce: %d, forventet %d", nonceLen, constants.XNonceSize)
	}
	header.Nonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(input, header.Nonce); err != nil {
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
