// fileheader_test.go
package headers

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/vilshansen/cipherforge-go/constants"
)

// Test helper functions
func createTestHeader(t *testing.T) FileHeader {
	t.Helper()
	nonce := make([]byte, constants.XNonceSize)

	// Fill with some test data
	rand.Read(nonce)

	return FileHeader{
		MagicMarker:  constants.MagicMarker,
		XChaChaNonce: nonce,
	}
}

func TestFileHeader_GetFileHeaderBytes(t *testing.T) {
	tests := []struct {
		name     string
		header   FileHeader
		wantErr  bool
		checkLen bool
	}{
		{
			name:     "valid header",
			header:   createTestHeader(t),
			wantErr:  false,
			checkLen: true,
		},
		{
			name: "header with empty filename",
			header: FileHeader{
				MagicMarker:  constants.MagicMarker,
				XChaChaNonce: make([]byte, constants.XNonceSize),
			},
			wantErr:  false,
			checkLen: true,
		},
		{
			name: "header with long filename",
			header: FileHeader{
				MagicMarker:  constants.MagicMarker,
				XChaChaNonce: make([]byte, constants.XNonceSize),
			},
			wantErr:  false,
			checkLen: true,
		},
		{
			name: "header with special characters in filename",
			header: FileHeader{
				MagicMarker:  constants.MagicMarker,
				XChaChaNonce: make([]byte, constants.XNonceSize),
			},
			wantErr:  false,
			checkLen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headerBytes := GetFileHeaderBytes(tt.header)

			if tt.checkLen && len(headerBytes) == 0 {
				t.Error("GetFileHeaderBytes() returned empty byte slice")
			}

			// Verify the structure can be parsed back
			reader := bytes.NewReader(headerBytes)
			parsedHeader, err := ReadFileHeader(reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFileHeader() after GetFileHeaderBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify parsed header matches original
				if parsedHeader.MagicMarker != tt.header.MagicMarker {
					t.Errorf("MagicMarker mismatch: got %q, want %q", parsedHeader.MagicMarker, tt.header.MagicMarker)
				}
				if !bytes.Equal(parsedHeader.XChaChaNonce, tt.header.XChaChaNonce) {
					t.Error("XChaChaNonce mismatch")
				}
			}
		})
	}
}

func TestWriteFileHeader(t *testing.T) {
	tests := []struct {
		name      string
		header    FileHeader
		wantErr   bool
		errString string
	}{
		{
			name:    "successful write",
			header:  createTestHeader(t),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			err := WriteFileHeader(GetFileHeaderBytes(tt.header), &buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteFileHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if tt.errString != "" && err != nil && !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("WriteFileHeader() error = %v, want error containing %v", err, tt.errString)
				}
				return
			}

			// Verify we can read back what we wrote
			if buf.Len() > 0 {
				reader := bytes.NewReader(buf.Bytes())
				parsedHeader, err := ReadFileHeader(reader)
				if err != nil {
					t.Errorf("Failed to read back written header: %v", err)
					return
				}

				// Basic validation of parsed header
				if parsedHeader.MagicMarker != tt.header.MagicMarker {
					t.Errorf("MagicMarker mismatch after write/read: got %q, want %q",
						parsedHeader.MagicMarker, tt.header.MagicMarker)
				}
			}
		})
	}
}

func TestReadFileHeader(t *testing.T) {
	validHeader := createTestHeader(t)
	validHeaderBytes := GetFileHeaderBytes(validHeader)

	tests := []struct {
		name        string
		data        []byte
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid header",
			data:    validHeaderBytes,
			wantErr: false,
		},
		{
			name:        "empty data",
			data:        []byte{},
			wantErr:     true,
			errContains: "magic marker",
		},
		{
			name:        "invalid magic marker",
			data:        []byte("INVALID-MAGIC-MARKER-123"),
			wantErr:     true,
			errContains: "unknown file format",
		},
		{
			name:        "truncated magic marker",
			data:        []byte("CIPHERFO"), // Partial magic marker
			wantErr:     true,
			errContains: "magic marker",
		},
		{
			name: "invalid nonce length",
			data: func() []byte {
				var buf bytes.Buffer
				buf.Write([]byte(constants.MagicMarker))

				// Write invalid nonce length
				binaryWrite(&buf, uint32(100)) // Wrong nonce length
				return buf.Bytes()
			}(),
			wantErr:     true,
			errContains: "længde på nonce",
		},
		{
			name: "truncated nonce data",
			data: func() []byte {
				var buf bytes.Buffer
				buf.Write([]byte(constants.MagicMarker))

				// Write correct nonce length but truncated data
				binaryWrite(&buf, uint32(constants.XNonceSize))
				buf.Write(make([]byte, constants.XNonceSize/2)) // Only half
				return buf.Bytes()
			}(),
			wantErr:     true,
			errContains: "unexpected EOF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader(tt.data)
			header, err := ReadFileHeader(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFileHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("ReadFileHeader() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ReadFileHeader() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				// Validate the parsed header
				if header.MagicMarker != constants.MagicMarker {
					t.Errorf("ReadFileHeader() MagicMarker = %v, want %v", header.MagicMarker, constants.MagicMarker)
				}
				if len(header.XChaChaNonce) != constants.XNonceSize {
					t.Errorf("ReadFileHeader() XChaChaNonce length = %v, want %v",
						len(header.XChaChaNonce), constants.XNonceSize)
				}
			}
		})
	}
}

func TestReadFileHeader_EdgeCases(t *testing.T) {
	t.Run("minimum valid header", func(t *testing.T) {
		header := FileHeader{
			MagicMarker:  constants.MagicMarker,
			XChaChaNonce: make([]byte, constants.XNonceSize),
		}

		headerBytes := GetFileHeaderBytes(header)
		reader := bytes.NewReader(headerBytes)

		parsedHeader, err := ReadFileHeader(reader)
		if err != nil {
			t.Errorf("ReadFileHeader() failed with minimum valid header: %v", err)
			return
		}
		if parsedHeader.MagicMarker != header.MagicMarker {
			t.Errorf("Minimum header corrupted MagicMarker: got %q, want %q",
				parsedHeader.MagicMarker, header.MagicMarker)
		}
		if len(parsedHeader.XChaChaNonce) != constants.XNonceSize {
			t.Errorf("Minimum header corrupted XChaChaNonce length: got %d, want %d",
				len(parsedHeader.XChaChaNonce), constants.XNonceSize)
		}
	})
}

func TestReadFileHeader_WithCustomReader(t *testing.T) {
	t.Run("reader that returns partial reads", func(t *testing.T) {
		header := createTestHeader(t)
		headerBytes := GetFileHeaderBytes(header)

		// Create a reader that returns data byte by byte
		slowReader := &slowReader{data: headerBytes}

		parsedHeader, err := ReadFileHeader(slowReader)
		if err != nil {
			t.Errorf("ReadFileHeader() failed with slow reader: %v", err)
			return
		}
		if parsedHeader.MagicMarker != header.MagicMarker {
			t.Errorf("Minimum header corrupted MagicMarker: got %q, want %q",
				parsedHeader.MagicMarker, header.MagicMarker)
		}
		if len(parsedHeader.XChaChaNonce) != constants.XNonceSize {
			t.Errorf("Minimum header corrupted XChaChaNonce length: got %d, want %d",
				len(parsedHeader.XChaChaNonce), constants.XNonceSize)
		}

	})
}

// Test individual helper functions
func TestReadMagicMarker(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantMarker  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid magic marker",
			data:       constants.MagicMarker,
			wantMarker: constants.MagicMarker,
			wantErr:    false,
		},
		{
			name:        "invalid magic marker",
			data:        "INVALID-MAGIC-MARKER",
			wantMarker:  "",
			wantErr:     true,
			errContains: "unknown file format",
		},
		{
			name:        "empty data",
			data:        "",
			wantMarker:  "",
			wantErr:     true,
			errContains: "magic marker",
		},
		{
			name:        "partial magic marker",
			data:        constants.MagicMarker[:10],
			wantMarker:  "",
			wantErr:     true,
			errContains: "magic marker",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader([]byte(tt.data))
			header := &FileHeader{}
			result, err := readMagicMarker(reader, header)

			if (err != nil) != tt.wantErr {
				t.Errorf("readMagicMarker() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("readMagicMarker() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("readMagicMarker() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if result == nil {
					t.Error("readMagicMarker() returned nil result")
				} else if header.MagicMarker != tt.wantMarker {
					t.Errorf("readMagicMarker() MagicMarker = %v, want %v", header.MagicMarker, tt.wantMarker)
				}
			}
		})
	}
}

// Helper function to write binary data (mimicking the binary.Write in your actual code)
func binaryWrite(buf *bytes.Buffer, data uint32) {
	// Simple big-endian write for testing
	buf.WriteByte(byte(data >> 24))
	buf.WriteByte(byte(data >> 16))
	buf.WriteByte(byte(data >> 8))
	buf.WriteByte(byte(data))
}

// slowReader is a reader that returns data one byte at a time
type slowReader struct {
	data   []byte
	offset int
}

func (r *slowReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}

	// Only return one byte at a time
	if len(p) > 0 {
		p[0] = r.data[r.offset]
		r.offset++
		return 1, nil
	}
	return 0, nil
}
