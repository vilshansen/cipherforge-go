package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	// Cryptographic constants (Key and MAC size)
	KeySize        = 32 // 256 bits for AES-256 (Encryption Key)
	MacKeySize     = 32 // 256 bits for HMAC-SHA256 (Authentication Key)
	TotalKeySize   = KeySize + MacKeySize
	SaltSize       = 16 // 128 bits
	NonceSize      = 16 // 128 bits for AES-CTR (Standard Nonce size for CTR)
	TagSize        = 32 // 256 bits for HMAC-SHA256 Tag
	PasswordLength = 32
	// Standard Scrypt Parametre for Kryptering
	ScryptN   = 1 << 15   // scrypt parameter N (iterations)
	ScryptR   = 8         // scrypt parameter r (block size)
	ScryptP   = 1         // scrypt parameter p (parallelization)
	ChunkSize = 64 * 1024 // Chunk size for streaming I/O

	// File format marker
	FileMagicMarker = "CIPHERFORGE-V00002" // Updated version for new structure
)

// Header struct defines the metadata stored at the start of the encrypted file
type Header struct {
	Magic        []byte
	ScryptN      uint32
	ScryptR      uint32
	ScryptP      uint32
	Salt         []byte
	Nonce        []byte
	OriginalName string
}

// ProgressWriter tracks bytes written and updates terminal progress
type ProgressWriter struct {
	Writer     io.Writer
	TotalBytes int64
	Written    int64
	StartTime  time.Time
}

// Write implements the io.Writer interface
func (pw *ProgressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.Writer.Write(p)
	pw.Written += int64(n)
	pw.updateProgress()
	return
}

// updateProgress prints the current progress to the terminal
func (pw *ProgressWriter) updateProgress() {
	if pw.TotalBytes == 0 {
		return
	}

	progress := float64(pw.Written) / float64(pw.TotalBytes) * 100
	elapsed := time.Since(pw.StartTime).Seconds()

	var rateStr string
	if elapsed > 0 {
		rate := float64(pw.Written) / elapsed // bytes per second
		rateStr = formatBytes(int64(rate)) + "/s"
	}

	// Terminal output update
	fmt.Printf("\rFremdrift: %.2f%% (%s/%s) [%s]",
		progress,
		formatBytes(pw.Written),
		formatBytes(pw.TotalBytes),
		rateStr,
	)
}

// generateSecurePassword generates a secure, random password
func generateSecurePassword(length int) (string, error) {
	const charPool = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}"
	b := make([]byte, length)

	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("kunne ikke generere tilfældige bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		b[i] = charPool[b[i]%byte(len(charPool))]
	}
	return string(b), nil
}

// DerivedKeys holds the two keys needed for Encrypt-then-MAC
type DerivedKeys struct {
	EncKey []byte // KeySize (32 bytes) for AES-CTR
	MacKey []byte // MacKeySize (32 bytes) for HMAC-SHA256
}

// deriveKey uses Scrypt to derive a single block of bytes and splits it into two keys.
func deriveKey(password string, salt []byte, N, R, P uint32) (DerivedKeys, error) {
	if password == "" {
		return DerivedKeys{}, fmt.Errorf("password kan ikke være tomt")
	}

	fmt.Println("Udlede sikre krypterings- og autentificeringsnøgler fra password ved hjælp af Scrypt...")

	// Udled 64 bytes totalt (32 for ENC, 32 for MAC)
	keyBlock, err := scrypt.Key([]byte(password), salt, int(N), int(R), int(P), TotalKeySize)
	if err != nil {
		return DerivedKeys{}, fmt.Errorf("scrypt nøgleudledning mislykkedes: %w", err)
	}

	// Split key block
	keys := DerivedKeys{
		EncKey: keyBlock[:KeySize],
		MacKey: keyBlock[KeySize:],
	}

	// Sikkerhed: Nulstil keyBlock, da nøglerne er blevet kopieret
	for i := range keyBlock {
		keyBlock[i] = 0
	}

	return keys, nil
}

// writeHeader writes all metadata to the output file
func writeHeader(w io.Writer, header *Header) error {
	var err error

	// Skriv Magic Marker
	if _, err = w.Write(header.Magic); err != nil {
		return err
	}

	// Skriv Scrypt-parametre
	if err = binary.Write(w, binary.BigEndian, header.ScryptN); err != nil {
		return err
	}
	if err = binary.Write(w, binary.BigEndian, header.ScryptR); err != nil {
		return err
	}
	if err = binary.Write(w, binary.BigEndian, header.ScryptP); err != nil {
		return err
	}

	// Skriv Salt
	if err = binary.Write(w, binary.BigEndian, uint32(len(header.Salt))); err != nil {
		return err
	}
	if _, err = w.Write(header.Salt); err != nil {
		return err
	}

	// Skriv Nonce (IV)
	if err = binary.Write(w, binary.BigEndian, uint32(len(header.Nonce))); err != nil {
		return err
	}
	if _, err = w.Write(header.Nonce); err != nil {
		return err
	}

	// Skriv OriginalName
	nameBytes := []byte(header.OriginalName)
	if err = binary.Write(w, binary.BigEndian, uint16(len(nameBytes))); err != nil {
		return err
	}
	if _, err = w.Write(nameBytes); err != nil {
		return err
	}

	return nil
}

// readHeader reads and validates metadata from the input file
func readHeader(r io.Reader) (*Header, error) {
	header := &Header{}
	var err error

	// Læs Magic Marker
	header.Magic = make([]byte, len(FileMagicMarker))
	if _, err = io.ReadFull(r, header.Magic); err != nil {
		return nil, fmt.Errorf("kunne ikke læse magic marker: %w", err)
	}
	if string(header.Magic) != FileMagicMarker {
		return nil, fmt.Errorf("ukendt filformat: ugyldig magic header. Forventet: %s, Fundet: %s", FileMagicMarker, string(header.Magic))
	}

	// Læs Scrypt-parametre
	if err = binary.Read(r, binary.BigEndian, &header.ScryptN); err != nil {
		return nil, fmt.Errorf("kunne ikke læse Scrypt N: %w", err)
	}
	if err = binary.Read(r, binary.BigEndian, &header.ScryptR); err != nil {
		return nil, fmt.Errorf("kunne ikke læse Scrypt R: %w", err)
	}
	if err = binary.Read(r, binary.BigEndian, &header.ScryptP); err != nil {
		return nil, fmt.Errorf("kunne ikke læse Scrypt P: %w", err)
	}

	// Læs Salt
	var saltLen uint32
	if err = binary.Read(r, binary.BigEndian, &saltLen); err != nil {
		return nil, fmt.Errorf("kunne ikke læse salt længde: %w", err)
	}
	if saltLen != SaltSize {
		return nil, fmt.Errorf("ugyldig salt længde: %d", saltLen)
	}
	header.Salt = make([]byte, saltLen)
	if _, err = io.ReadFull(r, header.Salt); err != nil {
		return nil, fmt.Errorf("kunne ikke læse salt: %w", err)
	}

	// Læs Nonce (IV)
	var nonceLen uint32
	if err = binary.Read(r, binary.BigEndian, &nonceLen); err != nil {
		return nil, fmt.Errorf("kunne ikke læse nonce længde: %w", err)
	}
	if nonceLen != NonceSize {
		return nil, fmt.Errorf("ugyldig nonce længde: %d", nonceLen)
	}
	header.Nonce = make([]byte, nonceLen)
	if _, err = io.ReadFull(r, header.Nonce); err != nil {
		return nil, fmt.Errorf("kunne ikke læse nonce: %w", err)
	}

	// Læs OriginalName
	var nameLen uint16
	if err = binary.Read(r, binary.BigEndian, &nameLen); err != nil {
		return nil, fmt.Errorf("kunne ikke læse filnavn længde: %w", err)
	}
	nameBytes := make([]byte, nameLen)
	if _, err = io.ReadFull(r, nameBytes); err != nil {
		return nil, fmt.Errorf("kunne ikke læse filnavn: %w", err)
	}
	header.OriginalName = string(nameBytes)

	return header, nil
}

// encryptFile handles the entire encryption process
func encryptFile(inputFile, outputFile, userPassword string) (err error) {
	fmt.Printf("Starter kryptering af %s til %s\n", inputFile, outputFile)

	fi, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke få filinformation: %w", err)
	}
	fileSize := fi.Size()

	// --- 1. Key and Parameter Generation ---
	salt := make([]byte, SaltSize)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("kunne ikke generere salt: %w", err)
	}
	nonce := make([]byte, NonceSize) // IV for CTR
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("kunne ikke generere nonce: %w", err)
	}

	var password string
	if userPassword == "" {
		password, err = generateSecurePassword(PasswordLength)
		if err != nil {
			return err
		}
		fmt.Printf("Advarsel: Tilfældigt password genereret. Opbevar det sikkert: %s\n", password)
	} else {
		password = userPassword
	}

	// Bruger de definerede konstanter
	keys, err := deriveKey(password, salt, ScryptN, ScryptR, ScryptP)
	if err != nil {
		return err
	}
	// Sikkerhed: Nulstil nøgler ved afslutning
	defer func() {
		for i := range keys.EncKey {
			keys.EncKey[i] = 0
		}
		for i := range keys.MacKey {
			keys.MacKey[i] = 0
		}
	}()

	// --- 2. Cipher Initialization (AES-256 CTR) and HMAC ---
	block, err := aes.NewCipher(keys.EncKey)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette AES-blok: %w", err)
	}
	stream := cipher.NewCTR(block, nonce)

	// Opret HMAC med MacKey
	h := hmac.New(sha256.New, keys.MacKey)

	// --- 3. Create Header and Write to Output File ---
	header := &Header{
		Magic:        []byte(FileMagicMarker),
		ScryptN:      ScryptN, // Skriver de globale konstanter til filen
		ScryptR:      ScryptR,
		ScryptP:      ScryptP,
		Salt:         salt,
		Nonce:        nonce,
		OriginalName: filepath.Base(inputFile),
	}

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	// Header MAC: Skriv Header til filen og MAC'en (Header er Associated Data)
	headerWriter := io.MultiWriter(outFile, h)
	if err = writeHeader(headerWriter, header); err != nil {
		return fmt.Errorf("kunne ikke skrive header: %w", err)
	}

	// --- 4. Streaming Kryptering (Ciphertext skal nu MAC'es) ---
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	// CRITICAL FIX: Sørg for at den MAC'ede strøm er ciphertext

	// 1. Opret MultiWriter, der sender *ciphertext* til både filen og HMAC-hash'en.
	cipherTextOut := io.MultiWriter(outFile, h)

	// 2. Opret Streamwriter: Den modtager PLAINTEXT, krypterer det, og sender *ciphertext* til cipherTextOut.
	streamWriter := &cipher.StreamWriter{S: stream, W: cipherTextOut}

	fmt.Println("Krypterer og streamer filindhold...")

	// Brug ProgressWriter til at vise fremdrift baseret på bytes læst fra inputfilen (plaintext)
	pw := &ProgressWriter{
		Writer:     streamWriter, // ProgressWriter modtager PLAINTEXT og sender det til streamWriter
		TotalBytes: fileSize,
		StartTime:  time.Now(),
	}

	// io.Copy kopierer indholdet af inFile (plaintext) til pw/streamWriter
	if _, err = io.Copy(pw, inFile); err != nil {
		return fmt.Errorf("fejl under streaming kryptering: %w", err)
	}

	// --- 5. Afslutning: Skriv HMAC Tag ---
	tag := h.Sum(nil) // Få det endelige HMAC-tag (beregnet over Header + Ciphertext)
	if _, err = outFile.Write(tag); err != nil {
		return fmt.Errorf("kunne ikke skrive HMAC tag: %w", err)
	}

	fmt.Println("\nKryptering fuldført.")
	return nil
}

// decryptFile handles the entire decryption process
func decryptFile(inputFile, outputFile string) (err error) {
	fmt.Printf("Starter dekryptering af %s til %s\n", inputFile, outputFile)

	// --- 1. Secure Password Input ---
	fmt.Print("Indtast dekrypteringspassword: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("fejl ved læsning af password: %w", err)
	}
	password := string(bytePassword)
	fmt.Println()

	defer func() {
		for i := range bytePassword {
			bytePassword[i] = 0
		}
	}()

	// --- 2. Fil-I/O og Tag Håndtering ---
	fi, err := os.Stat(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke få filinformation: %w", err)
	}
	fileSize := fi.Size()

	// Tjek filstørrelse (skal mindst være større end tagget)
	if fileSize < int64(TagSize) {
		return fmt.Errorf("filen er for kort til at indeholde et gyldigt HMAC-tag")
	}

	// Adskil filen i Body (Header + Ciphertext) og Tag
	tagStart := fileSize - int64(TagSize)

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	// Læs Tagget fra slutningen
	if _, err = inFile.Seek(tagStart, io.SeekStart); err != nil {
		return fmt.Errorf("fejl ved seeking til tag: %w", err)
	}

	expectedTag := make([]byte, TagSize)
	if _, err = io.ReadFull(inFile, expectedTag); err != nil {
		return fmt.Errorf("kunne ikke læse HMAC tag: %w", err)
	}

	// Gå tilbage til filens start for at læse Header
	if _, err = inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("fejl ved nulstilling af filpointer (før header læsning): %w", err)
	}

	// --- 3. Læs Header og Nøgleudledning ---
	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("fejl under læsning af header: %w", err)
	}

	// Gem den præcise position EFTER headeren (starten af Ciphertext)
	headerEndPos, err := inFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return fmt.Errorf("fejl ved at få header end position: %w", err)
	}

	// Bruger de læste parametre fra headeren
	keys, err := deriveKey(password, header.Salt, header.ScryptN, header.ScryptR, header.ScryptP)
	if err != nil {
		return fmt.Errorf("nøgleudledning mislykkedes (forkert password?): %w", err)
	}
	defer func() {
		for i := range keys.EncKey {
			keys.EncKey[i] = 0
		}
		for i := range keys.MacKey {
			keys.MacKey[i] = 0
		}
	}()

	// --- 4. Verificer HMAC (Header + Ciphertext) ---
	h := hmac.New(sha256.New, keys.MacKey)

	// Nulstil filpointeren til start for MAC-beregning (position 0)
	if _, err = inFile.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("fejl ved nulstilling for MAC: %w", err)
	}

	// Vi bruger en LimitedReader til kun at læse (Header + Ciphertext) og udelukke Tagget
	bodyReader := io.LimitReader(inFile, tagStart)

	// MAC Header + Ciphertext i én go
	if _, err = io.Copy(h, bodyReader); err != nil {
		return fmt.Errorf("fejl under MAC-beregning: %w", err)
	}

	calculatedTag := h.Sum(nil)

	fmt.Println("Verificerer filautenticitet (HMAC)...")
	if !hmac.Equal(calculatedTag, expectedTag) {
		return fmt.Errorf("autentificering mislykkedes: HMAC-tag matcher ikke (muligvis forkert password eller filen er korrupt)")
	}
	fmt.Println("Autentificering bekræftet. Starter dekryptering...")

	// --- 5. Streaming Dekryptering ---

	// Gå direkte til den gemte position for starten af Ciphertexten.
	if _, err = inFile.Seek(headerEndPos, io.SeekStart); err != nil {
		return fmt.Errorf("fejl ved at seek til start af Ciphertext: %w", err)
	}

	// Filpointeren er nu placeret PRÆCIST i starten af Ciphertext

	// Beregn den faktiske ciphertext-størrelse (Total Body størrelse - Header størrelse)
	cipherTextLength := tagStart - headerEndPos

	// Nu kan vi oprette LimitedReaderen sikkert (den læser kun Ciphertext)
	cipherTextReader := io.LimitReader(inFile, cipherTextLength)

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	block, err := aes.NewCipher(keys.EncKey)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette AES-blok: %w", err)
	}
	stream := cipher.NewCTR(block, header.Nonce)

	// Dekryptering sker på stream-niveau: output af streamReader er dekrypteret data
	streamReader := &cipher.StreamReader{S: stream, R: cipherTextReader}

	// Brug ProgressWriter til at vise fremdrift baseret på den estimerede dekrypterede størrelse
	pw := &ProgressWriter{
		Writer:     outFile,
		TotalBytes: cipherTextLength, // Ciphertext størrelsen er lig med plaintext størrelsen i CTR
		StartTime:  time.Now(),
	}

	// io.Copy kopierer streamReader (dekrypteret data) til pw (som skriver til outFile)
	if _, err = io.Copy(pw, streamReader); err != nil {
		return fmt.Errorf("fejl under streaming dekryptering: %w", err)
	}

	fmt.Println("\nDekryptering fuldført.")
	return nil
}

// formatBytes helper function for human-readable file size
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Brug: cipherforge <kommando> [argumenter]")
		fmt.Println("\nKommandoer:")
		fmt.Println("  -ef <input_file> <output_file> [-p <password>]  (Krypter)")
		fmt.Println("  -df <input_file> <output_file>                (Dekrypter)")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "-ef":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "Brug: cipherforge -ef <input_file> <output_file> [-p <password>]")
			os.Exit(1)
		}
		inputFile := os.Args[2]
		outputFile := os.Args[3]

		password := ""
		for i := 4; i < len(os.Args)-1; i++ {
			if os.Args[i] == "-p" {
				password = os.Args[i+1]
				break
			}
		}

		if err := encryptFile(inputFile, outputFile, password); err != nil {
			fmt.Fprintf(os.Stderr, "Krypteringsfejl: %v\n", err)
			os.Exit(1)
		}

	case "-df":
		if len(os.Args) != 4 {
			fmt.Fprintln(os.Stderr, "Brug: cipherforge -df <input_file> <output_file>")
			os.Exit(1)
		}
		inputFile := os.Args[2]
		outputFile := os.Args[3]

		if err := decryptFile(inputFile, outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Dekrypteringsfejl: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Ugyldig kommando: %s. Brug -ef eller -df.\n", command)
		os.Exit(1)
	}
}
