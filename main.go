package main

import (
	"bytes"
	"crypto/rand" // ADDED: Standard sikker kilde til tilfældighed
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall" // Beholdt for term.ReadPassword

	// Fjernet: "golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305" // Den foretrukne AEAD (Authenticated Encryption with Associated Data)
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term" // Til sikkert password-input
)

// --- Kryptografiske Konstanter ---
const (
	// MAGIC_MARKER er filformatets identifikator (V00003 for XChaCha20-Poly1305)
	MagicMarker    = "CIPHERFORGE-V00003"
	KeySize        = 32 // 256-bit XChaCha20 nøgle
	SaltSize       = 16 // 128-bit salt
	XNonceSize     = 24 // 192-bit XChaCha20 Nonce (Extended Nonce)
	TagSize        = 16 // 128-bit Poly1305 autentificeringstag
	PasswordLength = 32 // Standard længde for tilfældigt password
	CharacterPool  = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

	// Fjernet: ChunkSize

	// SCYPT PARAMETRE (MAKSIMAL SIKKERHED)
	ScryptN = 1 << 18 // 262,144 iterationer (Høj latency, stærk sikkerhed)
	ScryptR = 8
	ScryptP = 1
)

// --- Header Struktur og Hjælpefunktioner ---

// FileHeader gemmer metadata for at sikre reproducerbar dekryptering
type FileHeader struct {
	Magic    string
	ScryptN  int
	ScryptR  int
	ScryptP  int
	Salt     []byte
	Nonce    []byte
	FileName string
}

// headerBytes genskaber headeren som en byte-slice for brug som Associated Data (AAD).
func headerBytes(header FileHeader) []byte {
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

// writeHeader skriver alle metadata til filens start.
func writeHeader(header FileHeader, output io.Writer) (int64, error) {
	// Bruger den sikre headerBytes-funktion til at få den fulde AAD-struktur
	headerData := headerBytes(header)

	// Skriv den samlede header til output-streamen
	n, err := output.Write(headerData)
	if err != nil {
		return 0, fmt.Errorf("fejl ved skrivning af header: %w", err)
	}

	return int64(n), nil
}

// readHeader læser og validerer metadata fra filen.
func readHeader(input io.Reader) (FileHeader, error) {
	header := FileHeader{}

	// Læs Magic Marker (Validering)
	magic := make([]byte, len(MagicMarker))
	if _, err := io.ReadFull(input, magic); err != nil {
		return header, fmt.Errorf("fejl ved læsning af magic marker: %w", err)
	}
	header.Magic = string(magic)
	if header.Magic != MagicMarker {
		return header, fmt.Errorf("ukendt filformat. Forventet: %s, Fundet: %s", MagicMarker, header.Magic)
	}

	// Læs Scrypt Parametre
	var n, r, p uint32
	if err := binary.Read(input, binary.BigEndian, &n); err != nil {
		return header, fmt.Errorf("fejl ved læsning af ScryptN: %w", err)
	}
	if err := binary.Read(input, binary.BigEndian, &r); err != nil {
		return header, fmt.Errorf("fejl ved læsning af ScryptR: %w", err)
	}
	if err := binary.Read(input, binary.BigEndian, &p); err != nil {
		return header, fmt.Errorf("fejl ved læsning af ScryptP: %w", err)
	}
	header.ScryptN = int(n)
	header.ScryptR = int(r)
	header.ScryptP = int(p)

	// Læs Salt
	var saltLen uint32
	if err := binary.Read(input, binary.BigEndian, &saltLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af saltlængde: %w", err)
	}
	header.Salt = make([]byte, saltLen)
	if _, err := io.ReadFull(input, header.Salt); err != nil {
		return header, fmt.Errorf("fejl ved læsning af salt: %w", err)
	}

	// Læs XNonce
	var nonceLen uint32
	if err := binary.Read(input, binary.BigEndian, &nonceLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af nonce-længde: %w", err)
	}
	if nonceLen != XNonceSize {
		return header, fmt.Errorf("ugyldig nonce-længde: %d, forventet %d", nonceLen, XNonceSize)
	}
	header.Nonce = make([]byte, nonceLen)
	if _, err := io.ReadFull(input, header.Nonce); err != nil {
		return header, fmt.Errorf("fejl ved læsning af nonce: %w", err)
	}

	// Læs Filnavn
	var nameLen uint32
	if err := binary.Read(input, binary.BigEndian, &nameLen); err != nil {
		return header, fmt.Errorf("fejl ved læsning af filnavnslængde: %w", err)
	}
	fileNameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(input, fileNameBytes); err != nil {
		return header, fmt.Errorf("fejl ved læsning af filnavn: %w", err)
	}
	header.FileName = string(fileNameBytes)

	return header, nil
}

// --- Kryptografiske Kernefunktioner ---

// generateSecurePassword genererer et sikkert, tilfældigt password.
func generateSecurePassword(length int) string {
	// BRUGER NU: crypto/rand for portabilitet og sikkerhed
	passwordBytes := make([]byte, length)
	poolLen := len(CharacterPool)

	// Læs tilstrækkeligt mange tilfældige bytes
	if _, err := rand.Read(passwordBytes); err != nil {
		log.Fatalf("Fejl ved generering af tilfældigt password fra crypto/rand: %v", err)
	}

	// Map de tilfældige bytes til tegn i CharacterPool
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Brug modulo for at vælge tegn fra poolen
		idx := int(passwordBytes[i]) % poolLen
		result[i] = CharacterPool[idx]
	}

	return string(result)
}

// deriveKey udleder en 32-byte krypteringsnøgle vha. Scrypt.
func deriveKey(password string, salt []byte, N, R, P int) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("password må ikke være tomt")
	}
	fmt.Println("Udleder sikker krypteringsnøgle fra password vha. Scrypt...")

	key, err := scrypt.Key([]byte(password), salt, N, R, P, KeySize)
	if err != nil {
		return nil, fmt.Errorf("scrypt nøglederivation mislykkedes: %w", err)
	}

	return key, nil
}

// --- Fil-I/O og Streaming Logik (Forenklet) ---

// encryptFile håndterer hele krypteringsprocessen.
func encryptFile(inputFile string, outputFile string, userPassword string) error {
	// 1. Initialiser
	salt := make([]byte, SaltSize)
	nonce := make([]byte, XNonceSize)

	// Brug crypto/rand for sikkert tilfældighedsmateriale (salt og nonce)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("kunne ikke generere tilfældigt salt: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("kunne ikke generere tilfældigt nonce: %w", err)
	}

	// Bestem password
	password := userPassword
	if password == "" {
		password = generateSecurePassword(PasswordLength)
		// VIGTIGT: Advisér brugeren om at gemme det genererede password
		fmt.Printf("ADVARSEL: Tilfældigt password er genereret: %s\n", password)
		fmt.Println("GEM DETTE PASSWORD SIKKERT. Det er nødvendigt for dekryptering.")
	}

	// 2. Udled nøgle
	key, err := deriveKey(password, salt, ScryptN, ScryptR, ScryptP)
	if err != nil {
		return fmt.Errorf("fejl i nøglederivation: %w", err)
	}
	defer func() {
		// Forsøg at nulstille nøglematerialet
		for i := range key {
			key[i] = 0
		}
	}()

	// 3. Åbn Filer
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	stat, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("kunne ikke læse filstatistik: %w", err)
	}
	fileSize := stat.Size()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	// 4. Skriv Header (AAD)
	header := FileHeader{
		Magic: MagicMarker, ScryptN: ScryptN, ScryptR: ScryptR, ScryptP: ScryptP,
		Salt: salt, Nonce: nonce, FileName: filepath.Base(inputFile),
	}
	headerLen, err := writeHeader(header, outFile)
	if err != nil {
		return fmt.Errorf("fejl ved skrivning af header: %w", err)
	}

	// 5. Initialiser AEAD Cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("kunne ikke initialisere XChaCha20-Poly1305: %w", err)
	}

	// 6. Krypter
	fmt.Println("Læser inputfil i hukommelsen for kryptering...")
	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return fmt.Errorf("fejl ved læsning af inputfil: %w", err)
	}
	defer func() {
		// Nulstil plaintext-buffer efter brug
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	fmt.Printf("Krypterer %.2f MB fil med XChaCha20-Poly1305...\n", float64(fileSize)/(1024*1024))
	// Headeren (AAD) er inkluderet i autentificeringen.
	ciphertextWithTag := aead.Seal(nil, nonce, plaintext, headerBytes(header))

	// 7. Skriv Ciphertext og Tag til Outputfil
	if _, err := outFile.Write(ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved skrivning af krypteret data: %w", err)
	}

	fmt.Printf("Kryptering fuldført. Output filstørrelse: %.2f MB\n", float64(headerLen+int64(len(ciphertextWithTag)))/(1024*1024))
	return nil
}

// decryptFile håndterer hele dekrypteringsprocessen.
func decryptFile(inputFile string, outputFile string) error {
	// 1. Initialiser
	fmt.Println("Indtast venligst dit dekrypteringspassword:")
	passwordChars, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("kunne ikke læse password fra terminal: %w", err)
	}
	password := string(passwordChars)
	defer func() {
		// Nulstil password-buffer efter brug (begrænset effekt i Go)
		for i := range passwordChars {
			passwordChars[i] = 0
		}
	}()

	// 2. Åbn Filer
	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke åbne inputfil: %w", err)
	}
	defer inFile.Close()

	stat, err := inFile.Stat()
	if err != nil {
		return fmt.Errorf("kunne ikke læse filstatistik: %w", err)
	}
	fileSize := stat.Size()

	// 3. Læs Header
	// Bruger ikke bufio.NewReader her for at forenkle I/O-logikken.
	header, err := readHeader(inFile)
	if err != nil {
		return fmt.Errorf("fejl ved læsning af header: %w", err)
	}

	// Beregn headerlængden baseret på hvor meget vi har læst
	currentPos, _ := inFile.Seek(0, io.SeekCurrent)
	headerLen := currentPos

	// 4. Udled nøgle ved hjælp af parametrene fra filheaderen
	key, err := deriveKey(password, header.Salt, header.ScryptN, header.ScryptR, header.ScryptP)
	if err != nil {
		return fmt.Errorf("fejl i nøglederivation: %w", err)
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()

	// 5. Initialiser AEAD Cipher
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("kunne ikke initialisere XChaCha20-Poly1305: %w", err)
	}

	// Læs hele Ciphertext + Tag ind i hukommelsen
	ciphertextWithTagLen := fileSize - headerLen
	ciphertextWithTag := make([]byte, ciphertextWithTagLen)
	// io.ReadFull sikrer, at vi læser præcis det antal bytes, vi forventer
	if _, err := io.ReadFull(inFile, ciphertextWithTag); err != nil {
		return fmt.Errorf("fejl ved læsning af krypteret data: %w", err)
	}

	// 6. Dekrypter og Autentificér (AAD)
	fmt.Println("Dekrypterer og autentificerer filen...")

	// Genskan headeren som bytes for at bruge den som AAD
	aad := headerBytes(header)

	plaintext, err := aead.Open(nil, header.Nonce, ciphertextWithTag, aad)
	if err != nil {
		// En AEAD Open fejl indikerer altid enten et forkert password (forkert nøgle)
		// eller at filen er blevet manipuleret (autentificering mislykkedes).
		return fmt.Errorf("dekrypteringsfejl: autentificering mislykkedes (forkert password eller korrupt fil): %w", err)
	}
	defer func() {
		// Nulstil plaintext-buffer efter brug
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	// 7. Skriv Outputfil
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("kunne ikke oprette outputfil: %w", err)
	}
	defer outFile.Close()

	if _, err := outFile.Write(plaintext); err != nil {
		return fmt.Errorf("fejl ved skrivning af dekrypteret data: %w", err)
	}

	fmt.Println("Dekryptering fuldført.")
	return nil
}

// --- Main CLI Logik ---

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Brug: %s (-ef <input_fil> <output_fil> [-p <password>] | -df <input_fil> <output_fil>)\n", os.Args[0])
		return
	}

	operation := os.Args[1]

	defer func() {
		// Utskriv fejlmeddelelser fra log
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Fatal fejl: %v\n", r)
		}
	}()

	var err error
	if operation == "-ef" {
		if len(os.Args) < 4 {
			err = fmt.Errorf("brug: %s -ef <input_fil> <output_fil> [-p <password>]", os.Args[0])
		} else {
			inputFile := os.Args[2]
			outputFile := os.Args[3]
			var password string
			for i := 4; i < len(os.Args); i++ {
				if os.Args[i] == "-p" && i+1 < len(os.Args) {
					password = os.Args[i+1]
					break
				}
			}
			err = encryptFile(inputFile, outputFile, password)
		}
	} else if operation == "-df" {
		if len(os.Args) != 4 {
			err = fmt.Errorf("brug: %s -df <input_fil> <output_fil>", os.Args[0])
		} else {
			inputFile := os.Args[2]
			outputFile := os.Args[3]
			err = decryptFile(inputFile, outputFile)
		}
	} else {
		err = fmt.Errorf("ugyldig operation. Brug -ef (encrypt) eller -df (decrypt)")
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Fejl: %v\n", err)
		os.Exit(1)
	}
}
