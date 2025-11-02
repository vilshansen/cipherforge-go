package constants

const (
	MagicMarker      = "CIPHERFORGE-V00003"
	KeySize          = 32 // 256-bit XChaCha20 nøgle
	XNonceSize       = 24 // 192-bit XChaCha20 Nonce (Extended Nonce)
	TagSize          = 16 // 128-bit Poly1305 autentificeringstag
	PasswordLength   = 45 // Standard længde for tilfældigt password.
	CharacterPool    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	Argon2Iterations = 10         // iterations
	Argon2Memory     = 512 * 1024 // 512MB in KiB
	Argon2Threads    = 4          // parallelism
	Argon2SaltLength = 16         // 128-bit salt
)

// HelpText indeholder den fulde, formaterede hjælpevejledning til CLI-værktøjet.
const HelpText = `
NAVN
    cipherforge - Kryptering og dekryptering af filer med XChaCha20-Poly1305 og Argon2id nøgleafledning.

SYNOPSIS
    Krypter:   cipherforge -ef -i <input_fil> -o <output_fil> [-p <kodeord>]
    Dekrypter: cipherforge -df -i <input_fil> -o <output_fil> [-p <kodeord>]

BESKRIVELSE
    Cipherforge er et værktøj til at kryptere og dekryptere filer ved hjælp af de stærkeste moderne
	kryptografiske standarder.

PARAMETRE
    -ef, --encrypt
        Krypterer den angivne inputfil.

    -df, --decrypt
        Dekrypterer den angivne inputfil.

    -p, --password <kodeord>
        Angiver kodeordet direkte.

        Kan anvendes både ved kryptering og dekryptering. Hvis dette flag udelades, genereres et 
        tilfældigt, stærkt kodeord automatisk og udskrives på skærmen.

        Ved dekryptering bør kodeordet altid indtastes interaktivt for at sikre, at det ikke gemmes
        i shell-historikken.

EKSEMPLER
    # Krypter fil med automatisk genereret password:
    cipherforge -ef -i data.txt -o data.cfo

    # Dekrypter fil (kræver interaktiv password-indtastning):
    cipherforge -df -i data.cfo -o data_original.txt

KILDEKODE
    Fuld kildekode til programmet findes på https://github.com/vilshansen/cipherforge-go/

`
