package constants

const (
	MagicMarker    = "CIPHERFORGE-V00003"
	KeySize        = 32 // 256-bit XChaCha20 nøgle
	SaltSize       = 16 // 128-bit salt
	XNonceSize     = 24 // 192-bit XChaCha20 Nonce (Extended Nonce)
	TagSize        = 16 // 128-bit Poly1305 autentificeringstag
	PasswordLength = 32 // Standard længde for tilfældigt password
	CharacterPool  = "!#$%&*+-0123456789?@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	ScryptN        = 1 << 20 // 1,048,576 iterationer
	ScryptR        = 8
	ScryptP        = 1
)

// HelpText indeholder den fulde, formaterede hjælpevejledning til CLI-værktøjet.
const HelpText = `
NAVN
    cipherforge - Kryptering og dekryptering af filer med XChaCha20-Poly1305 og scrypt nøgleafledning.

SYNOPSIS (USAGE)
    cipherforge [OPERATION] <input_fil> <output_fil>

BESKRIVELSE
    Cipherforge er et værktøj til at kryptere og dekryptere filer ved hjælp af de stærkeste moderne
	kryptografiske standarder.

OPERATIONER
    -ef, --encrypt <input_fil> <output_fil>
        Krypterer den angivne inputfil.

    -df, --decrypt <input_fil> <output_fil>
        Dekrypterer den angivne inputfil.

OPTIONER
    -p, --password <kodeord>
        Angiver kodeordet direkte.

        Kan anvendes både ved kryptering og dekryptering. Hvis dette flag udelades, genereres et 
        tilfældigt, stærkt kodeord automatisk og udskrives på skærmen.

        Ved dekryptering bør kodeordet altid indtastes interaktivt for at sikre, at det ikke gemmes
        i shell-historikken.

EKSEMPLER

    # Krypter fil med automatisk genereret password:
    cipherforge -ef data.txt data.cf

    # Dekrypter fil (kræver interaktiv password-indtastning):
    cipherforge -df data.cf data_original.txt

SE OGSÅ
    Fuld kildekode til programmet findes på https://github.com/vilshansen/cipherforge-go/

`
