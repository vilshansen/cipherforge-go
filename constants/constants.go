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
