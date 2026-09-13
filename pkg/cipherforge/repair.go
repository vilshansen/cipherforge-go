package cipherforge

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"io"

	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/format"
)

// ErrNoRepair is returned when no nearby variant of a secret authenticates the
// key-commitment tag stored in the file.
var ErrNoRepair = errors.New("no single-character correction of the secret authenticates this file")

// RepairSecret looks for a secret that authenticates against the key-commitment
// tag stored in the .cfo stream r, differing from secret by a single character.
//
// Why this is possible: the 32-byte key-commitment tag in the trailer is
// HMAC-SHA256(encKey, context || fileSalt), and encKey is derived from the
// secret and the file salt. Both the salt and the tag live in the fixed-size
// regions at the start and end of the file, so a candidate secret can be tested
// with one key derivation and one HMAC — no payload is read and no plaintext is
// produced. That makes an exhaustive single-character search (a few thousand
// candidates) effectively instant.
//
// The search covers the four transcription errors a human actually makes:
//
//   - substitution — one character typed as another
//   - transposition — two adjacent characters swapped
//   - deletion — one character dropped
//   - insertion — one character added
//
// Candidates are drawn from crypto.CharacterPool plus the group separator, so
// both the random characters and the dashes of a generated secret are covered.
//
// A returned secret is not a guess: it reproduces a 256-bit tag, so a false
// match would require a collision in HMAC-SHA256. The caller may use it as the
// real secret for this file. The caller owns the returned slice and should zero
// it with crypto.ZeroBytes when done.
//
// r must be seekable; its read position is moved by the search.
func RepairSecret(r io.ReadSeeker, secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrNoRepair
	}

	target, err := readRepairTarget(r)
	if err != nil {
		return nil, err
	}

	if corrected, ok := target.search(secret); ok {
		return corrected, nil
	}
	return nil, ErrNoRepair
}

// repairTarget holds everything needed to test a candidate secret without
// decrypting: the per-file salt and the stored key-commitment tag.
type repairTarget struct {
	salt      []byte
	committed []byte
}

// readRepairTarget validates the v7 header and reads the salt from the front of
// the file and the key-commitment tag from the end. The trailer's HMAC is
// deliberately not verified — the caller reaches this path precisely because
// authentication failed, and the commitment tag is the weaker, independent
// check that is useful here.
func readRepairTarget(r io.ReadSeeker) (repairTarget, error) {
	var t repairTarget

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return t, err
	}

	magic := make([]byte, format.MagicSize)
	if _, err := io.ReadFull(r, magic); err != nil {
		return t, err
	}
	if string(magic) != format.Magic {
		return t, fmt.Errorf("not a valid .cfo file")
	}

	version, err := format.ReadUint32(r)
	if err != nil {
		return t, err
	}
	if version != format.FileVersion {
		return t, fmt.Errorf("unsupported file version %d (v%d required)", version, format.FileVersion)
	}

	suite := make([]byte, format.SuiteSize)
	if _, err := io.ReadFull(r, suite); err != nil {
		return t, err
	}
	if suite[0] != format.AESGCM256Suite {
		return t, fmt.Errorf("unsupported encryption suite %d", suite[0])
	}

	flags := make([]byte, format.FlagsSize)
	if _, err := io.ReadFull(r, flags); err != nil {
		return t, err
	}
	if flags[0] != 0 {
		return t, fmt.Errorf("unsupported format flags 0x%02x", flags[0])
	}

	t.salt = make([]byte, format.SaltSize)
	if _, err := io.ReadFull(r, t.salt); err != nil {
		return t, err
	}

	fileSize, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return t, err
	}
	if fileSize < int64(format.TrailerSize) {
		return t, fmt.Errorf("file too small to be a .cfo file")
	}
	if _, err := r.Seek(fileSize-int64(format.TrailerSize), io.SeekStart); err != nil {
		return t, err
	}

	// Trailer layout: [segmentCount: 8] [trailerHMAC: 32] [keyCommitment: 32].
	trailerBuf := make([]byte, format.TrailerSize)
	if _, err := io.ReadFull(r, trailerBuf); err != nil {
		return t, err
	}
	t.committed = bytes.Clone(trailerBuf[40:72])

	return t, nil
}

// matches reports whether secret is the secret that produced the stored
// key-commitment tag. Only encKey is needed, so macKey is discarded straight
// away rather than being left for the garbage collector.
func (t repairTarget) matches(secret []byte) bool {
	encKey, macKey := crypto.DeriveKeys(secret, t.salt)
	if macKey != nil {
		crypto.ZeroBytes(macKey)
	}
	if encKey == nil {
		return false
	}
	defer crypto.ZeroBytes(encKey)

	return hmac.Equal(t.committed, computeKeyCommitTag(encKey, t.salt))
}

// search walks every single-character edit of secret and returns the first one
// that authenticates. The order is deliberate: substitutions first (by far the
// most common error and the largest set), then transpositions, then the
// length-changing errors.
func (t repairTarget) search(secret []byte) ([]byte, bool) {
	alphabet := repairAlphabet()
	candidate := bytes.Clone(secret)

	// Substitution: replace one character with any other symbol.
	for i := range candidate {
		original := candidate[i]
		for _, c := range alphabet {
			if c == original {
				continue
			}
			candidate[i] = c
			if t.matches(candidate) {
				return candidate, true
			}
		}
		candidate[i] = original
	}

	// Transposition: swap two adjacent characters. Swapping back restores the
	// candidate, so the same slice is reused for the next position.
	for i := 0; i+1 < len(candidate); i++ {
		if candidate[i] == candidate[i+1] {
			continue
		}
		candidate[i], candidate[i+1] = candidate[i+1], candidate[i]
		if t.matches(candidate) {
			return candidate, true
		}
		candidate[i], candidate[i+1] = candidate[i+1], candidate[i]
	}

	// Deletion: drop one character.
	if len(candidate) > 1 {
		shorter := make([]byte, 0, len(candidate)-1)
		for i := range candidate {
			shorter = shorter[:0]
			shorter = append(shorter, candidate[:i]...)
			shorter = append(shorter, candidate[i+1:]...)
			if t.matches(shorter) {
				return bytes.Clone(shorter), true
			}
		}
	}

	// Insertion: add one character at any position.
	longer := make([]byte, len(candidate)+1)
	for i := 0; i <= len(candidate); i++ {
		copy(longer, candidate[:i])
		copy(longer[i+1:], candidate[i:])
		for _, c := range alphabet {
			longer[i] = c
			if t.matches(longer) {
				return bytes.Clone(longer), true
			}
		}
	}

	return nil, false
}

// repairAlphabet is the set of symbols a secret can contain: the generation
// pool plus the group separator, which is part of the secret string.
func repairAlphabet() []byte {
	alphabet := make([]byte, 0, len(crypto.CharacterPool)+1)
	alphabet = append(alphabet, crypto.CharacterPool...)
	alphabet = append(alphabet, byte(crypto.SecretSeparator))
	return alphabet
}
