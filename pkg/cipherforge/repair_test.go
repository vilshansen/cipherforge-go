package cipherforge

import (
	"bytes"
	"errors"
	"testing"
)

// repairTestSecret mirrors the shape of a generated secret: 45 pool characters
// in nine groups of five.
const repairTestSecret = "8oEmo-Qhvn6-u9gK3-pweUY-ZrTuJ-ZJtvz-U6WiU-B87Tj-AxH3k"

// encryptToMemory encrypts plaintext under secret and returns the .cfo bytes.
func encryptToMemory(t *testing.T, plaintext, secret []byte) []byte {
	t.Helper()

	var out bytes.Buffer
	if err := NewEncrypter(secret).Encrypt(bytes.NewReader(plaintext), &out, nil); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return out.Bytes()
}

func TestRepairSecretFindsSingleCharacterEdits(t *testing.T) {
	ciphertext := encryptToMemory(t, []byte("recover this payload"), []byte(repairTestSecret))
	original := repairTestSecret
	n := len(original)

	// Each case is exactly one transcription error away from the real secret.
	broken := []struct {
		name  string
		value string
	}{
		{"substituted character", original[:n-1] + "q"},
		{"substituted separator", original[:5] + "X" + original[6:]},
		{"transposed characters", original[:n-2] + "k3"},
		{"deleted character", original[:n-1]},
		{"deleted separator", original[:47] + original[48:]},
		{"inserted character", original + "X"},
		{"inserted separator", original[:20] + "-" + original[20:]},
	}

	for _, tc := range broken {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value == original {
				t.Fatalf("test case %q is not a typo: it equals the original secret", tc.name)
			}

			got, err := RepairSecret(bytes.NewReader(ciphertext), []byte(tc.value))
			if err != nil {
				t.Fatalf("RepairSecret(%q) = %v, want the original secret", tc.value, err)
			}
			if string(got) != original {
				t.Errorf("RepairSecret(%q) = %q, want %q", tc.value, got, original)
			}
		})
	}
}

func TestRepairSecretReturnsWorkingSecret(t *testing.T) {
	// The recovered secret must actually decrypt the file, not merely satisfy
	// the key-commitment tag.
	plaintext := []byte("the quick brown fox")
	ciphertext := encryptToMemory(t, plaintext, []byte(repairTestSecret))

	got, err := RepairSecret(bytes.NewReader(ciphertext), []byte(repairTestSecret[:len(repairTestSecret)-1]+"q"))
	if err != nil {
		t.Fatalf("RepairSecret: %v", err)
	}

	var recovered bytes.Buffer
	if err := NewDecrypter(got).Decrypt(bytes.NewReader(ciphertext), &recovered, nil); err != nil {
		t.Fatalf("decrypt with the repaired secret: %v", err)
	}
	if !bytes.Equal(recovered.Bytes(), plaintext) {
		t.Errorf("decrypted %q, want %q", recovered.Bytes(), plaintext)
	}
}

func TestRepairSecretRejectsUnrelatedSecret(t *testing.T) {
	ciphertext := encryptToMemory(t, []byte("payload"), []byte(repairTestSecret))

	_, err := RepairSecret(bytes.NewReader(ciphertext), []byte("Zq7vT-bN2wX-9kPmR-4sJhL-cF6yD-gK8uE-aW3nZ-xV5tB-mQ2rS"))
	if !errors.Is(err, ErrNoRepair) {
		t.Fatalf("RepairSecret error = %v, want ErrNoRepair", err)
	}
}

func TestRepairSecretRejectsNonCFOInput(t *testing.T) {
	_, err := RepairSecret(bytes.NewReader([]byte("this is not a cfo file")), []byte(repairTestSecret))
	if err == nil {
		t.Fatal("expected an error for non-.cfo input")
	}
	if errors.Is(err, ErrNoRepair) {
		t.Fatalf("want a format error, got %v", err)
	}
}

func TestRepairSecretDoesNotMutateInput(t *testing.T) {
	ciphertext := encryptToMemory(t, []byte("payload"), []byte(repairTestSecret))

	typo := []byte(repairTestSecret[:len(repairTestSecret)-1] + "q")
	before := string(typo)

	if _, err := RepairSecret(bytes.NewReader(ciphertext), typo); err != nil {
		t.Fatalf("RepairSecret: %v", err)
	}
	if string(typo) != before {
		t.Errorf("RepairSecret mutated its input: %q -> %q", before, typo)
	}
}

// BenchmarkRepairSecretNoMatch measures the worst case: no candidate matches, so
// the entire single-character search space is exhausted.
func BenchmarkRepairSecretNoMatch(b *testing.B) {
	secret := []byte(repairTestSecret)

	var ciphertext bytes.Buffer
	if err := NewEncrypter(secret).Encrypt(bytes.NewReader([]byte("payload")), &ciphertext, nil); err != nil {
		b.Fatal(err)
	}
	blob := ciphertext.Bytes()

	// A same-length secret that shares no characters with the real one, so no
	// early exit is possible.
	unrelated := bytes.Repeat([]byte("z"), len(repairTestSecret))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := RepairSecret(bytes.NewReader(blob), unrelated); !errors.Is(err, ErrNoRepair) {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
