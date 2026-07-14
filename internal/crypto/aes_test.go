package crypto

import (
	"bytes"
	"testing"
)

var testKey32 = []byte("12345678901234567890123456789012") // 32 bytes

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("secret message for tessera")
	ciphertext, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ciphertext, testKey32)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: want %q, got %q", plaintext, got)
	}
}

func TestEncryptProducesUniqueOutput(t *testing.T) {
	plaintext := []byte("same plaintext")
	ct1, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatal(err)
	}
	ct2, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatal(err)
	}
	// Random nonce means identical plaintexts must produce different ciphertexts.
	if bytes.Equal(ct1, ct2) {
		t.Fatal("Encrypt produced identical ciphertext for the same plaintext (nonce reuse?)")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	plaintext := []byte("sensitive data")
	ciphertext, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("99999999999999999999999999999999") // different 32-byte key
	_, err = Decrypt(ciphertext, wrongKey)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	plaintext := []byte("integrity check")
	ciphertext, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the middle of the ciphertext (past the 12-byte nonce).
	mid := len(ciphertext) / 2
	ciphertext[mid] ^= 0xFF
	_, err = Decrypt(ciphertext, testKey32)
	if err == nil {
		t.Fatal("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestDecryptTooShortFails(t *testing.T) {
	// Fewer bytes than a GCM nonce (12 bytes).
	_, err := Decrypt([]byte("short"), testKey32)
	if err == nil {
		t.Fatal("expected error for too-short ciphertext, got nil")
	}
}

func TestEncryptInvalidKeyFails(t *testing.T) {
	// AES requires 16, 24, or 32 byte key; 10 bytes is invalid.
	_, err := Encrypt([]byte("data"), []byte("tooshort"))
	if err == nil {
		t.Fatal("expected error for invalid key length, got nil")
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	plaintext := []byte{}
	ciphertext, err := Encrypt(plaintext, testKey32)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	got, err := Decrypt(ciphertext, testKey32)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("empty plaintext round-trip: want %v, got %v", plaintext, got)
	}
}
