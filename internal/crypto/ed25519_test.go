package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeypairReturnsValidBase64(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("public key not valid base64: %v", err)
	}
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("private key not valid base64: %v", err)
	}
	// Ed25519 public key is 32 bytes; private key (seed+pub) is 64 bytes.
	if len(pubBytes) != 32 {
		t.Fatalf("public key: want 32 bytes, got %d", len(pubBytes))
	}
	if len(privBytes) != 64 {
		t.Fatalf("private key: want 64 bytes, got %d", len(privBytes))
	}
}

func TestGenerateKeypairIsUnique(t *testing.T) {
	pub1, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if pub1 == pub2 {
		t.Fatal("two generated keypairs have the same public key")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello tessera")
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := Verify(pub, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for valid signature")
	}
}

func TestVerifyFailsOnTamperedData(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("original data")
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte("tampered data")
	ok, err := Verify(pub, tampered, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("Verify returned true for tampered data")
	}
}

func TestVerifyFailsOnWrongKey(t *testing.T) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("some data")
	sig, err := Sign(priv, data)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(pub2, data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ok {
		t.Fatal("Verify returned true when using a different public key")
	}
}

func TestSignInvalidKey(t *testing.T) {
	_, err := Sign("not-base64!!!", []byte("data"))
	if err == nil {
		t.Fatal("expected error for invalid private key, got nil")
	}
}

func TestVerifyInvalidPublicKey(t *testing.T) {
	_, err := Verify("not-base64!!!", []byte("data"), "YWJj")
	if err == nil {
		t.Fatal("expected error for invalid public key, got nil")
	}
}
