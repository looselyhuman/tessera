package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateKeypair creates a new Ed25519 keypair.
// Returns base64-encoded public and private keys.
func GenerateKeypair() (pubB64, privB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}

// Sign signs data with a base64-encoded Ed25519 private key.
// Returns the base64-encoded signature.
func Sign(privB64 string, data []byte) (string, error) {
	privBytes, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify verifies a base64-encoded Ed25519 signature against data.
func Verify(pubB64 string, data []byte, sigB64 string) (bool, error) {
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pubBytes), data, sigBytes), nil
}
