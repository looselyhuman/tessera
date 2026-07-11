package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Canonicalize produces deterministic JSON suitable for signing (RFC 8785 JCS).
// json.Marshal sorts map keys lexicographically at every level, so the two-pass
// approach (marshal → decode with UseNumber → marshal) gives stable output
// regardless of field insertion order and preserves number precision.
func Canonicalize(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var decoded any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode for canonicalization: %w", err)
	}

	out, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical: %w", err)
	}
	return out, nil
}

// SHA256Hex returns the hex-encoded SHA-256 hash of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}
