package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// Canonicalize produces deterministic JSON suitable for signing.
// Keys are sorted alphabetically at every level.
func Canonicalize(v any) ([]byte, error) {
	// Marshal to intermediate map then re-encode with sorted keys.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	var ordered any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&ordered); err != nil {
		return nil, fmt.Errorf("decode for canonicalization: %w", err)
	}

	out, err := json.Marshal(sortedJSON(ordered))
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

// sortedJSON recursively sorts map keys so JSON output is deterministic.
func sortedJSON(v any) any {
	switch val := v.(type) {
	case map[string]any:
		sorted := make(map[string]any, len(val))
		for k, vv := range val {
			sorted[k] = sortedJSON(vv)
		}
		return sorted
	case []any:
		for i, item := range val {
			val[i] = sortedJSON(item)
		}
		return val
	default:
		return v
	}
}
