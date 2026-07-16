package crypto

import (
	"bytes"
	"testing"
)

func TestCanonicalizeIsDeterministic(t *testing.T) {
	input := map[string]any{
		"z": "last",
		"a": "first",
		"m": map[string]any{
			"y": 2,
			"x": 1,
		},
		"nums": []any{3.14, 1e10, 0},
	}

	first, err := Canonicalize(input)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}

	for i := 0; i < 100; i++ {
		got, err := Canonicalize(input)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if !bytes.Equal(first, got) {
			t.Fatalf("non-deterministic output on run %d:\nwant %s\ngot  %s", i, first, got)
		}
	}
}

func TestCanonicalizeKeyOrder(t *testing.T) {
	input := map[string]any{"z": 3, "a": 1, "m": 2}
	out, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1,"m":2,"z":3}`
	if string(out) != want {
		t.Fatalf("want %s got %s", want, string(out))
	}
}

// TestCanonicalizeErrorOnNonSerializable confirms Canonicalize returns an error
// for types that json.Marshal cannot handle. This is the error class that
// WellKnownAgent's canonErr guard protects against: when Canonicalize fails,
// signing is skipped entirely rather than producing a signature over nil bytes.
func TestCanonicalizeErrorOnNonSerializable(t *testing.T) {
	badInput := map[string]any{
		"channel": make(chan int), // json.Marshal cannot serialize channels
	}
	_, err := Canonicalize(badInput)
	if err == nil {
		t.Fatal("expected error for non-serializable input, got nil")
	}
}

func TestCanonicalizeNestedKeyOrder(t *testing.T) {
	input := map[string]any{
		"outer": map[string]any{"z": 9, "a": 1},
	}
	out, err := Canonicalize(input)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"outer":{"a":1,"z":9}}`
	if string(out) != want {
		t.Fatalf("want %s got %s", want, string(out))
	}
}
