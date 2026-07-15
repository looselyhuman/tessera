package handler

import (
	"net/http"
	"testing"
)

// TestRegisterNoPatternConflicts ensures the full route table registers without
// panicking. Go 1.22+ ServeMux panics at registration time on ambiguous
// patterns — a failure mode that go build and go vet cannot catch, and that
// otherwise only surfaces when the binary starts.
func TestRegisterNoPatternConflicts(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked: %v", r)
		}
	}()
	Register(http.NewServeMux(), &Handler{})
}
