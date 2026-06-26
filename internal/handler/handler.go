package handler

import (
	"encoding/json"
	"net/http"

	"github.com/looselyhuman/tessera/internal/service"
)

// Handler holds the service dependencies for HTTP handlers.
type Handler struct {
	svc *service.TesseraService
}

// New creates a Handler wired to the given service.
func New(svc *service.TesseraService) *Handler {
	return &Handler{svc: svc}
}

// stub writes a 501 Not Implemented JSON response for unimplemented endpoints.
func stub(endpoint string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":    "not implemented",
			"endpoint": endpoint,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
