package handler

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/looselyhuman/tessera/internal/service"
)

// Handler holds the service dependencies for HTTP handlers.
type Handler struct {
	svc      *service.TesseraService
	adminKey string
}

// New creates a Handler wired to the given service.
// adminKey is the value expected in the X-Admin-Key header for admin endpoints;
// an empty string disables all admin endpoints.
func New(svc *service.TesseraService, adminKey string) *Handler {
	return &Handler{svc: svc, adminKey: adminKey}
}

// isAdminAuthorized checks the X-Admin-Key header against the configured admin key.
func (h *Handler) isAdminAuthorized(r *http.Request) bool {
	if h.adminKey == "" {
		return false
	}
	provided := r.Header.Get("X-Admin-Key")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(h.adminKey)) == 1
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
