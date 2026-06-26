package handler

import (
	"net/http"
	"strings"
)

// bearerToken extracts a Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// RequireBearer is a middleware that requires a non-empty Bearer token.
// It does NOT validate the token — that's the service's responsibility.
func RequireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if bearerToken(r) == "" {
			writeError(w, http.StatusUnauthorized, "bearer token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdminKey is a middleware that checks for an admin API key header.
// Key is compared to the value set at server startup.
func RequireAdminKey(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provided := r.Header.Get("X-Admin-Key")
			if key == "" || provided != key {
				writeError(w, http.StatusForbidden, "admin access required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
