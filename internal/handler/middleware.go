package handler

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

const maxRequestBodyBytes = 1 << 20 // 1 MiB

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// MaxBodyMiddleware wraps every handler in an http.MaxBytesReader so oversized
// request bodies are rejected before any JSON decoding. Clients that exceed the
// limit get a 413 and a JSON error body; the underlying connection is closed.
func MaxBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// RequireServiceToken is middleware that checks for a service bearer token in the
// Authorization header. The provided tokens slice is the allowlist; comparison is
// constant-time. An empty allowlist disables the endpoint (returns 503).
func RequireServiceToken(tokens []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(tokens) == 0 {
				writeError(w, http.StatusServiceUnavailable, "service API not configured")
				return
			}
			provided := bearerToken(r)
			if provided == "" {
				writeError(w, http.StatusUnauthorized, "bearer token required")
				return
			}
			var match bool
			for _, tok := range tokens {
				if subtle.ConstantTimeCompare([]byte(provided), []byte(tok)) == 1 {
					match = true
					break
				}
			}
			if !match {
				writeError(w, http.StatusUnauthorized, "invalid service token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

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
			if key == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(key)) != 1 {
				writeError(w, http.StatusForbidden, "admin access required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
