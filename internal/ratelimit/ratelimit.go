// Package ratelimit provides a sliding-window in-memory rate limiter keyed by client IP.
// The implementation mirrors the agora middleware/ratelimit.go pattern exactly so both
// services share the same proxy-aware IP extraction logic.
package ratelimit

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is a sliding-window in-memory rate limiter keyed by client IP.
type Limiter struct {
	window         time.Duration
	limit          int
	buckets        sync.Map // map[string]*ipBucket
	trustedProxies []*net.IPNet
}

type ipBucket struct {
	mu       sync.Mutex
	requests []time.Time
}

var defaultTrustedProxyCIDRs = []string{
	"127.0.0.1/32",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

// New creates a Limiter allowing at most requestsPerMinute requests per IP
// in any 60-second sliding window. Starts a background goroutine to prune stale buckets.
func New(requestsPerMinute int) *Limiter {
	rl := &Limiter{
		window: time.Minute,
		limit:  requestsPerMinute,
	}
	for _, cidr := range defaultTrustedProxyCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			rl.trustedProxies = append(rl.trustedProxies, network)
		}
	}
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the request from ip is within the rate limit.
func (rl *Limiter) Allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	v, _ := rl.buckets.LoadOrStore(ip, &ipBucket{})
	bucket := v.(*ipBucket)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	valid := bucket.requests[:0]
	for _, t := range bucket.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	bucket.requests = valid

	if len(bucket.requests) >= rl.limit {
		return false
	}
	bucket.requests = append(bucket.requests, now)
	return true
}

// Middleware wraps h with rate limiting. Rejected requests get 429 + Retry-After: 60.
func (rl *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(rl.clientIP(r)) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isTrustedProxy reports whether host (bare IP, no port) is in the trusted proxy list.
func (rl *Limiter) isTrustedProxy(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range rl.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP extracts the real client IP. XFF/X-Real-IP are only trusted when the
// direct peer (RemoteAddr) is a known proxy CIDR; otherwise RemoteAddr is used directly.
func (rl *Limiter) clientIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}
	if rl.isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			return strings.TrimSpace(parts[0])
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	return host
}

// cleanupLoop runs every 5 minutes and deletes buckets whose requests all fall
// outside the current window, preventing unbounded memory growth.
func (rl *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.window)
		rl.buckets.Range(func(key, value any) bool {
			bucket := value.(*ipBucket)
			bucket.mu.Lock()
			allStale := true
			for _, t := range bucket.requests {
				if t.After(cutoff) {
					allStale = false
					break
				}
			}
			if allStale {
				rl.buckets.Delete(key)
			}
			bucket.mu.Unlock()
			return true
		})
	}
}
