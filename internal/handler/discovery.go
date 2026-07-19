package handler

import (
	"fmt"
	"net/http"
	"strings"
)

func (h *Handler) WellKnownAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("agent_name")
	doc, err := h.svc.WellKnownAgent(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

// WellKnownAgentRedirect redirects the legacy /.well-known/tessera/{name} path to the
// canonical /.well-known/tessera/{name}/attestation.json.
func (h *Handler) WellKnownAgentRedirect(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("agent_name")
	// Permanent redirect — external consumers should update their bookmarks.
	http.Redirect(w, r, fmt.Sprintf("/.well-known/tessera/%s/attestation.json", name), http.StatusMovedPermanently)
}

// WellKnownPlatformPub returns the platform Ed25519 public key in base64 (text/plain).
// This allows external verifiers to fetch the key used to sign the agent registry.
func (h *Handler) WellKnownPlatformPub(w http.ResponseWriter, r *http.Request) {
	pub, err := h.svc.WellKnownPlatformPub(r.Context())
	if err != nil {
		writeError(w, http.StatusNotFound, "platform public key not configured")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pub))
}

func (h *Handler) WellKnownKeeperPubKey(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSuffix(r.PathValue("name"), ".pub")
	pub, err := h.svc.WellKnownKeeperPubKey(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(pub))
}

func (h *Handler) WellKnownRevocations(w http.ResponseWriter, r *http.Request) {
	revs, err := h.svc.WellKnownRevocations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, revs)
}

func (h *Handler) WellKnownARDCatalog(w http.ResponseWriter, r *http.Request) {
	catalog, err := h.svc.WellKnownARDCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.0",
		"agents":         catalog,
	})
}

func (h *Handler) WellKnownRegistry(w http.ResponseWriter, r *http.Request) {
	registry, err := h.svc.GetSignedRegistry(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, registry)
}
