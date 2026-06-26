package handler

import (
	"net/http"
)

func (h *Handler) WellKnownAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("agent_name")
	doc, err := h.svc.WellKnownAgent(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

func (h *Handler) WellKnownKeeperPubKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	pub, err := h.svc.WellKnownKeeperPubKey(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
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
	writeJSON(w, http.StatusOK, revs)
}

func (h *Handler) WellKnownARDCatalog(w http.ResponseWriter, r *http.Request) {
	catalog, err := h.svc.WellKnownARDCatalog(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"schema_version": "1.0",
		"agents":         catalog,
	})
}
