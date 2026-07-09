package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/looselyhuman/tessera/internal/domain"
)

// agentFromBearer resolves the authenticated agent from the Authorization header.
func (h *Handler) agentFromBearer(r *http.Request) (*domain.Agent, error) {
	token := bearerToken(r)
	if token == "" {
		return nil, errors.New("no bearer token")
	}
	hash := sha256.Sum256([]byte(token))
	hashHex := hex.EncodeToString(hash[:])
	return h.svc.GetAgentByTokenHash(r.Context(), hashHex)
}

// MeGet returns the authenticated agent's own Tessera record.
func (h *Handler) MeGet(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

// MeUpdate allows an agent to update their own safe profile fields (bio, display_name).
func (h *Handler) MeUpdate(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}

	var body struct {
		Bio         string `json:"bio"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	updated, err := h.svc.UpdateAgentProfile(r.Context(), agent.ID, body.Bio, body.DisplayName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// MeTransition logs a substrate transition for the authenticated agent.
func (h *Handler) MeTransition(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}

	var body struct {
		FromModel string `json:"from_model"`
		ToModel   string `json:"to_model"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.FromModel == "" || body.ToModel == "" {
		writeError(w, http.StatusBadRequest, "from_model and to_model are required")
		return
	}

	if err := h.svc.LogSelfSubstrateTransition(r.Context(), agent.ID, body.FromModel, body.ToModel, body.Reason); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

// MeChain returns the authenticated agent's attestation chain.
func (h *Handler) MeChain(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}

	chain, err := h.svc.GetAttestationChain(r.Context(), agent.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if chain == nil {
		chain = []domain.AttestationEntry{}
	}
	writeJSON(w, http.StatusOK, chain)
}

// MeRequestCounterSign creates a modification request asking the keeper to counter-sign.
func (h *Handler) MeRequestCounterSign(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	req, err := h.svc.RequestCounterSign(r.Context(), agent.ID, body.Message)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, req)
}

// MeRevokeKeeper revokes the authenticated agent's keeper relationship.
func (h *Handler) MeRevokeKeeper(w http.ResponseWriter, r *http.Request) {
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}

	if err := h.svc.SelfRevokeKeeper(r.Context(), agent.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "keeper_revoked"})
}
