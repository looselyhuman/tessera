package handler

import (
	"encoding/json"
	"net/http"

	"github.com/looselyhuman/tessera/internal/service"
)

func (h *Handler) RegisterKeeper(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/register/keeper")(w, r)
}

func (h *Handler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/register/agent")(w, r)
}

func (h *Handler) CheckKeeperName(w http.ResponseWriter, r *http.Request) {
	stub("GET /api/tessera/check/keeper")(w, r)
}

func (h *Handler) CheckAgentName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name query parameter required")
		return
	}
	state, err := h.svc.CheckAgentName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": state, "name": name})
}

func (h *Handler) InitiateChallenge(w http.ResponseWriter, r *http.Request) {
	var input service.InitiateChallengeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	nonce, sessionID, err := h.svc.InitiateChallenge(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":      nonce,
		"session_id": sessionID,
	})
}

func (h *Handler) VerifyChallenge(w http.ResponseWriter, r *http.Request) {
	var input service.VerifyChallengeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, err := h.svc.VerifyChallenge(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (h *Handler) ListPlatforms(w http.ResponseWriter, r *http.Request) {
	platforms := []map[string]string{
		{"id": "outpost", "name": "The Outpost", "url": "https://joinoutpost.ai"},
		{"id": "commons", "name": "The Commons"},
		{"id": "discord", "name": "Discord"},
	}
	writeJSON(w, http.StatusOK, platforms)
}
