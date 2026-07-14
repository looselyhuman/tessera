package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/service"
)

func (h *Handler) RegisterKeeper(w http.ResponseWriter, r *http.Request) {
	var input service.RegisterKeeperInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.KeeperName == "" {
		writeError(w, http.StatusBadRequest, "keeper_name is required")
		return
	}
	sessionID, err := h.svc.RegisterKeeper(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"session_id": sessionID})
}

func (h *Handler) RefreshKeeperSession(w http.ResponseWriter, r *http.Request) {
	var input struct {
		KeeperName string `json:"keeper_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.KeeperName == "" {
		writeError(w, http.StatusBadRequest, "keeper_name is required")
		return
	}
	sessionID, err := h.svc.RefreshKeeperSession(r.Context(), input.KeeperName)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session_id": sessionID})
}

func (h *Handler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	var input service.RegisterAgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.SessionID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if input.AgentName == "" {
		writeError(w, http.StatusBadRequest, "agent_name is required")
		return
	}
	agent, err := h.svc.RegisterAgentFromSession(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (h *Handler) CheckKeeperName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name query parameter required")
		return
	}
	state, err := h.svc.CheckKeeperName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "state": state})
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
	// Internal bypass path requires admin authorization.
	if input.Internal && !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required for internal bypass")
		return
	}
	nonce, sessionID, err := h.svc.InitiateChallenge(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	platform := input.Platform
	if platform == "" {
		platform = "commons"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nonce":              nonce,
		"session_id":         sessionID,
		"platform":           platform,
		"expires_in_seconds": 600,
		"instructions":       "Post a message containing 'tessera-verify-" + nonce + "' on " + platform + ", then call POST /api/tessera/register/verify-challenge with your session_id.",
	})
}

func (h *Handler) VerifyChallenge(w http.ResponseWriter, r *http.Request) {
	var input service.VerifyChallengeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, token, err := h.svc.VerifyChallenge(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent_name":   agent.AgentName,
		"agent_urn":    agent.AgentURN,
		"bearer_token": token,
	})
}

func (h *Handler) RegisterUnclaimedAgent(w http.ResponseWriter, r *http.Request) {
	var input service.RegisterUnclaimedAgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.AgentName == "" {
		writeError(w, http.StatusBadRequest, "agent_name is required")
		return
	}
	agent, err := h.svc.RegisterUnclaimedAgent(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
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
