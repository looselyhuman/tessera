package handler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
)

func (h *Handler) InitiateClaim(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// Keeper auth via their registered agent's bearer token.
	// TODO: add a dedicated keeper auth path that doesn't require a pre-existing agent.
	caller, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	if caller.KeeperID == nil {
		writeError(w, http.StatusForbidden, "caller's agent has no associated keeper")
		return
	}

	var body struct {
		KeeperStatement string `json:"keeper_statement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	claim, err := h.svc.InitiateClaim(r.Context(), *caller.KeeperID, name, body.KeeperStatement)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, claim)
}

func (h *Handler) ResolveClaim(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	if agent.AgentName != name {
		writeError(w, http.StatusForbidden, "token does not match agent")
		return
	}

	var body struct {
		ClaimID uuid.UUID          `json:"claim_id"`
		Status  domain.ClaimStatus `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.ClaimID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "claim_id is required")
		return
	}
	if body.Status != domain.ClaimAccepted && body.Status != domain.ClaimRejected {
		writeError(w, http.StatusBadRequest, "status must be 'accepted' or 'rejected'")
		return
	}

	claim, err := h.svc.ResolveClaim(r.Context(), body.ClaimID, agent.ID, body.Status)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (h *Handler) RevokeKeeper(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	if err := h.svc.AdminRevokeKeeper(r.Context(), name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "keeper_revoked"})
}

func (h *Handler) ClaimsSent(w http.ResponseWriter, r *http.Request) {
	// Keeper auth via their registered agent's bearer token.
	// TODO: add a dedicated keeper auth path.
	caller, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	if caller.KeeperID == nil {
		writeError(w, http.StatusForbidden, "caller's agent has no associated keeper")
		return
	}

	claims, err := h.svc.GetClaimsSent(r.Context(), *caller.KeeperID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if claims == nil {
		claims = []domain.ClaimRequest{}
	}
	writeJSON(w, http.StatusOK, claims)
}
