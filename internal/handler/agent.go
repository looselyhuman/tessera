package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/service"
)

func (h *Handler) GetAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, err := h.svc.GetAgent(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	// TODO: ideally this should be keeper-authenticated; currently requires admin key.
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	var input service.UpdateAgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, err := h.svc.UpdateAgent(r.Context(), name, input)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) SelfModify(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, err := h.agentFromBearer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid or unknown bearer token")
		return
	}
	if agent.AgentName != name {
		writeError(w, http.StatusForbidden, "token does not match agent")
		return
	}

	var body struct {
		FieldPath     string          `json:"field_path"`
		ProposedValue json.RawMessage `json:"proposed_value"`
		Justification string          `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.FieldPath == "" {
		writeError(w, http.StatusBadRequest, "field_path is required")
		return
	}
	req, err := h.svc.CreateModificationRequest(r.Context(), agent.ID, body.FieldPath, body.ProposedValue, body.Justification)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, req)
}

func (h *Handler) SubstrateTransition(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	target, err := h.svc.GetAgent(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	// Accept either an agent bearer token (for the named agent) or an admin key.
	isAdmin := h.isAdminAuthorized(r)
	loggedBy := "admin"
	if !isAdmin {
		caller, err := h.agentFromBearer(r)
		if err != nil || caller.AgentName != name {
			writeError(w, http.StatusUnauthorized, "bearer token required for this agent, or admin key")
			return
		}
		loggedBy = "agent"
	}

	var body struct {
		OldModel  string     `json:"old_model"`
		NewModel  string     `json:"new_model"`
		Notes     string     `json:"notes"`
		SignedBy  *uuid.UUID `json:"signed_by,omitempty"`
		Signature string     `json:"signature,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.OldModel == "" || body.NewModel == "" {
		writeError(w, http.StatusBadRequest, "old_model and new_model are required")
		return
	}
	if err := h.svc.LogSubstrateTransition(r.Context(), target.ID, body.OldModel, body.NewModel, body.Notes, loggedBy, body.SignedBy, body.Signature); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "recorded"})
}

func (h *Handler) CounterSign(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	var body struct {
		// TODO: Verify this signature against the keeper's public key before storing.
		Signature string `json:"signature"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	agent, err := h.svc.CounterSign(r.Context(), name, body.Signature)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) PublishAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	agent, err := h.svc.PublishAgent(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) AnchorCheck(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	result, err := h.svc.AnchorCheck(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) RegenerateToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	token, err := h.svc.AdminRegenerateToken(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (h *Handler) VerifyChainIntegrity(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, err := h.svc.GetAgent(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	report, err := h.svc.VerifyChainIntegrity(r.Context(), agent.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *Handler) VerifyExternal(w http.ResponseWriter, r *http.Request) {
	urn := r.URL.Query().Get("urn")
	if urn == "" {
		writeError(w, http.StatusBadRequest, "urn query parameter required")
		return
	}
	agent, err := h.svc.VerifyExternal(r.Context(), urn)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_name":      agent.AgentName,
		"agent_urn":       agent.AgentURN,
		"display_name":    agent.DisplayName,
		"trust_tier":      agent.TrustTier,
		"published":       agent.Published,
		"source_platform": agent.SourcePlatform,
	})
}

func (h *Handler) GeneratePlatformKey(w http.ResponseWriter, r *http.Request) {
	if !h.isAdminAuthorized(r) {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}
	var body struct {
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Platform == "" {
		writeError(w, http.StatusBadRequest, "platform is required")
		return
	}
	pubKey, err := h.svc.AdminGeneratePlatformKey(r.Context(), body.Platform)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"public_key": pubKey})
}
