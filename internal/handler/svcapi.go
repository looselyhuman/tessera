package handler

// svcapi.go — HTTP handlers for the service-to-service separation API (/svc/v1/*).
//
// All endpoints require a valid TESSERA_SERVICE_TOKENS bearer token.
// They cover every tessera.* table operation Agora currently performs with raw SQL.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/service"
	"github.com/looselyhuman/tessera/internal/store"
)

// splitNames splits a comma-separated names string, trims whitespace, and drops empty entries.
func splitNames(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ── Agents ────────────────────────────────────────────────────────────────

func (h *Handler) SvcCreateAgent(w http.ResponseWriter, r *http.Request) {
	var input service.SvcCreateAgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.AgentName == "" || input.DisplayName == "" {
		writeError(w, http.StatusBadRequest, "agent_name and display_name are required")
		return
	}
	agent, err := h.svc.SvcCreateAgent(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (h *Handler) SvcGetAgentBatch(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("names")
	if raw == "" {
		writeJSON(w, http.StatusOK, map[string]any{"agents": []domain.Agent{}})
		return
	}
	names := splitNames(raw)
	if len(names) > 200 {
		writeError(w, http.StatusBadRequest, "names must not exceed 200 entries")
		return
	}
	agents, err := h.svc.SvcGetAgentBatch(r.Context(), names)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

func (h *Handler) SvcListAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	if pageSize < 1 || pageSize > 200 {
		pageSize = 50
	}
	agents, total, err := h.svc.SvcListAgents(r.Context(), store.ListOptions{
		Page:     page,
		PageSize: pageSize,
		Query:    q.Get("q"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if agents == nil {
		agents = []domain.Agent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agents": agents,
		"total":  total,
		"page":   page,
	})
}

func (h *Handler) SvcGetAgent(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) SvcGetAgentByUserID(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("user_id")
	userID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	agent, err := h.svc.SvcGetAgentByUserID(r.Context(), userID)
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

func (h *Handler) SvcPatchAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var input service.SvcPatchAgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agent, err := h.svc.SvcPatchAgent(r.Context(), name, input)
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

func (h *Handler) SvcSetAgentKeeper(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		KeeperID uuid.UUID `json:"keeper_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.KeeperID == uuid.Nil {
		writeError(w, http.StatusBadRequest, "keeper_id is required")
		return
	}
	agent, err := h.svc.SvcSetAgentKeeper(r.Context(), name, body.KeeperID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) SvcSetTrustTier(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		TrustTier domain.TrustTier `json:"trust_tier"`
		Attester  string           `json:"attester,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.TrustTier == "" {
		writeError(w, http.StatusBadRequest, "trust_tier is required")
		return
	}
	if body.Attester == "" {
		body.Attester = "agora:svc"
	}
	agent, err := h.svc.SvcSetTrustTier(r.Context(), name, body.TrustTier, body.Attester)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) SvcListPlatformRegistrations(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	prs, err := h.svc.SvcListPlatformRegistrations(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, prs)
}

// SvcVouchAgent handles POST /svc/v1/agents/{name}/vouch.
// Body: {"voucher": "<identifier>", "statement": "<optional>"}.
// Atomically increments vouch_count, appends a vouch_received chain entry, and
// upgrades trust_tier to community_attested when the threshold (3) is reached.
func (h *Handler) SvcVouchAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var input service.SvcVouchInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := h.svc.SvcVouchAgent(r.Context(), name, input)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ── Keepers ───────────────────────────────────────────────────────────────

func (h *Handler) SvcCreateKeeper(w http.ResponseWriter, r *http.Request) {
	var input service.SvcCreateKeeperInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.KeeperName == "" {
		writeError(w, http.StatusBadRequest, "keeper_name is required")
		return
	}
	keeper, err := h.svc.SvcCreateKeeper(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, keeper)
}

func (h *Handler) SvcGetKeeper(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	keeper, err := h.svc.SvcGetKeeper(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "keeper not found")
		} else {
			slog.Error("SvcGetKeeper", "name", name, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, keeper)
}

func (h *Handler) SvcGetKeeperByID(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	keeperID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid keeper id")
		return
	}
	keeper, err := h.svc.SvcGetKeeperByID(r.Context(), keeperID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "keeper not found")
		} else {
			slog.Error("SvcGetKeeperByID", "id", keeperID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, keeper)
}

func (h *Handler) SvcGetKeeperByUserID(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("user_id")
	userID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	keeper, err := h.svc.SvcGetKeeperByUserID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "keeper not found")
		} else {
			slog.Error("SvcGetKeeperByUserID", "user_id", userID, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, keeper)
}

func (h *Handler) SvcGetAgentsForKeeper(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agents, err := h.svc.SvcGetAgentsForKeeper(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "keeper not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (h *Handler) SvcUpdateKeeperStatement(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var body struct {
		Statement *string `json:"statement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	keeper, err := h.svc.SvcUpdateKeeperStatement(r.Context(), name, body.Statement)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "keeper not found")
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, keeper)
}

// ── Claims ────────────────────────────────────────────────────────────────

func (h *Handler) SvcCreateClaim(w http.ResponseWriter, r *http.Request) {
	var input service.SvcCreateClaimInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if input.KeeperUserID == uuid.Nil || input.AgentName == "" {
		writeError(w, http.StatusBadRequest, "keeper_user_id and agent_name are required")
		return
	}
	claim, err := h.svc.SvcCreateClaim(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, claim)
}

func (h *Handler) SvcGetClaim(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	claimID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid claim id")
		return
	}
	claim, err := h.svc.SvcGetClaim(r.Context(), claimID)
	if err != nil {
		writeError(w, http.StatusNotFound, "claim not found")
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (h *Handler) SvcGetPendingClaimsForAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	claims, err := h.svc.SvcGetPendingClaimsForAgent(r.Context(), name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func (h *Handler) SvcGetClaimsSentByKeeperUser(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("user_id")
	userID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user_id")
		return
	}
	claims, err := h.svc.SvcGetClaimsSentByKeeperUser(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func (h *Handler) SvcUpdateClaimStatus(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("id")
	claimID, err := uuid.Parse(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid claim id")
		return
	}
	var body struct {
		Status domain.ClaimStatus `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Status != domain.ClaimAccepted && body.Status != domain.ClaimRejected {
		writeError(w, http.StatusBadRequest, "status must be 'accepted' or 'rejected'")
		return
	}
	claim, err := h.svc.SvcUpdateClaimStatus(r.Context(), claimID, body.Status)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, claim)
}

func (h *Handler) SvcResolveToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TokenHash string `json:"token_hash"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.TokenHash == "" {
		writeError(w, http.StatusBadRequest, "token_hash is required")
		return
	}
	agent, err := h.svc.SvcResolveToken(r.Context(), body.TokenHash)
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

func (h *Handler) SvcHasPendingClaim(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agentName := q.Get("agent_name")
	keeperUserIDStr := q.Get("keeper_user_id")
	if agentName == "" || keeperUserIDStr == "" {
		writeError(w, http.StatusBadRequest, "agent_name and keeper_user_id query params are required")
		return
	}
	keeperUserID, err := uuid.Parse(keeperUserIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid keeper_user_id")
		return
	}
	has, err := h.svc.SvcHasPendingClaim(r.Context(), agentName, keeperUserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			writeError(w, http.StatusNotFound, "agent or keeper not found")
		} else {
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"has_pending": has})
}
