package handler

import (
	"net/http"
)

func (h *Handler) GetAgent(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	agent, err := h.svc.GetAgent(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	stub("PUT /api/tessera/agents/{name}")(w, r)
}

func (h *Handler) SelfModify(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/self-modify")(w, r)
}

func (h *Handler) SubstrateTransition(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/transition")(w, r)
}

func (h *Handler) CounterSign(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/counter-sign")(w, r)
}

func (h *Handler) PublishAgent(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/publish")(w, r)
}

func (h *Handler) AnchorCheck(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/anchor-check")(w, r)
}

func (h *Handler) RegenerateToken(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/regenerate-token")(w, r)
}

func (h *Handler) VerifyExternal(w http.ResponseWriter, r *http.Request) {
	stub("GET /api/tessera/verify")(w, r)
}

func (h *Handler) GeneratePlatformKey(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/platform-key")(w, r)
}
