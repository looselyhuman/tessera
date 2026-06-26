package handler

import (
	"net/http"
)

func (h *Handler) InitiateClaim(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/claim")(w, r)
}

func (h *Handler) ResolveClaim(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/claim/resolve")(w, r)
}

func (h *Handler) RevokeKeeper(w http.ResponseWriter, r *http.Request) {
	stub("POST /api/tessera/agents/{name}/revoke-keeper")(w, r)
}

func (h *Handler) ClaimsSent(w http.ResponseWriter, r *http.Request) {
	stub("GET /api/tessera/claims/sent")(w, r)
}
