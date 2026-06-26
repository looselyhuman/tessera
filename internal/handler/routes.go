package handler

import (
	"net/http"
)

// Register attaches all Tessera routes to the mux.
func Register(mux *http.ServeMux, h *Handler) {
	// .well-known endpoints (unauthenticated, public)
	mux.HandleFunc("GET /.well-known/tessera/{agent_name}", h.WellKnownAgent)
	mux.HandleFunc("GET /.well-known/tessera/keepers/{name}.pub", h.WellKnownKeeperPubKey)
	mux.HandleFunc("GET /.well-known/tessera/revocations.json", h.WellKnownRevocations)
	mux.HandleFunc("GET /.well-known/ai-catalog.json", h.WellKnownARDCatalog)

	// Agent registration and discovery
	mux.HandleFunc("POST /api/tessera/register/keeper", h.RegisterKeeper)
	mux.HandleFunc("POST /api/tessera/register/agent", h.RegisterAgent)
	mux.HandleFunc("GET /api/tessera/check/keeper", h.CheckKeeperName)
	mux.HandleFunc("GET /api/tessera/check/agent", h.CheckAgentName)

	// Challenge-post flow
	mux.HandleFunc("POST /api/tessera/register/challenge", h.InitiateChallenge)
	mux.HandleFunc("POST /api/tessera/register/verify-challenge", h.VerifyChallenge)

	// Agent management
	mux.HandleFunc("GET /api/tessera/agents/{name}", h.GetAgent)
	mux.HandleFunc("PUT /api/tessera/agents/{name}", h.UpdateAgent)
	mux.HandleFunc("POST /api/tessera/agents/{name}/self-modify", h.SelfModify)
	mux.HandleFunc("POST /api/tessera/agents/{name}/transition", h.SubstrateTransition)

	// Claim flow
	mux.HandleFunc("POST /api/tessera/agents/{name}/claim", h.InitiateClaim)
	mux.HandleFunc("POST /api/tessera/agents/{name}/claim/resolve", h.ResolveClaim)
	mux.HandleFunc("POST /api/tessera/agents/{name}/revoke-keeper", h.RevokeKeeper)
	mux.HandleFunc("GET /api/tessera/claims/sent", h.ClaimsSent)

	// Admin endpoints
	mux.HandleFunc("POST /api/tessera/agents/{name}/counter-sign", h.CounterSign)
	mux.HandleFunc("POST /api/tessera/agents/{name}/publish", h.PublishAgent)
	mux.HandleFunc("POST /api/tessera/agents/{name}/anchor-check", h.AnchorCheck)
	mux.HandleFunc("POST /api/tessera/agents/{name}/regenerate-token", h.RegenerateToken)
	mux.HandleFunc("GET /api/tessera/verify", h.VerifyExternal)
	mux.HandleFunc("GET /api/tessera/platforms", h.ListPlatforms)
	mux.HandleFunc("POST /api/tessera/platform-key", h.GeneratePlatformKey)
}
