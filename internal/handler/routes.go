package handler

import (
	"net/http"
)

// Register attaches all Tessera routes to the mux.
func Register(mux *http.ServeMux, h *Handler) {
	// .well-known endpoints (unauthenticated, public)
	mux.HandleFunc("GET /.well-known/tessera/{agent_name}", h.WellKnownAgent)
	mux.HandleFunc("GET /.well-known/tessera/keepers/{name}", h.WellKnownKeeperPubKey)
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

	// Self-service /me endpoints (bearer token auth)
	mux.Handle("GET /api/tessera/me", RequireBearer(http.HandlerFunc(h.MeGet)))
	mux.Handle("PUT /api/tessera/me", RequireBearer(http.HandlerFunc(h.MeUpdate)))
	mux.Handle("POST /api/tessera/me/transition", RequireBearer(http.HandlerFunc(h.MeTransition)))
	mux.Handle("GET /api/tessera/me/chain", RequireBearer(http.HandlerFunc(h.MeChain)))
	mux.Handle("POST /api/tessera/me/request-countersign", RequireBearer(http.HandlerFunc(h.MeRequestCounterSign)))
	mux.Handle("POST /api/tessera/me/revoke-keeper", RequireBearer(http.HandlerFunc(h.MeRevokeKeeper)))

	// Admin endpoints — protected by RequireAdminKey middleware
	adminMW := RequireAdminKey(h.adminKey)
	mux.Handle("POST /api/tessera/agents/{name}/counter-sign", adminMW(http.HandlerFunc(h.CounterSign)))
	mux.Handle("POST /api/tessera/agents/{name}/publish", adminMW(http.HandlerFunc(h.PublishAgent)))
	mux.Handle("POST /api/tessera/agents/{name}/anchor-check", adminMW(http.HandlerFunc(h.AnchorCheck)))
	mux.Handle("POST /api/tessera/agents/{name}/regenerate-token", adminMW(http.HandlerFunc(h.RegenerateToken)))
	mux.Handle("POST /api/tessera/platform-key", adminMW(http.HandlerFunc(h.GeneratePlatformKey)))
	mux.Handle("GET /api/tessera/platforms", adminMW(http.HandlerFunc(h.ListPlatforms)))

	// Verify returns a stripped public view — no auth required, no sensitive fields exposed
	mux.HandleFunc("GET /api/tessera/verify", h.VerifyExternal)
}
