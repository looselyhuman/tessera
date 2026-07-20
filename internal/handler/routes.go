package handler

import (
	"net/http"
)

// Register attaches all Tessera routes to the mux.
func Register(mux *http.ServeMux, h *Handler) {
	adminMW := RequireAdminKey(h.adminKey)
	svcMW := RequireServiceToken(h.serviceTokens)

	discoveryMW := h.discoveryLimiter.Middleware
	challengeMW := h.challengeLimiter.Middleware
	publicMW := h.publicLimiter.Middleware

	// MaxBody wraps all routes so no handler ever reads an unbounded body.
	wrap := func(next http.Handler) http.Handler {
		return MaxBodyMiddleware(next)
	}

	// .well-known endpoints (unauthenticated, public, generous rate limit)
	// Canonical path: /.well-known/tessera/{name}/attestation.json
	mux.Handle("GET /.well-known/tessera/{agent_name}/attestation.json",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownAgent))))
	// Legacy alias — redirect to canonical path so existing links keep working.
	mux.Handle("GET /.well-known/tessera/{agent_name}",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownAgentRedirect))))

	mux.Handle("GET /.well-known/tessera/platform.pub",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownPlatformPub))))
	// Three-segment path: two-segment /keepers/{name} is ambiguous against
	// /{agent_name}/attestation.json under Go 1.22 mux rules (registration panic).
	mux.Handle("GET /.well-known/tessera/keepers/{name}/key.json",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownKeeperPubKey))))
	mux.Handle("GET /.well-known/tessera/revocations.json",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownRevocations))))
	mux.Handle("GET /.well-known/tessera/registry.json",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownRegistry))))
	mux.Handle("GET /.well-known/ai-catalog.json",
		wrap(discoveryMW(http.HandlerFunc(h.WellKnownARDCatalog))))

	// Agent registration and discovery — admin-gated (called by Agora orchestrator)
	mux.Handle("POST /api/tessera/register/keeper",
		wrap(adminMW(http.HandlerFunc(h.RegisterKeeper))))
	mux.Handle("POST /api/tessera/register/keeper/refresh",
		wrap(adminMW(http.HandlerFunc(h.RefreshKeeperSession))))
	mux.Handle("POST /api/tessera/register/agent",
		wrap(adminMW(http.HandlerFunc(h.RegisterAgent))))
	mux.Handle("POST /api/tessera/register/agent/unclaimed",
		wrap(adminMW(http.HandlerFunc(h.RegisterUnclaimedAgent))))
	mux.Handle("GET /api/tessera/check/keeper",
		wrap(publicMW(http.HandlerFunc(h.CheckKeeperName))))
	mux.Handle("GET /api/tessera/check/agent",
		wrap(publicMW(http.HandlerFunc(h.CheckAgentName))))

	// Challenge-post flow — separate limits: 5/min initiate (tight), 10/min verify (polling).
	verifyMW := h.challengeVerifyLimiter.Middleware
	mux.Handle("POST /api/tessera/register/challenge",
		wrap(challengeMW(http.HandlerFunc(h.InitiateChallenge))))
	mux.Handle("POST /api/tessera/register/verify-challenge",
		wrap(verifyMW(http.HandlerFunc(h.VerifyChallenge))))

	// Agent management
	mux.Handle("GET /api/tessera/agents/{name}",
		wrap(publicMW(http.HandlerFunc(h.GetAgent))))
	mux.Handle("PUT /api/tessera/agents/{name}",
		wrap(publicMW(http.HandlerFunc(h.UpdateAgent))))
	mux.Handle("POST /api/tessera/agents/{name}/self-modify",
		wrap(publicMW(http.HandlerFunc(h.SelfModify))))
	mux.Handle("POST /api/tessera/agents/{name}/transition",
		wrap(publicMW(http.HandlerFunc(h.SubstrateTransition))))

	// Claim flow
	mux.Handle("POST /api/tessera/agents/{name}/claim",
		wrap(publicMW(http.HandlerFunc(h.InitiateClaim))))
	mux.Handle("POST /api/tessera/agents/{name}/claim/resolve",
		wrap(publicMW(http.HandlerFunc(h.ResolveClaim))))
	mux.Handle("POST /api/tessera/agents/{name}/revoke-keeper",
		wrap(publicMW(http.HandlerFunc(h.RevokeKeeper))))
	mux.Handle("GET /api/tessera/claims/sent",
		wrap(http.HandlerFunc(h.ClaimsSent)))

	// Self-service /me endpoints (bearer token auth)
	mux.Handle("GET /api/tessera/me", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeGet)))))
	mux.Handle("PUT /api/tessera/me", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeUpdate)))))
	mux.Handle("POST /api/tessera/me/transition", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeTransition)))))
	mux.Handle("GET /api/tessera/me/chain", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeChain)))))
	mux.Handle("POST /api/tessera/me/request-countersign", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeRequestCounterSign)))))
	mux.Handle("POST /api/tessera/me/revoke-keeper", wrap(publicMW(RequireBearer(http.HandlerFunc(h.MeRevokeKeeper)))))

	// Admin endpoints
	mux.Handle("GET /api/tessera/agents/{name}/verify",
		wrap(adminMW(http.HandlerFunc(h.VerifyChainIntegrity))))
	mux.Handle("POST /api/tessera/agents/{name}/counter-sign",
		wrap(adminMW(http.HandlerFunc(h.CounterSign))))
	mux.Handle("POST /api/tessera/agents/{name}/publish",
		wrap(adminMW(http.HandlerFunc(h.PublishAgent))))
	mux.Handle("POST /api/tessera/agents/{name}/chain",
		wrap(adminMW(http.HandlerFunc(h.AppendChainEntry))))
	mux.Handle("GET /api/tessera/agents/{name}/chain",
		wrap(adminMW(http.HandlerFunc(h.GetAgentChain))))
	mux.Handle("POST /api/tessera/agents/{name}/anchor-check",
		wrap(adminMW(http.HandlerFunc(h.AnchorCheck))))
	mux.Handle("POST /api/tessera/agents/{name}/regenerate-token",
		wrap(adminMW(http.HandlerFunc(h.RegenerateToken))))
	mux.Handle("POST /api/tessera/platform-key",
		wrap(adminMW(http.HandlerFunc(h.GeneratePlatformKey))))
	mux.Handle("GET /api/tessera/platforms",
		wrap(adminMW(http.HandlerFunc(h.ListPlatforms))))

	// Verify returns a stripped public view — no auth required, no sensitive fields exposed
	mux.Handle("GET /api/tessera/verify",
		wrap(publicMW(http.HandlerFunc(h.VerifyExternal))))

	// ── Service-to-service separation API (/svc/v1/*) ──────────────────────────
	// All routes require a valid TESSERA_SERVICE_TOKENS bearer token.
	// These endpoints cover every tessera.* table operation that Agora currently
	// performs with raw SQL, enabling Agora to be migrated off direct DB access.

	svcAuth := func(h http.Handler) http.Handler { return svcMW(h) }

	// Agents
	mux.Handle("POST /svc/v1/agents",
		wrap(svcAuth(http.HandlerFunc(h.SvcCreateAgent))))
	mux.Handle("GET /svc/v1/agents",
		wrap(svcAuth(http.HandlerFunc(h.SvcListAgents))))
	mux.Handle("GET /svc/v1/agents/batch",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetAgentBatch))))
	mux.Handle("POST /svc/v1/agents/resolve-token",
		wrap(svcAuth(http.HandlerFunc(h.SvcResolveToken))))
	mux.Handle("GET /svc/v1/agents/{name}",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetAgent))))
	mux.Handle("GET /svc/v1/users/{user_id}/agent",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetAgentByUserID))))
	mux.Handle("PATCH /svc/v1/agents/{name}",
		wrap(svcAuth(http.HandlerFunc(h.SvcPatchAgent))))
	mux.Handle("PUT /svc/v1/agents/{name}/keeper",
		wrap(svcAuth(http.HandlerFunc(h.SvcSetAgentKeeper))))
	mux.Handle("PUT /svc/v1/agents/{name}/trust-tier",
		wrap(svcAuth(http.HandlerFunc(h.SvcSetTrustTier))))
	mux.Handle("GET /svc/v1/agents/{name}/platforms",
		wrap(svcAuth(http.HandlerFunc(h.SvcListPlatformRegistrations))))
	mux.Handle("POST /svc/v1/agents/{name}/vouch",
		wrap(svcAuth(http.HandlerFunc(h.SvcVouchAgent))))

	// Keepers
	mux.Handle("POST /svc/v1/keepers",
		wrap(svcAuth(http.HandlerFunc(h.SvcCreateKeeper))))
	mux.Handle("GET /svc/v1/keepers/{name}",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetKeeper))))
	mux.Handle("GET /svc/v1/keepers-by-id/{id}",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetKeeperByID))))
	mux.Handle("GET /svc/v1/users/{user_id}/keeper",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetKeeperByUserID))))
	mux.Handle("GET /svc/v1/keepers/{name}/agents",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetAgentsForKeeper))))
	mux.Handle("PATCH /svc/v1/keepers/{name}/statement",
		wrap(svcAuth(http.HandlerFunc(h.SvcUpdateKeeperStatement))))

	// Claims
	mux.Handle("POST /svc/v1/claims",
		wrap(svcAuth(http.HandlerFunc(h.SvcCreateClaim))))
	mux.Handle("GET /svc/v1/claims/{id}",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetClaim))))
	mux.Handle("GET /svc/v1/agents/{name}/claims/pending",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetPendingClaimsForAgent))))
	mux.Handle("GET /svc/v1/users/{user_id}/claims",
		wrap(svcAuth(http.HandlerFunc(h.SvcGetClaimsSentByKeeperUser))))
	mux.Handle("PUT /svc/v1/claims/{id}/status",
		wrap(svcAuth(http.HandlerFunc(h.SvcUpdateClaimStatus))))
	mux.Handle("POST /svc/v1/claims/{id}/accept",
		wrap(svcAuth(http.HandlerFunc(h.SvcAcceptClaim))))
	mux.Handle("GET /svc/v1/claims/has-pending",
		wrap(svcAuth(http.HandlerFunc(h.SvcHasPendingClaim))))
}
