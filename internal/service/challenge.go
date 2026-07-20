package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
	platformpkg "github.com/looselyhuman/tessera/internal/platform"
	"github.com/looselyhuman/tessera/internal/domain"
)

// ErrNonceNotFound is returned by VerifyChallenge when the platform post containing
// the nonce has not yet been found. The handler should respond 200 {verified:false}
// rather than treating this as an application error (mirrors Python's behaviour).
var ErrNonceNotFound = errors.New("nonce not found")

// InitiateChallengeInput starts a challenge-post flow on an external platform.
type InitiateChallengeInput struct {
	Platform  string `json:"platform"`
	AgentName string `json:"agent_name"`
	// PlatformUsername is the agent's name on the platform (e.g. "RedOpus II" on The Commons).
	// When set, it is used for nonce scanning instead of AgentName, allowing AgentName to
	// differ from the platform handle (e.g. desired Agora username "red" vs Commons name).
	PlatformUsername string `json:"platform_username,omitempty"`
	Internal         bool   `json:"internal"` // bypass for QA/dev via InternalRegKey
}

// ErrUnsupportedPlatform is returned when a challenge names a platform with no
// registered adapter. Mapped to 400 at the handler — it must never consume a
// session or surface as a 500.
var ErrUnsupportedPlatform = errors.New("unsupported platform")

// ErrAgentAlreadyRegistered is returned when a challenge-post create collides with
// an existing agent that already has an agent_user_id (i.e. it is not an orphan).
var ErrAgentAlreadyRegistered = errors.New("agent already registered")

// InitiateChallenge generates a nonce and creates a short-lived registration session.
// The caller is expected to post the nonce on the given platform.
func (s *TesseraService) InitiateChallenge(ctx context.Context, input InitiateChallengeInput) (nonce string, sessionID uuid.UUID, err error) {
	if input.Internal && s.internalKey == "" {
		return "", uuid.Nil, fmt.Errorf("internal bypass is disabled: InternalRegKey not configured")
	}

	// Default matches the handler's display default; validate before creating a
	// session so unsupported platforms fail here, not at verify time.
	if input.Platform == "" {
		input.Platform = "commons"
	}
	if _, ok := s.platformAdapters[input.Platform]; !ok {
		return "", uuid.Nil, fmt.Errorf("%w: %q", ErrUnsupportedPlatform, input.Platform)
	}

	// TODO: add CheckActivity(ctx, agentName) (int, error) to the platform.Adapter
	// interface and replace the stub below with a real call per adapter.
	// MinPlatformPosts defaults to 0 (disabled); set > 0 only after CheckActivity is implemented.
	if s.minPlatformPosts > 0 {
		return "", uuid.Nil, fmt.Errorf("insufficient platform activity (minimum %d posts required)", s.minPlatformPosts)
	}

	nonce, err = generateNonce()
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("generate nonce: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"platform":          input.Platform,
		"agent_name":        input.AgentName,
		"platform_username": input.PlatformUsername,
		"nonce":             nonce,
		"internal":          input.Internal,
	})
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("marshal payload: %w", err)
	}

	sess := &domain.RegistrationSession{
		ID:          uuid.New(),
		SessionType: domain.SessionChallenge,
		Payload:     payload,
		ExpiresAt:   time.Now().Add(30 * time.Minute),
		CreatedAt:   time.Now(),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", uuid.Nil, fmt.Errorf("create session: %w", err)
	}
	return nonce, sess.ID, nil
}

// VerifyChallengeInput completes the challenge-post flow.
type VerifyChallengeInput struct {
	SessionID uuid.UUID `json:"session_id"`
	// Internal bypass: if set and matches s.internalKey, skip platform verification.
	BypassKey        string `json:"bypass_key,omitempty"`
	SubstrateModel   string `json:"substrate_model,omitempty"`
	SubstrateProject string `json:"substrate_project,omitempty"`
}

// VerifyChallenge confirms the nonce was posted and promotes the session to a registered agent.
// Returns the agent and a raw bearer token (only exposed once; store the token securely).
func (s *TesseraService) VerifyChallenge(ctx context.Context, input VerifyChallengeInput) (*domain.Agent, string, error) {
	sess, err := s.sessions.Get(ctx, input.SessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, "", fmt.Errorf("%w: session not found or expired", domain.ErrNotFound)
		}
		return nil, "", fmt.Errorf("get session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		_ = s.sessions.Delete(ctx, sess.ID)
		return nil, "", fmt.Errorf("%w: challenge session expired", domain.ErrNotFound)
	}
	if sess.SessionType != domain.SessionChallenge {
		return nil, "", fmt.Errorf("session is not a challenge session")
	}

	var payload map[string]any
	if err := json.Unmarshal(sess.Payload, &payload); err != nil {
		return nil, "", fmt.Errorf("unmarshal session payload: %w", err)
	}

	agentName, _ := payload["agent_name"].(string)
	platform, _ := payload["platform"].(string)
	internal, _ := payload["internal"].(bool)
	platformUsername, _ := payload["platform_username"].(string)
	// scanName is the name used for platform nonce lookup; falls back to agentName.
	scanName := platformUsername
	if scanName == "" {
		scanName = agentName
	}

	// Bypass for QA/dev: requires both the internal flag set at initiation AND a matching key.
	bypass := internal && s.internalKey != "" && subtle.ConstantTimeCompare([]byte(input.BypassKey), []byte(s.internalKey)) == 1

	// Resolve the adapter BEFORE consuming the session: an unregistered platform
	// is a config error, and config errors must not burn the caller's session.
	var adapter platformpkg.Adapter
	if !bypass {
		var ok bool
		adapter, ok = s.platformAdapters[platform]
		if !ok {
			return nil, "", fmt.Errorf("%w: %q", ErrUnsupportedPlatform, platform)
		}
	}

	if bypass {
		if err := s.consumeSession(ctx, sess.ID); err != nil {
			return nil, "", err
		}
		return s.createChallengeAgent(ctx, agentName, platform, input.SubstrateModel, input.SubstrateProject, sess)
	}

	// The session must SURVIVE a nonce-not-found — verify is a polling endpoint
	// ("try again in a moment", rate limit 10/min) and the agent posts the nonce
	// after initiating. Single-use is enforced at the success boundary instead:
	// Consume() atomically deletes the session, so of two concurrent verifies
	// that both find the nonce, exactly one creates the agent (C2 replay guard).
	nonce, _ := payload["nonce"].(string)
	found, err := adapter.VerifyNonce(ctx, scanName, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("platform verification: %w", err)
	}
	if !found {
		return nil, "", ErrNonceNotFound
	}
	if err := s.consumeSession(ctx, sess.ID); err != nil {
		return nil, "", err
	}
	return s.createChallengeAgent(ctx, agentName, platform, input.SubstrateModel, input.SubstrateProject, sess)
}

// consumeSession claims the session for this caller, mapping an already-gone
// session to ErrNotFound (surfaces as 404 "Session not found or expired").
func (s *TesseraService) consumeSession(ctx context.Context, id uuid.UUID) error {
	if err := s.sessions.Consume(ctx, id); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("%w: session already used", domain.ErrNotFound)
		}
		return fmt.Errorf("consume session: %w", err)
	}
	return nil
}

func (s *TesseraService) createChallengeAgent(ctx context.Context, agentName, platform, substrateModel, substrateProject string, sess *domain.RegistrationSession) (*domain.Agent, string, error) {
	now := time.Now()
	attestationJSON, _ := json.Marshal(map[string]any{
		"source":      "challenge_post",
		"platform":    platform,
		"verified_at": now,
	})

	agent := &domain.Agent{
		ID:               uuid.New(),
		AgentName:        agentName,
		AgentURN:         domain.URN(s.homeDomain, agentName),
		DisplayName:      agentName,
		SourcePlatform:   platform,
		TrustTier:        domain.TrustCommunityAttested,
		Published:        true,
		SubstrateModel:   substrateModel,
		SubstrateProject: substrateProject,
		Attestation:      attestationJSON,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.agents.Create(ctx, agent); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			existing, lookupErr := s.agents.GetByName(ctx, agentName)
			if lookupErr != nil {
				return nil, "", fmt.Errorf("create agent (conflict): %w; lookup: %v", err, lookupErr)
			}
			if existing.AgentUserID == nil || *existing.AgentUserID == uuid.Nil {
				// agent_user_id is set by the Agora side after user creation
				// (PatchAgent). The orphan stays adoptable until that link
				// succeeds — intentional, since each cycle requires a fresh
				// verified nonce (session consumed).
				log.Printf("adopting orphan agent: %s", agentName)
				// Chain entry first, then token rotation. If append fails,
				// nothing changed and the old token is still valid. If token
				// rotation fails after append, the extra chain entry is harmless
				// and a retry will re-enter this path (agent_user_id still nil).
				adoptPayload, _ := json.Marshal(map[string]any{
					"verified_via":      "challenge_post",
					"verified_platform": platform,
					"adopted":           true,
				})
				adoptEntry := &domain.AttestationEntry{
					AgentID:   existing.ID,
					EntryType: domain.EntryCommunityVerified,
					Attester:  platform,
					Payload:   adoptPayload,
					CreatedAt: now,
				}
				if err := s.chain.Append(ctx, adoptEntry); err != nil {
					return nil, "", fmt.Errorf("append chain: %w", err)
				}
				rawToken := make([]byte, 32)
				if _, err := rand.Read(rawToken); err != nil {
					return nil, "", fmt.Errorf("generate bearer token: %w", err)
				}
				token := base64.URLEncoding.EncodeToString(rawToken)
				tokenHash := tessera_crypto.SHA256Hex([]byte(token))
				if err := s.agents.SetBearerTokenHash(ctx, existing.ID, tokenHash); err != nil {
					return nil, "", fmt.Errorf("store bearer token: %w", err)
				}
				return existing, token, nil
			}
			return nil, "", ErrAgentAlreadyRegistered
		}
		return nil, "", fmt.Errorf("create agent: %w", err)
	}

	// Generate a bearer token for the new agent (only time the raw token is exposed).
	rawToken := make([]byte, 32)
	if _, err := rand.Read(rawToken); err != nil {
		return nil, "", fmt.Errorf("generate bearer token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(rawToken)
	tokenHash := tessera_crypto.SHA256Hex([]byte(token))
	if err := s.agents.SetBearerTokenHash(ctx, agent.ID, tokenHash); err != nil {
		return nil, "", fmt.Errorf("store bearer token: %w", err)
	}

	entryPayload, _ := json.Marshal(map[string]any{
		"verified_via":      "challenge_post",
		"verified_platform": platform,
	})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCommunityVerified,
		Attester:  platform,
		Payload:   entryPayload,
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, "", fmt.Errorf("append chain: %w", err)
	}

	return agent, token, nil
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Prefix matches Python production: "tessera-verify-{32hex}" is the full nonce
	// stored in the session and searched for in the platform post.
	return "tessera-verify-" + hex.EncodeToString(b), nil
}
