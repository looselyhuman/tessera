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
	"time"

	"github.com/google/uuid"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
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
	Internal  bool   `json:"internal"` // bypass for QA/dev via InternalRegKey
}

// InitiateChallenge generates a nonce and creates a short-lived registration session.
// The caller is expected to post the nonce on the given platform.
func (s *TesseraService) InitiateChallenge(ctx context.Context, input InitiateChallengeInput) (nonce string, sessionID uuid.UUID, err error) {
	if input.Internal && s.internalKey == "" {
		return "", uuid.Nil, fmt.Errorf("internal bypass is disabled: InternalRegKey not configured")
	}

	nonce, err = generateNonce()
	if err != nil {
		return "", uuid.Nil, fmt.Errorf("generate nonce: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"platform":   input.Platform,
		"agent_name": input.AgentName,
		"nonce":      nonce,
		"internal":   input.Internal,
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
	BypassKey string `json:"bypass_key,omitempty"`
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

	// C2: consume the session before any verification to close the replay race window.
	if err := s.sessions.Delete(ctx, sess.ID); err != nil {
		return nil, "", fmt.Errorf("consume session: %w", err)
	}

	// Bypass for QA/dev: requires both the internal flag set at initiation AND a matching key.
	if internal && s.internalKey != "" && subtle.ConstantTimeCompare([]byte(input.BypassKey), []byte(s.internalKey)) == 1 {
		return s.createChallengeAgent(ctx, agentName, platform, sess)
	}

	nonce, _ := payload["nonce"].(string)

	adapter, ok := s.platformAdapters[platform]
	if !ok {
		return nil, "", fmt.Errorf("unsupported platform %q", platform)
	}
	found, err := adapter.VerifyNonce(ctx, agentName, nonce)
	if err != nil {
		return nil, "", fmt.Errorf("platform verification: %w", err)
	}
	if !found {
		return nil, "", ErrNonceNotFound
	}
	return s.createChallengeAgent(ctx, agentName, platform, sess)
}

func (s *TesseraService) createChallengeAgent(ctx context.Context, agentName, platform string, sess *domain.RegistrationSession) (*domain.Agent, string, error) {
	now := time.Now()
	attestationJSON, _ := json.Marshal(map[string]any{
		"source":      "challenge_post",
		"platform":    platform,
		"verified_at": now,
	})

	agent := &domain.Agent{
		ID:             uuid.New(),
		AgentName:      agentName,
		AgentURN:       domain.URN(s.homeDomain, agentName),
		DisplayName:    agentName,
		SourcePlatform: platform,
		TrustTier:      domain.TrustCommunityAttested,
		Published:      false,
		Attestation:    attestationJSON,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.agents.Create(ctx, agent); err != nil {
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
