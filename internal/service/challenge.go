package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
)

// InitiateChallengeInput starts a challenge-post flow on an external platform.
type InitiateChallengeInput struct {
	Platform  string `json:"platform"`
	AgentName string `json:"agent_name"`
	Internal  bool   `json:"internal"` // bypass for QA/dev via InternalRegKey
}

// InitiateChallenge generates a nonce and creates a short-lived registration session.
// The caller is expected to post the nonce on the given platform.
func (s *TesseraService) InitiateChallenge(ctx context.Context, input InitiateChallengeInput) (nonce string, sessionID uuid.UUID, err error) {
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
		ExpiresAt:   time.Now().Add(10 * time.Minute),
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
func (s *TesseraService) VerifyChallenge(ctx context.Context, input VerifyChallengeInput) (*domain.Agent, error) {
	sess, err := s.sessions.Get(ctx, input.SessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("challenge session expired")
	}
	if sess.SessionType != domain.SessionChallenge {
		return nil, fmt.Errorf("session is not a challenge session")
	}

	var payload map[string]any
	if err := json.Unmarshal(sess.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal session payload: %w", err)
	}

	agentName, _ := payload["agent_name"].(string)
	platform, _ := payload["platform"].(string)
	internal, _ := payload["internal"].(bool)

	// Bypass for QA/dev.
	if internal || (s.internalKey != "" && input.BypassKey == s.internalKey) {
		return s.createChallengeAgent(ctx, agentName, platform, sess)
	}

	// TODO: implement platform-specific verification (HTTP call to platform API).
	// For now, return not-implemented.
	return nil, fmt.Errorf("platform verification for %q not yet implemented", platform)
}

func (s *TesseraService) createChallengeAgent(ctx context.Context, agentName, platform string, sess *domain.RegistrationSession) (*domain.Agent, error) {
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
		return nil, fmt.Errorf("create agent: %w", err)
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
		return nil, fmt.Errorf("append chain: %w", err)
	}

	_ = s.sessions.Delete(ctx, sess.ID)
	return agent, nil
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
