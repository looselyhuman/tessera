package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
	"github.com/looselyhuman/tessera/internal/domain"
)

// UpdateAgentInput holds admin-editable fields for an agent record.
// All fields are optional — only non-nil/non-empty values are applied.
type UpdateAgentInput struct {
	DisplayName      *string         `json:"display_name,omitempty"`
	Bio              *string         `json:"bio,omitempty"`
	SubstrateModel   *string         `json:"substrate_model,omitempty"`
	SubstrateProject *string         `json:"substrate_project,omitempty"`
	ARDCardURI       *string         `json:"ard_card_uri,omitempty"`
	IdentityAnchors  json.RawMessage `json:"identity_anchors,omitempty"`
	Capabilities     json.RawMessage `json:"capabilities,omitempty"`
	DriftPolicy      json.RawMessage `json:"drift_policy,omitempty"`
}

// UpdateAgent applies admin-provided field updates to an agent record.
func (s *TesseraService) UpdateAgent(ctx context.Context, agentName string, input UpdateAgentInput) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	if input.DisplayName != nil {
		agent.DisplayName = *input.DisplayName
	}
	if input.Bio != nil {
		agent.Bio = *input.Bio
	}
	if input.SubstrateModel != nil {
		agent.SubstrateModel = *input.SubstrateModel
	}
	if input.SubstrateProject != nil {
		agent.SubstrateProject = *input.SubstrateProject
	}
	if input.ARDCardURI != nil {
		agent.ARDCardURI = *input.ARDCardURI
	}
	if len(input.IdentityAnchors) > 0 {
		agent.IdentityAnchors = input.IdentityAnchors
	}
	if len(input.Capabilities) > 0 {
		agent.Capabilities = input.Capabilities
	}
	if len(input.DriftPolicy) > 0 {
		agent.DriftPolicy = input.DriftPolicy
	}
	agent.UpdatedAt = time.Now()
	if err := s.agents.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}
	return agent, nil
}

// CreateModificationRequest creates a self-modification request for an agent.
func (s *TesseraService) CreateModificationRequest(ctx context.Context, agentID uuid.UUID, fieldPath string, proposedValue json.RawMessage, justification string) (*domain.ModificationRequest, error) {
	now := time.Now()
	req := &domain.ModificationRequest{
		ID:            uuid.New(),
		AgentID:       agentID,
		RequestedBy:   agentID,
		FieldPath:     fieldPath,
		ProposedValue: proposedValue,
		CurrentValue:  json.RawMessage(`null`),
		Justification: justification,
		Status:        domain.ModPending,
		CreatedAt:     now,
	}
	if err := s.modifications.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create modification request: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"request_id": req.ID.String(),
		"field_path": fieldPath,
	})
	entry := &domain.AttestationEntry{
		AgentID:   agentID,
		EntryType: domain.EntryAgentSelfModified,
		Attester:  "agent:" + agentID.String(),
		Payload:   payload,
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}

	return req, nil
}

// CounterSign marks the agent as counter-signed and appends a chain entry.
// The incoming signature is verified against the agent's keeper public key before being accepted.
func (s *TesseraService) CounterSign(ctx context.Context, agentName, signature string) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}

	if signature == "" {
		return nil, fmt.Errorf("signature is required for counter-sign")
	}

	// sigData is what the counter-signature covers; the chain entry stores its
	// canonical form so VerifyChainIntegrity can re-check the signature later.
	sigData := map[string]any{
		"agent_id":   agent.ID.String(),
		"agent_name": agent.AgentName,
		"agent_urn":  agent.AgentURN,
	}
	if agent.KeeperID != nil {
		sigData["keeper_id"] = agent.KeeperID.String()
	}
	canonical, err := tessera_crypto.Canonicalize(sigData)
	if err != nil {
		return nil, fmt.Errorf("canonicalize counter-sign data: %w", err)
	}

	if agent.KeeperID != nil {
		keeper, err := s.keepers.GetByID(ctx, *agent.KeeperID)
		if err != nil {
			return nil, fmt.Errorf("get keeper for counter-sign verification: %w", err)
		}
		ok, err := tessera_crypto.Verify(keeper.PublicKey, canonical, signature)
		if err != nil {
			return nil, fmt.Errorf("verify counter-sign: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("counter-sign signature is invalid")
		}
	}

	agent.CountersignRequested = false
	agent.PlatformSignature = signature
	agent.UpdatedAt = time.Now()
	if err := s.agents.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}

	attester := "admin"
	if agent.KeeperID != nil {
		attester = fmt.Sprintf("keeper:%s", agent.KeeperID.String())
	}
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCounterSigned,
		Attester:  attester,
		Payload:   json.RawMessage(canonical),
		Signature: signature,
		CreatedAt: time.Now(),
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}

	return agent, nil
}

// PublishAgent marks an agent as publicly visible.
func (s *TesseraService) PublishAgent(ctx context.Context, agentName string) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	agent.Published = true
	agent.UpdatedAt = time.Now()
	if err := s.agents.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}
	return agent, nil
}

// AnchorCheck returns a summary of the agent's identity anchors.
func (s *TesseraService) AnchorCheck(ctx context.Context, agentName string) (map[string]any, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	var anchors []any
	if len(agent.IdentityAnchors) > 0 {
		_ = json.Unmarshal(agent.IdentityAnchors, &anchors)
	}
	return map[string]any{
		"agent_name": agentName,
		"anchors":    anchors,
		"count":      len(anchors),
	}, nil
}

// AdminRegenerateToken generates a new bearer token for the named agent and returns the raw token.
// This is the only time the raw token is ever exposed; only the SHA-256 hash is stored.
func (s *TesseraService) AdminRegenerateToken(ctx context.Context, agentName string) (string, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return "", err
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	token := base64.URLEncoding.EncodeToString(raw)
	hash := tessera_crypto.SHA256Hex([]byte(token))
	if err := s.agents.SetBearerTokenHash(ctx, agent.ID, hash); err != nil {
		return "", fmt.Errorf("store token hash: %w", err)
	}
	return token, nil
}

// VerifyExternal looks up an agent by URN for external callers.
func (s *TesseraService) VerifyExternal(ctx context.Context, urn string) (*domain.Agent, error) {
	return s.agents.GetByURN(ctx, urn)
}

// AdminGeneratePlatformKey generates an Ed25519 keypair for a named platform integration.
// The private key is stored AES-256-GCM encrypted; only the public key is returned.
// The canonical name is "platform" — the well-known reader and WellKnownAgent both
// look up the key under that name. Any other name is accepted but logged as a warning
// since it will not be found by the standard lookup path.
func (s *TesseraService) AdminGeneratePlatformKey(ctx context.Context, platformName string) (string, error) {
	if platformName != "platform" {
		slog.Warn("platform key generated with non-canonical name — well-known endpoints use 'platform'",
			"name", platformName)
	}
	pubB64, privB64, err := tessera_crypto.GenerateKeypair()
	if err != nil {
		return "", fmt.Errorf("generate platform keypair: %w", err)
	}

	encRaw, err := tessera_crypto.Encrypt([]byte(privB64), s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("encrypt platform private key: %w", err)
	}

	key := &domain.Key{
		KeyType:             domain.KeyTypePlatform,
		KeyName:             platformName,
		PublicKey:           pubB64,
		EncryptedPrivateKey: base64.StdEncoding.EncodeToString(encRaw),
		CreatedAt:           time.Now(),
	}
	if err := s.keys.Create(ctx, key); err != nil {
		return "", fmt.Errorf("store platform key: %w", err)
	}
	return pubB64, nil
}

// AdminRevokeKeeper removes the keeper relationship from an agent and logs a chain entry.
func (s *TesseraService) AdminRevokeKeeper(ctx context.Context, agentName string) error {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return err
	}
	if agent.KeeperID == nil {
		return fmt.Errorf("agent has no keeper")
	}
	prevKeeperID := *agent.KeeperID
	agent.KeeperID = nil
	agent.UpdatedAt = time.Now()
	if err := s.agents.Update(ctx, agent); err != nil {
		return fmt.Errorf("update agent: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"revoked_keeper": prevKeeperID.String(),
		"reason":         "admin_action",
	})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryKeeperRevoked,
		Attester:  "admin",
		Payload:   payload,
		CreatedAt: time.Now(),
	}
	return s.chain.Append(ctx, entry)
}
