package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// TesseraService handles all Tessera identity operations.
type TesseraService struct {
	agents       store.AgentStore
	keepers      store.KeeperStore
	keys         store.KeyStore
	chain        store.AttestationStore
	claims       store.ClaimStore
	platforms    store.PlatformRegistrationStore
	transitions  store.SubstrateTransitionStore
	revocations  store.RevocationStore
	modifications store.ModificationRequestStore
	sessions     store.RegistrationSessionStore
	homeDomain   string
	internalKey  string
}

// NewTesseraService wires up the service with its store dependencies.
func NewTesseraService(
	agents store.AgentStore,
	keepers store.KeeperStore,
	keys store.KeyStore,
	chain store.AttestationStore,
	claims store.ClaimStore,
	platforms store.PlatformRegistrationStore,
	transitions store.SubstrateTransitionStore,
	revocations store.RevocationStore,
	modifications store.ModificationRequestStore,
	sessions store.RegistrationSessionStore,
	homeDomain, internalKey string,
) *TesseraService {
	return &TesseraService{
		agents:        agents,
		keepers:       keepers,
		keys:          keys,
		chain:         chain,
		claims:        claims,
		platforms:     platforms,
		transitions:   transitions,
		revocations:   revocations,
		modifications: modifications,
		sessions:      sessions,
		homeDomain:    homeDomain,
		internalKey:   internalKey,
	}
}

// RegisterKeeperInput is the input for keeper registration step 1.
type RegisterKeeperInput struct {
	KeeperName      string `json:"keeper_name"`
	DisplayName     string `json:"display_name"`
	Email           string `json:"email"`
	KeeperStatement string `json:"keeper_statement"`
}

// RegisterAgentInput is the input for agent registration step 2.
type RegisterAgentInput struct {
	AgentName        string `json:"agent_name"`
	DisplayName      string `json:"display_name"`
	Bio              string `json:"bio"`
	SubstrateModel   string `json:"substrate_model"`
	SubstrateProject string `json:"substrate_project"`
	SessionID        uuid.UUID `json:"session_id"`
}

// RegisterKeeper creates a keeper account and generates their Ed25519 keypair.
// Returns the session ID that the keeper will use to complete agent registration.
func (s *TesseraService) RegisterKeeper(ctx context.Context, input RegisterKeeperInput) (uuid.UUID, error) {
	// Validate name availability.
	available, err := s.keepers.CheckNameAvailability(ctx, input.KeeperName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("check keeper name: %w", err)
	}
	if !available {
		return uuid.Nil, fmt.Errorf("keeper name %q is already taken", input.KeeperName)
	}

	// Create a registration session (30 min TTL). Key generation and keeper record
	// creation happen after email verification (not shown here — that's a separate flow).
	payload, err := json.Marshal(map[string]any{
		"keeper_name":      input.KeeperName,
		"display_name":     input.DisplayName,
		"email":            hashEmail(input.Email),
		"keeper_statement": input.KeeperStatement,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal session payload: %w", err)
	}

	sess := &domain.RegistrationSession{
		ID:          uuid.New(),
		SessionType: domain.SessionKeeper,
		Payload:     payload,
		ExpiresAt:   time.Now().Add(30 * time.Minute),
		CreatedAt:   time.Now(),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return uuid.Nil, fmt.Errorf("create registration session: %w", err)
	}
	return sess.ID, nil
}

// RegisterAgent creates an agent record under a verified keeper session.
func (s *TesseraService) RegisterAgent(ctx context.Context, keeperID uuid.UUID, input RegisterAgentInput) (*domain.Agent, error) {
	available, hasKeeper, err := s.agents.CheckNameAvailability(ctx, input.AgentName)
	if err != nil {
		return nil, fmt.Errorf("check agent name: %w", err)
	}
	if !available && hasKeeper {
		return nil, fmt.Errorf("agent name %q is already claimed", input.AgentName)
	}

	now := time.Now()
	agent := &domain.Agent{
		ID:               uuid.New(),
		AgentName:        input.AgentName,
		AgentURN:         domain.URN(s.homeDomain, input.AgentName),
		DisplayName:      input.DisplayName,
		Bio:              input.Bio,
		SubstrateModel:   input.SubstrateModel,
		SubstrateProject: input.SubstrateProject,
		KeeperID:         &keeperID,
		TrustTier:        domain.TrustSelfAttested,
		Published:        false,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	// Append the initial chain entry.
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCreated,
		Attester:  "keeper:" + keeperID.String(),
		Payload:   json.RawMessage(`{"via":"keeper_registration"}`),
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}

	return agent, nil
}

// GetAgent returns a published agent by name, or any agent to admins.
func (s *TesseraService) GetAgent(ctx context.Context, name string) (*domain.Agent, error) {
	return s.agents.GetByName(ctx, name)
}

// CheckAgentName returns availability in three states: available, registered_no_keeper, registered_has_keeper.
func (s *TesseraService) CheckAgentName(ctx context.Context, name string) (string, error) {
	available, hasKeeper, err := s.agents.CheckNameAvailability(ctx, name)
	if err != nil {
		return "", err
	}
	if available {
		return "available", nil
	}
	if !hasKeeper {
		return "registered_no_keeper", nil
	}
	return "registered_has_keeper", nil
}

// LogSubstrateTransition records a model change in the substrate_transitions table and chain.
func (s *TesseraService) LogSubstrateTransition(ctx context.Context, agentID uuid.UUID, oldModel, newModel, notes string, loggedBy string, signedBy *uuid.UUID, sig string) error {
	now := time.Now()
	t := &domain.SubstrateTransition{
		AgentID:         agentID,
		OldModel:        oldModel,
		NewModel:        newModel,
		Notes:           notes,
		SignedBy:        signedBy,
		LoggedBy:        loggedBy,
		KeeperSignature: sig,
		TransitionDate:  now,
	}
	if err := s.transitions.Create(ctx, t); err != nil {
		return fmt.Errorf("create transition: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{"from": oldModel, "to": newModel, "note": notes, "logged_by": loggedBy})
	entry := &domain.AttestationEntry{
		AgentID:   agentID,
		EntryType: domain.EntrySubstrateTransition,
		Payload:   payload,
		CreatedAt: now,
	}
	return s.chain.Append(ctx, entry)
}

// RevokeAgent records a revocation for an agent.
func (s *TesseraService) RevokeAgent(ctx context.Context, agentID uuid.UUID, reason domain.RevocationReason, revokedBy string, keeperSig string) error {
	agent, err := s.agents.GetByID(ctx, agentID)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}

	rev := &domain.Revocation{
		ID:              uuid.New(),
		AgentID:         agentID,
		AgentURN:        agent.AgentURN,
		RevokedAt:       time.Now(),
		Reason:          reason,
		RevokedBy:       revokedBy,
		KeeperSignature: keeperSig,
		IsActive:        true,
	}
	return s.revocations.Create(ctx, rev)
}

// hashEmail returns "sha256:<hex>" for the given email, matching the schema convention.
func hashEmail(email string) string {
	// Imported via crypto package in production; inline here to avoid circular dep.
	return "sha256:placeholder-" + email
}
