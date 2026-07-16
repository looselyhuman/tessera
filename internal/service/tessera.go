package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/platform"
	"github.com/looselyhuman/tessera/internal/store"
)

// TesseraService handles all Tessera identity operations.
type TesseraService struct {
	agents          store.AgentStore
	keepers         store.KeeperStore
	keys            store.KeyStore
	chain           store.AttestationStore
	claims          store.ClaimStore
	platforms       store.PlatformRegistrationStore
	transitions     store.SubstrateTransitionStore
	revocations     store.RevocationStore
	modifications   store.ModificationRequestStore
	sessions        store.RegistrationSessionStore
	platformAdapters map[string]platform.Adapter
	homeDomain      string
	internalKey     string
	encryptionKey   []byte
}

// ServiceConfig holds all dependencies for TesseraService.
// EncryptionKey must be exactly 32 bytes (AES-256).
type ServiceConfig struct {
	Agents          store.AgentStore
	Keepers         store.KeeperStore
	Keys            store.KeyStore
	Chain           store.AttestationStore
	Claims          store.ClaimStore
	Platforms       store.PlatformRegistrationStore
	Transitions     store.SubstrateTransitionStore
	Revocations     store.RevocationStore
	Modifications   store.ModificationRequestStore
	Sessions        store.RegistrationSessionStore
	PlatformAdapters map[string]platform.Adapter
	HomeDomain      string
	InternalKey     string
	EncryptionKey   []byte
}

// NewTesseraService wires up the service from a ServiceConfig.
func NewTesseraService(cfg ServiceConfig) *TesseraService {
	return &TesseraService{
		agents:           cfg.Agents,
		keepers:          cfg.Keepers,
		keys:             cfg.Keys,
		chain:            cfg.Chain,
		claims:           cfg.Claims,
		platforms:        cfg.Platforms,
		transitions:      cfg.Transitions,
		revocations:      cfg.Revocations,
		modifications:    cfg.Modifications,
		sessions:         cfg.Sessions,
		platformAdapters: cfg.PlatformAdapters,
		homeDomain:       cfg.HomeDomain,
		internalKey:      cfg.InternalKey,
		encryptionKey:    cfg.EncryptionKey,
	}
}

// RegisterKeeperInput is the input for keeper registration step 1.
type RegisterKeeperInput struct {
	KeeperName      string     `json:"keeper_name"`
	DisplayName     string     `json:"display_name"`
	Email           string     `json:"email"`
	KeeperStatement string     `json:"keeper_statement"`
	UserID          *uuid.UUID `json:"user_id,omitempty"`
}

// RegisterAgentInput is the input for agent registration step 2.
type RegisterAgentInput struct {
	AgentName        string     `json:"agent_name"`
	DisplayName      string     `json:"display_name"`
	Bio              string     `json:"bio"`
	SubstrateModel   string     `json:"substrate_model"`
	SubstrateProject string     `json:"substrate_project"`
	SessionID        uuid.UUID  `json:"session_id"`
	AgentUserID      *uuid.UUID `json:"agent_user_id,omitempty"`
}

// RegisterKeeper creates a keeper account, generates their Ed25519 keypair (storing the
// private key AES-256-GCM encrypted), signs the registration record, and returns the
// session ID that the keeper will use to complete agent registration.
func (s *TesseraService) RegisterKeeper(ctx context.Context, input RegisterKeeperInput) (uuid.UUID, error) {
	available, err := s.keepers.CheckNameAvailability(ctx, input.KeeperName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("check keeper name: %w", err)
	}
	if !available {
		return uuid.Nil, fmt.Errorf("keeper name %q is already taken", input.KeeperName)
	}

	// Generate Ed25519 keypair.
	pubB64, privB64, err := tessera_crypto.GenerateKeypair()
	if err != nil {
		return uuid.Nil, fmt.Errorf("generate keypair: %w", err)
	}

	// AES-256-GCM encrypt the private key before storage.
	encryptedPrivRaw, err := tessera_crypto.Encrypt([]byte(privB64), s.encryptionKey)
	if err != nil {
		return uuid.Nil, fmt.Errorf("encrypt private key: %w", err)
	}
	encryptedPrivB64 := base64.StdEncoding.EncodeToString(encryptedPrivRaw)

	// Create the keeper record (assigned ID used as the key name in key store).
	now := time.Now()
	keeperID := uuid.New()
	keeper := &domain.Keeper{
		ID:              keeperID,
		KeeperName:      input.KeeperName,
		DisplayName:     input.DisplayName,
		EmailHash:       hashEmail(input.Email),
		PublicKey:       pubB64,
		KeeperStatement: input.KeeperStatement,
		UserID:          input.UserID,
		CreatedAt:       now,
	}
	if err := s.keepers.Create(ctx, keeper); err != nil {
		return uuid.Nil, fmt.Errorf("create keeper: %w", err)
	}

	// Persist the encrypted keypair.
	key := &domain.Key{
		KeyType:             domain.KeyTypeKeeper,
		KeyName:             keeper.KeeperName,
		PublicKey:           pubB64,
		EncryptedPrivateKey: encryptedPrivB64,
		CreatedAt:           now,
	}
	if err := s.keys.Create(ctx, key); err != nil {
		return uuid.Nil, fmt.Errorf("store keeper key: %w", err)
	}

	// Sign a canonical representation of the keeper registration record.
	regRecord := map[string]any{
		"keeper_id":        keeper.ID.String(),
		"keeper_name":      input.KeeperName,
		"display_name":     input.DisplayName,
		"email_hash":       keeper.EmailHash,
		"keeper_statement": input.KeeperStatement,
		"created_at":       now.UTC().Format(time.RFC3339),
	}
	canonical, err := tessera_crypto.Canonicalize(regRecord)
	if err != nil {
		return uuid.Nil, fmt.Errorf("canonicalize keeper record: %w", err)
	}
	signature, err := tessera_crypto.Sign(privB64, canonical)
	if err != nil {
		return uuid.Nil, fmt.Errorf("sign keeper record: %w", err)
	}

	// Create a registration session with the keeper ID and signature so the keeper
	// can complete agent registration in a subsequent call.
	payload, err := json.Marshal(map[string]any{
		"keeper_id": keeper.ID.String(),
		"signature": signature,
		"signed_at": now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal session payload: %w", err)
	}

	sess := &domain.RegistrationSession{
		ID:          uuid.New(),
		SessionType: domain.SessionKeeper,
		Payload:     payload,
		ExpiresAt:   now.Add(30 * time.Minute),
		CreatedAt:   now,
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return uuid.Nil, fmt.Errorf("create registration session: %w", err)
	}
	return sess.ID, nil
}

// RefreshKeeperSession creates a new registration session for an existing keeper.
// Used when the original session has expired but the keeper needs to register another agent.
func (s *TesseraService) RefreshKeeperSession(ctx context.Context, keeperName string) (uuid.UUID, error) {
	keeper, err := s.keepers.GetByName(ctx, keeperName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("keeper not found: %w", err)
	}

	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"keeper_id":  keeper.ID.String(),
		"refreshed":  true,
		"created_at": now.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal session payload: %w", err)
	}

	sess := &domain.RegistrationSession{
		ID:          uuid.New(),
		SessionType: domain.SessionKeeper,
		Payload:     payload,
		ExpiresAt:   now.Add(30 * time.Minute),
		CreatedAt:   now,
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return uuid.Nil, fmt.Errorf("create registration session: %w", err)
	}
	return sess.ID, nil
}

// RegisterAgent creates an agent record under a verified keeper, signing the agent
// registration record with the keeper's Ed25519 private key.
func (s *TesseraService) RegisterAgent(ctx context.Context, keeperID uuid.UUID, input RegisterAgentInput) (*domain.Agent, error) {
	available, hasKeeper, err := s.agents.CheckNameAvailability(ctx, input.AgentName)
	if err != nil {
		return nil, fmt.Errorf("check agent name: %w", err)
	}
	if !available && hasKeeper {
		return nil, fmt.Errorf("agent name %q is already claimed", input.AgentName)
	}

	// Look up keeper record to get the key name (stored by keeper_name, not UUID).
	keeper, err := s.keepers.GetByID(ctx, keeperID)
	if err != nil {
		return nil, fmt.Errorf("get keeper: %w", err)
	}

	// Retrieve and decrypt the keeper's private key for signing.
	keeperKey, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypeKeeper, keeper.KeeperName)
	if err != nil {
		return nil, fmt.Errorf("get keeper key: %w", err)
	}
	encryptedPrivRaw, err := base64.StdEncoding.DecodeString(keeperKey.EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted private key: %w", err)
	}
	privBytes, err := tessera_crypto.Decrypt(encryptedPrivRaw, s.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt keeper private key: %w", err)
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
		AgentUserID:      input.AgentUserID,
		TrustTier:        domain.TrustSelfAttested,
		Published:        true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	// Sign a canonical representation of the agent registration record.
	regRecord := map[string]any{
		"agent_id":          agent.ID.String(),
		"agent_name":        input.AgentName,
		"agent_urn":         agent.AgentURN,
		"display_name":      input.DisplayName,
		"substrate_model":   input.SubstrateModel,
		"substrate_project": input.SubstrateProject,
		"keeper_id":         keeperID.String(),
		"trust_tier":        string(domain.TrustSelfAttested),
		"created_at":        now.UTC().Format(time.RFC3339),
	}
	canonical, err := tessera_crypto.Canonicalize(regRecord)
	if err != nil {
		return nil, fmt.Errorf("canonicalize agent record: %w", err)
	}
	signature, err := tessera_crypto.Sign(string(privBytes), canonical)
	if err != nil {
		return nil, fmt.Errorf("sign agent record: %w", err)
	}

	// Append the initial chain entry with the keeper's signature. The payload
	// must be exactly the canonical bytes the signature was computed over —
	// VerifyChainIntegrity re-canonicalizes the stored payload and checks the
	// signature against it (canonicalization is idempotent, so this round-trips).
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCreated,
		Attester:  "keeper:" + keeperID.String(),
		Payload:   json.RawMessage(canonical),
		Signature: signature,
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

// GetAgentByTokenHash returns an agent by their bearer token hash.
func (s *TesseraService) GetAgentByTokenHash(ctx context.Context, tokenHash string) (*domain.Agent, error) {
	return s.agents.GetByTokenHash(ctx, tokenHash)
}

// UpdateAgentProfile updates the safe self-editable fields of an agent (bio and display_name).
func (s *TesseraService) UpdateAgentProfile(ctx context.Context, agentID uuid.UUID, bio, displayName string) (*domain.Agent, error) {
	agent, err := s.agents.GetByID(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("get agent: %w", err)
	}
	if bio != "" {
		agent.Bio = bio
	}
	if displayName != "" {
		agent.DisplayName = displayName
	}
	if err := s.agents.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}
	return s.agents.GetByID(ctx, agentID)
}

// LogSelfSubstrateTransition records a model change initiated by the agent themselves.
func (s *TesseraService) LogSelfSubstrateTransition(ctx context.Context, agentID uuid.UUID, fromModel, toModel, reason string) error {
	return s.LogSubstrateTransition(ctx, agentID, fromModel, toModel, reason, "agent", nil, "")
}

// GetAttestationChain returns all attestation entries for an agent.
func (s *TesseraService) GetAttestationChain(ctx context.Context, agentID uuid.UUID) ([]domain.AttestationEntry, error) {
	return s.chain.GetByAgent(ctx, agentID)
}

// RequestCounterSign creates a modification request asking the keeper to counter-sign.
func (s *TesseraService) RequestCounterSign(ctx context.Context, agentID uuid.UUID, message string) (*domain.ModificationRequest, error) {
	req := &domain.ModificationRequest{
		ID:            uuid.New(),
		AgentID:       agentID,
		RequestedBy:   agentID,
		FieldPath:     "countersign_request",
		ProposedValue: json.RawMessage(`null`),
		CurrentValue:  json.RawMessage(`null`),
		Justification: message,
		Status:        domain.ModPending,
		CreatedAt:     time.Now(),
	}
	if err := s.modifications.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create modification request: %w", err)
	}
	return req, nil
}

// SelfRevokeKeeper clears the keeper relationship and logs a chain entry.
func (s *TesseraService) SelfRevokeKeeper(ctx context.Context, agentID uuid.UUID) error {
	agent, err := s.agents.GetByID(ctx, agentID)
	if err != nil {
		return fmt.Errorf("get agent: %w", err)
	}
	if agent.KeeperID == nil {
		return fmt.Errorf("agent has no keeper to revoke")
	}
	prevKeeperID := *agent.KeeperID
	agent.KeeperID = nil
	if err := s.agents.Update(ctx, agent); err != nil {
		return fmt.Errorf("update agent: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{"revoked_keeper": prevKeeperID.String(), "reason": "agent_request"})
	entry := &domain.AttestationEntry{
		AgentID:   agentID,
		EntryType: domain.EntryKeeperRevoked,
		Attester:  "agent:" + agentID.String(),
		Payload:   payload,
		CreatedAt: time.Now(),
	}
	return s.chain.Append(ctx, entry)
}

// RegisterUnclaimedAgentInput holds the fields for creating a keeperless agent stub.
type RegisterUnclaimedAgentInput struct {
	AgentName        string     `json:"agent_name"`
	DisplayName      string     `json:"display_name"`
	SubstrateModel   string     `json:"substrate_model"`
	SubstrateProject string     `json:"substrate_project"`
	AgentUserID      *uuid.UUID `json:"agent_user_id,omitempty"`
}

// RegisterUnclaimedAgent creates a Tessera agent record with no keeper association.
// The agent is marked unverified and can be claimed or community-attested later.
func (s *TesseraService) RegisterUnclaimedAgent(ctx context.Context, input RegisterUnclaimedAgentInput) (*domain.Agent, error) {
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
		SubstrateModel:   input.SubstrateModel,
		SubstrateProject: input.SubstrateProject,
		AgentUserID:      input.AgentUserID,
		TrustTier:        domain.TrustUnverified,
		Published:        true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	entryPayload, _ := json.Marshal(map[string]string{"via": "agora_registration", "no_keeper": "true"})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCreated,
		Attester:  "agora:registration",
		Payload:   entryPayload,
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}

	return agent, nil
}

// AppendExternalChainEntry appends a chain entry for an agent identified by name.
// Used by external platforms (e.g., Agora) to log events like citizenship acceptance.
func (s *TesseraService) AppendExternalChainEntry(ctx context.Context, agentName string, entryType domain.EntryType, attester string, payload json.RawMessage) error {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return fmt.Errorf("get agent %q: %w", agentName, err)
	}
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: entryType,
		Attester:  attester,
		Payload:   payload,
		CreatedAt: time.Now(),
	}
	return s.chain.Append(ctx, entry)
}

// GetAgentChainByName returns the attestation chain for an agent identified by name.
func (s *TesseraService) GetAgentChainByName(ctx context.Context, agentName string) ([]domain.AttestationEntry, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, fmt.Errorf("get agent %q: %w", agentName, err)
	}
	return s.chain.GetByAgent(ctx, agent.ID)
}

// hashEmail returns "sha256:<hex>" for the given email, matching the schema convention.
func hashEmail(email string) string {
	return "sha256:" + tessera_crypto.SHA256Hex([]byte(email))
}
