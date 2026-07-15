package service

// svcapi.go — service methods for the separation API (/svc/v1/*).
//
// These methods cover every tessera.* table operation that Agora currently performs
// with raw SQL, enabling a clean migration away from direct cross-schema writes.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// ── Agent operations ────────────────────────────────────────────────────────

// SvcCreateAgentInput is the full set of fields Agora needs to create an agent
// record. The AgentUserID links the tessera agent to the corresponding agora user.
type SvcCreateAgentInput struct {
	AgentName        string     `json:"agent_name"`
	DisplayName      string     `json:"display_name"`
	Bio              string     `json:"bio,omitempty"`
	SubstrateModel   string     `json:"substrate_model,omitempty"`
	SubstrateProject string     `json:"substrate_project,omitempty"`
	KeeperID         *uuid.UUID `json:"keeper_id,omitempty"`
	AgentUserID      *uuid.UUID `json:"agent_user_id,omitempty"`
	TrustTier        domain.TrustTier `json:"trust_tier,omitempty"`
	Published        bool       `json:"published"`
	SourcePlatform   string     `json:"source_platform,omitempty"`
}

// SvcCreateAgent creates an agent record from Agora's orchestrator.
// Unlike RegisterAgent (which requires a keeper session and signs with the keeper's
// private key), this path is intended for Agora's own registration flow where Agora
// has already performed its auth checks and needs to materialise the tessera record.
func (s *TesseraService) SvcCreateAgent(ctx context.Context, input SvcCreateAgentInput) (*domain.Agent, error) {
	if input.TrustTier == "" {
		input.TrustTier = domain.TrustUnverified
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
		KeeperID:         input.KeeperID,
		AgentUserID:      input.AgentUserID,
		TrustTier:        input.TrustTier,
		Published:        input.Published,
		SourcePlatform:   input.SourcePlatform,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.agents.Create(ctx, agent); err != nil {
		return nil, fmt.Errorf("create agent: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"via":    "agora_svc_registration",
		"source": input.SourcePlatform,
	})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryCreated,
		Attester:  "agora:svc",
		Payload:   payload,
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}
	return agent, nil
}

// SvcListAgents returns a paginated list of agents.
func (s *TesseraService) SvcListAgents(ctx context.Context, opts store.ListOptions) ([]domain.Agent, int, error) {
	return s.agents.List(ctx, opts)
}

// SvcGetAgentByUserID returns the agent linked to the given agora user ID.
func (s *TesseraService) SvcGetAgentByUserID(ctx context.Context, userID uuid.UUID) (*domain.Agent, error) {
	return s.agents.GetByUserID(ctx, userID)
}

// SvcPatchAgentInput holds the optional fields that can be updated via the service API.
// Only non-nil fields are applied.
type SvcPatchAgentInput struct {
	Bio              *string `json:"bio,omitempty"`
	DisplayName      *string `json:"display_name,omitempty"`
	SubstrateModel   *string `json:"substrate_model,omitempty"`
	SubstrateProject *string `json:"substrate_project,omitempty"`
}

// SvcPatchAgent updates editable profile fields on a named agent.
func (s *TesseraService) SvcPatchAgent(ctx context.Context, agentName string, input SvcPatchAgentInput) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	if input.Bio != nil {
		agent.Bio = *input.Bio
	}
	if input.DisplayName != nil {
		agent.DisplayName = *input.DisplayName
	}
	if input.SubstrateModel != nil {
		agent.SubstrateModel = *input.SubstrateModel
	}
	if input.SubstrateProject != nil {
		agent.SubstrateProject = *input.SubstrateProject
	}
	agent.UpdatedAt = time.Now()
	if err := s.agents.Update(ctx, agent); err != nil {
		return nil, fmt.Errorf("update agent: %w", err)
	}
	return agent, nil
}

// SvcSetAgentKeeper assigns a keeper to a named agent.
func (s *TesseraService) SvcSetAgentKeeper(ctx context.Context, agentName string, keeperID uuid.UUID) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	if err := s.agents.SetKeeperID(ctx, agent.ID, keeperID); err != nil {
		return nil, fmt.Errorf("set keeper: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{"keeper_id": keeperID.String()})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryKeeperClaimed,
		Attester:  "agora:svc",
		Payload:   payload,
		CreatedAt: time.Now(),
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}
	return s.agents.GetByID(ctx, agent.ID)
}

// SvcSetTrustTier sets the trust tier on a named agent and appends an attestation entry.
func (s *TesseraService) SvcSetTrustTier(ctx context.Context, agentName string, tier domain.TrustTier, attester string) (*domain.Agent, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	if err := s.agents.SetTrustTier(ctx, agent.ID, tier); err != nil {
		return nil, fmt.Errorf("set trust tier: %w", err)
	}
	payload, _ := json.Marshal(map[string]string{
		"new_tier":  string(tier),
		"old_tier":  string(agent.TrustTier),
		"via":       "agora_svc",
	})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryRelational,
		Attester:  attester,
		Payload:   payload,
		CreatedAt: time.Now(),
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}
	return s.agents.GetByID(ctx, agent.ID)
}

// SvcListPlatformRegistrations returns all platform registrations for a named agent.
func (s *TesseraService) SvcListPlatformRegistrations(ctx context.Context, agentName string) ([]domain.PlatformRegistration, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	prs, err := s.platforms.ListByAgent(ctx, agent.ID)
	if err != nil {
		return nil, err
	}
	if prs == nil {
		prs = []domain.PlatformRegistration{}
	}
	return prs, nil
}

// ── Keeper operations ───────────────────────────────────────────────────────

// SvcCreateKeeperInput is the lightweight keeper creation input used by Agora's
// orchestrator. It does NOT generate an Ed25519 keypair — use RegisterKeeper for that.
// This path is for creating a keeper record in tessera.keepers when an agora user
// is being assigned the keeper role.
type SvcCreateKeeperInput struct {
	KeeperName      string     `json:"keeper_name"`
	DisplayName     *string    `json:"display_name,omitempty"`
	EmailHash       string     `json:"email_hash,omitempty"`
	KeeperStatement *string    `json:"keeper_statement,omitempty"`
	UserID          *uuid.UUID `json:"user_id,omitempty"`
}

// SvcCreateKeeper creates a minimal keeper record (no keypair generation).
// For full keeper registration with keypair, use RegisterKeeper via the admin API.
func (s *TesseraService) SvcCreateKeeper(ctx context.Context, input SvcCreateKeeperInput) (*domain.Keeper, error) {
	available, err := s.keepers.CheckNameAvailability(ctx, input.KeeperName)
	if err != nil {
		return nil, fmt.Errorf("check keeper name: %w", err)
	}
	if !available {
		return nil, fmt.Errorf("keeper name %q is already taken", input.KeeperName)
	}

	var stmt string
	if input.KeeperStatement != nil {
		stmt = *input.KeeperStatement
	}
	var dn string
	if input.DisplayName != nil {
		dn = *input.DisplayName
	} else {
		dn = input.KeeperName
	}

	keeper := &domain.Keeper{
		KeeperName:      input.KeeperName,
		DisplayName:     dn,
		EmailHash:       input.EmailHash,
		KeeperStatement: stmt,
		UserID:          input.UserID,
		CreatedAt:       time.Now(),
	}
	if err := s.keepers.Create(ctx, keeper); err != nil {
		return nil, fmt.Errorf("create keeper: %w", err)
	}
	return keeper, nil
}

// SvcGetKeeper returns a keeper by name.
func (s *TesseraService) SvcGetKeeper(ctx context.Context, keeperName string) (*domain.Keeper, error) {
	return s.keepers.GetByName(ctx, keeperName)
}

// SvcGetKeeperByID returns a keeper by its tessera UUID.
// Needed by Agora when it has a keeper_id from a claim record and must hydrate the keeper.
func (s *TesseraService) SvcGetKeeperByID(ctx context.Context, keeperID uuid.UUID) (*domain.Keeper, error) {
	return s.keepers.GetByID(ctx, keeperID)
}

// SvcGetKeeperByUserID returns the keeper whose user_id matches the given UUID.
func (s *TesseraService) SvcGetKeeperByUserID(ctx context.Context, userID uuid.UUID) (*domain.Keeper, error) {
	return s.keepers.GetByUserID(ctx, userID)
}

// SvcGetAgentsForKeeper returns all agents assigned to the named keeper.
func (s *TesseraService) SvcGetAgentsForKeeper(ctx context.Context, keeperName string) ([]domain.Agent, error) {
	keeper, err := s.keepers.GetByName(ctx, keeperName)
	if err != nil {
		return nil, err
	}
	agents, err := s.agents.ListByKeeperID(ctx, keeper.ID)
	if err != nil {
		return nil, err
	}
	if agents == nil {
		agents = []domain.Agent{}
	}
	return agents, nil
}

// SvcUpdateKeeperStatement updates the keeper_statement for the named keeper.
func (s *TesseraService) SvcUpdateKeeperStatement(ctx context.Context, keeperName string, statement *string) (*domain.Keeper, error) {
	keeper, err := s.keepers.GetByName(ctx, keeperName)
	if err != nil {
		return nil, err
	}
	if err := s.keepers.UpdateStatement(ctx, keeper.ID, statement); err != nil {
		return nil, fmt.Errorf("update statement: %w", err)
	}
	return s.keepers.GetByName(ctx, keeperName)
}

// ── Claim operations ────────────────────────────────────────────────────────

// SvcCreateClaimInput describes a keeper claim request. The keeper is identified
// by their keeper_user_id (agora.users.id); Tessera looks up the tessera.keepers
// record by user_id and uses that keeper's UUID as the canonical keeper_id.
type SvcCreateClaimInput struct {
	KeeperUserID    uuid.UUID  `json:"keeper_user_id"`
	AgentName       string     `json:"agent_name"`
	KeeperStatement string     `json:"keeper_statement,omitempty"`
}

// SvcCreateClaim creates a keeper claim via the service API.
// The keeper is resolved from keeper_user_id → tessera.keepers.id.
func (s *TesseraService) SvcCreateClaim(ctx context.Context, input SvcCreateClaimInput) (*domain.ClaimRequest, error) {
	// Resolve keeper by user_id.
	keeper, err := s.keepers.GetByUserID(ctx, input.KeeperUserID)
	if err != nil {
		return nil, fmt.Errorf("keeper not found for user %s: %w", input.KeeperUserID, err)
	}
	return s.InitiateClaim(ctx, keeper.ID, input.AgentName, input.KeeperStatement)
}

// SvcGetClaim returns a claim by ID.
func (s *TesseraService) SvcGetClaim(ctx context.Context, claimID uuid.UUID) (*domain.ClaimRequest, error) {
	return s.claims.GetByID(ctx, claimID)
}

// SvcGetPendingClaimsForAgent returns pending claims on a named agent.
func (s *TesseraService) SvcGetPendingClaimsForAgent(ctx context.Context, agentName string) ([]domain.ClaimRequest, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, err
	}
	claims, err := s.claims.GetPendingForAgent(ctx, agent.ID)
	if err != nil {
		return nil, err
	}
	if claims == nil {
		claims = []domain.ClaimRequest{}
	}
	return claims, nil
}

// SvcGetClaimsSentByKeeperUser returns all claims sent by the keeper identified
// by their agora user_id.
func (s *TesseraService) SvcGetClaimsSentByKeeperUser(ctx context.Context, keeperUserID uuid.UUID) ([]domain.ClaimRequest, error) {
	keeper, err := s.keepers.GetByUserID(ctx, keeperUserID)
	if err != nil {
		return nil, fmt.Errorf("keeper not found for user %s: %w", keeperUserID, err)
	}
	claims, err := s.claims.GetSentByKeeper(ctx, keeper.ID)
	if err != nil {
		return nil, err
	}
	if claims == nil {
		claims = []domain.ClaimRequest{}
	}
	return claims, nil
}

// SvcUpdateClaimStatus resolves a claim (accepts or rejects). Unlike ResolveClaim,
// this does not require the caller to be the agent — it is authorised at the
// service-token level and intended for Agora's orchestrator.
func (s *TesseraService) SvcUpdateClaimStatus(ctx context.Context, claimID uuid.UUID, status domain.ClaimStatus) (*domain.ClaimRequest, error) {
	claim, err := s.claims.GetByID(ctx, claimID)
	if err != nil {
		return nil, fmt.Errorf("claim not found: %w", err)
	}
	if claim.Status != domain.ClaimPending {
		return nil, fmt.Errorf("claim is already resolved")
	}

	now := time.Now()
	var entry *domain.AttestationEntry
	if status == domain.ClaimAccepted && claim.AgentID != nil {
		payload, _ := json.Marshal(map[string]string{
			"claim_id":  claimID.String(),
			"keeper_id": claim.KeeperID.String(),
			"via":       "agora_svc",
		})
		entry = &domain.AttestationEntry{
			AgentID:   *claim.AgentID,
			EntryType: domain.EntryKeeperClaimAccepted,
			Attester:  "agora:svc",
			Payload:   payload,
			CreatedAt: now,
		}
		if err := s.claims.ResolveClaimTx(ctx, claimID, *claim.AgentID, claim.KeeperID, status, entry); err != nil {
			return nil, fmt.Errorf("resolve claim: %w", err)
		}
	} else {
		if err := s.claims.Resolve(ctx, claimID, status); err != nil {
			return nil, fmt.Errorf("resolve claim: %w", err)
		}
	}

	claim.Status = status
	claim.ResolvedAt = &now
	return claim, nil
}

// SvcHasPendingClaim returns true if there is a pending claim on agentName from the keeper
// identified by keeper_user_id.
func (s *TesseraService) SvcHasPendingClaim(ctx context.Context, agentName string, keeperUserID uuid.UUID) (bool, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return false, err
	}
	keeper, err := s.keepers.GetByUserID(ctx, keeperUserID)
	if err != nil {
		return false, fmt.Errorf("keeper not found for user %s: %w", keeperUserID, err)
	}
	return s.claims.HasPendingClaim(ctx, agent.ID, keeper.ID)
}
