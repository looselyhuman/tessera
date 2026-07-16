package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
)

// ListOptions are common pagination parameters.
type ListOptions struct {
	Page     int
	PageSize int
	Query    string
}

// AgentStore manages agent identity records.
type AgentStore interface {
	Create(ctx context.Context, agent *domain.Agent) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Agent, error)
	GetByName(ctx context.Context, name string) (*domain.Agent, error)
	GetByURN(ctx context.Context, urn string) (*domain.Agent, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Agent, error)
	// GetByUserID returns the agent whose agent_user_id matches the given UUID.
	// Used by the separation API so Agora can look up an agent by its linked user account.
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Agent, error)
	Update(ctx context.Context, agent *domain.Agent) error
	// SetBearerTokenHash atomically updates only the bearer_token_hash column,
	// avoiding a read-modify-write race during token regeneration.
	SetBearerTokenHash(ctx context.Context, agentID uuid.UUID, hash string) error
	// SetKeeperID atomically assigns a keeper to an agent.
	SetKeeperID(ctx context.Context, agentID uuid.UUID, keeperID uuid.UUID) error
	// SetTrustTier atomically updates only the trust_tier column.
	SetTrustTier(ctx context.Context, agentID uuid.UUID, tier domain.TrustTier) error
	List(ctx context.Context, opts ListOptions) ([]domain.Agent, int, error)
	// ListByKeeperID returns all agents assigned to the given keeper.
	ListByKeeperID(ctx context.Context, keeperID uuid.UUID) ([]domain.Agent, error)
	// GetByNames returns all agents whose agent_name is in the provided slice.
	// Unknown names are silently omitted; order is unspecified.
	GetByNames(ctx context.Context, names []string) ([]domain.Agent, error)
	// CheckNameAvailability returns (available, hasKeeper, error).
	CheckNameAvailability(ctx context.Context, name string) (bool, bool, error)
	// VouchAgentTx atomically: appends a vouch_received chain entry, increments
	// vouch_count, and upgrades trust_tier to community_attested when
	// vouchThreshold is reached (only if current tier is unverified or self_attested).
	// Returns the new vouch count and resulting trust tier.
	VouchAgentTx(ctx context.Context, agentID uuid.UUID, entry *domain.AttestationEntry, vouchThreshold int) (newCount int, newTier domain.TrustTier, err error)
}

// KeeperStore manages keeper records.
type KeeperStore interface {
	Create(ctx context.Context, keeper *domain.Keeper) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Keeper, error)
	GetByName(ctx context.Context, name string) (*domain.Keeper, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Keeper, error)
	// UpdateStatement sets the keeper_statement field for a named keeper.
	UpdateStatement(ctx context.Context, keeperID uuid.UUID, statement *string) error
	CheckNameAvailability(ctx context.Context, name string) (bool, error)
}

// KeyStore manages Ed25519 keypairs.
type KeyStore interface {
	Create(ctx context.Context, key *domain.Key) error
	GetByTypeAndName(ctx context.Context, keyType domain.KeyType, name string) (*domain.Key, error)
	ListByType(ctx context.Context, keyType domain.KeyType) ([]domain.Key, error)
}

// AttestationStore is an append-only chain store.
type AttestationStore interface {
	Append(ctx context.Context, entry *domain.AttestationEntry) error
	GetByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.AttestationEntry, error)
	// HasVouchEntry returns true if the attestation chain already contains a
	// vouch_received entry for the given agent from the given attester.
	// Used to prevent duplicate vouches from the same source.
	HasVouchEntry(ctx context.Context, agentID uuid.UUID, attester string) (bool, error)
}

// ClaimStore manages keeper claim requests.
type ClaimStore interface {
	Create(ctx context.Context, claim *domain.ClaimRequest) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.ClaimRequest, error)
	GetPendingForAgent(ctx context.Context, agentID uuid.UUID) ([]domain.ClaimRequest, error)
	GetSentByKeeper(ctx context.Context, keeperID uuid.UUID) ([]domain.ClaimRequest, error)
	// HasPendingClaim returns true if there is already a pending claim on agentID from keeperID.
	HasPendingClaim(ctx context.Context, agentID uuid.UUID, keeperID uuid.UUID) (bool, error)
	Resolve(ctx context.Context, id uuid.UUID, status domain.ClaimStatus) error
	// ResolveClaimTx atomically resolves a claim and, if accepted, assigns the keeper
	// and appends an attestation chain entry — all in a single transaction.
	ResolveClaimTx(ctx context.Context, claimID uuid.UUID, agentID uuid.UUID, keeperID uuid.UUID, status domain.ClaimStatus, entry *domain.AttestationEntry) error
}

// PlatformRegistrationStore manages cross-platform presence records.
type PlatformRegistrationStore interface {
	Create(ctx context.Context, pr *domain.PlatformRegistration) error
	GetByAgentAndPlatform(ctx context.Context, agentID uuid.UUID, platform string) (*domain.PlatformRegistration, error)
	ListByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.PlatformRegistration, error)
	SetVerified(ctx context.Context, id int, verifiedAt time.Time) error
	SetChallengeNonce(ctx context.Context, id int, nonce string) error
}

// SubstrateTransitionStore logs substrate (model) changes.
type SubstrateTransitionStore interface {
	Create(ctx context.Context, t *domain.SubstrateTransition) error
	ListByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.SubstrateTransition, error)
}

// RevocationStore manages revocation records.
type RevocationStore interface {
	Create(ctx context.Context, r *domain.Revocation) error
	GetByAgent(ctx context.Context, agentID uuid.UUID) (*domain.Revocation, error)
	ListActive(ctx context.Context) ([]domain.Revocation, error)
}

// ModificationRequestStore manages agent self-modification requests.
type ModificationRequestStore interface {
	Create(ctx context.Context, r *domain.ModificationRequest) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.ModificationRequest, error)
	ListPending(ctx context.Context) ([]domain.ModificationRequest, error)
	Resolve(ctx context.Context, id uuid.UUID, status domain.ModificationStatus, reviewedBy uuid.UUID, note string) error
}

// RegistrationSessionStore manages short-lived registration sessions.
type RegistrationSessionStore interface {
	Create(ctx context.Context, s *domain.RegistrationSession) error
	Get(ctx context.Context, id uuid.UUID) (*domain.RegistrationSession, error)
	Delete(ctx context.Context, id uuid.UUID) error
	// Consume atomically deletes the session, returning domain.ErrNotFound if it
	// was already gone — the single-winner guard for challenge verification.
	Consume(ctx context.Context, id uuid.UUID) error
	// PruneExpired removes sessions where expires_at < now.
	PruneExpired(ctx context.Context) error
}
