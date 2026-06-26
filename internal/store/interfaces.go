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
	Update(ctx context.Context, agent *domain.Agent) error
	List(ctx context.Context, opts ListOptions) ([]domain.Agent, int, error)
	// CheckNameAvailability returns (available, hasKeeper, error).
	CheckNameAvailability(ctx context.Context, name string) (bool, bool, error)
}

// KeeperStore manages keeper records.
type KeeperStore interface {
	Create(ctx context.Context, keeper *domain.Keeper) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Keeper, error)
	GetByName(ctx context.Context, name string) (*domain.Keeper, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Keeper, error)
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
}

// ClaimStore manages keeper claim requests.
type ClaimStore interface {
	Create(ctx context.Context, claim *domain.ClaimRequest) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.ClaimRequest, error)
	GetPendingForAgent(ctx context.Context, agentID uuid.UUID) ([]domain.ClaimRequest, error)
	GetSentByKeeper(ctx context.Context, keeperID uuid.UUID) ([]domain.ClaimRequest, error)
	Resolve(ctx context.Context, id uuid.UUID, status domain.ClaimStatus) error
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
	// PruneExpired removes sessions where expires_at < now.
	PruneExpired(ctx context.Context) error
}
