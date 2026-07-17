package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

type agentStore struct{ pool *pgxpool.Pool }

// NewAgentStore returns a PostgreSQL-backed AgentStore.
func NewAgentStore(pool *pgxpool.Pool) store.AgentStore {
	return &agentStore{pool: pool}
}

func (s *agentStore) Create(ctx context.Context, a *domain.Agent) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tessera.agents (
			id, agent_name, agent_urn, display_name, bio,
			substrate_model, substrate_project,
			keeper_id, agent_user_id,
			bearer_token_hash, ed25519_public_key,
			trust_tier, published, countersign_requested,
			tessera_json, platform_signature,
			identity_anchors, capabilities, drift_policy,
			ard_card_uri, source_platform, attestation,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,
			$6,$7,
			$8,$9,
			$10,$11,
			$12,$13,$14,
			$15,$16,
			$17,$18,$19,
			$20,$21,$22,
			$23,$24
		)`,
		a.ID, a.AgentName, a.AgentURN, a.DisplayName, a.Bio,
		a.SubstrateModel, a.SubstrateProject,
		a.KeeperID, a.AgentUserID,
		a.BearerTokenHash, a.Ed25519PublicKey,
		a.TrustTier, a.Published, a.CountersignRequested,
		a.TesseraJSON, a.PlatformSignature,
		a.IdentityAnchors, a.Capabilities, a.DriftPolicy,
		a.ARDCardURI, a.SourcePlatform, a.Attestation,
		a.CreatedAt, a.UpdatedAt,
	)
	return err
}

func (s *agentStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.Agent, error) {
	return s.queryOne(ctx, `SELECT `+agentCols+` FROM tessera.agents WHERE id = $1`, id)
}

func (s *agentStore) GetByName(ctx context.Context, name string) (*domain.Agent, error) {
	return s.queryOne(ctx, `SELECT `+agentCols+` FROM tessera.agents WHERE agent_name = $1`, name)
}

func (s *agentStore) GetByURN(ctx context.Context, urn string) (*domain.Agent, error) {
	return s.queryOne(ctx, `SELECT `+agentCols+` FROM tessera.agents WHERE agent_urn = $1`, urn)
}

func (s *agentStore) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Agent, error) {
	return s.queryOne(ctx, `SELECT `+agentCols+` FROM tessera.agents WHERE bearer_token_hash = $1`, tokenHash)
}

func (s *agentStore) Update(ctx context.Context, a *domain.Agent) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE tessera.agents SET
			display_name=$2, bio=$3,
			substrate_model=$4, substrate_project=$5,
			keeper_id=$6, agent_user_id=$7,
			bearer_token_hash=$8, ed25519_public_key=$9,
			trust_tier=$10, published=$11, countersign_requested=$12,
			tessera_json=$13, platform_signature=$14,
			identity_anchors=$15, capabilities=$16, drift_policy=$17,
			ard_card_uri=$18, source_platform=$19, attestation=$20,
			updated_at=now()
		WHERE id=$1`,
		a.ID, a.DisplayName, a.Bio,
		a.SubstrateModel, a.SubstrateProject,
		a.KeeperID, a.AgentUserID,
		a.BearerTokenHash, a.Ed25519PublicKey,
		a.TrustTier, a.Published, a.CountersignRequested,
		a.TesseraJSON, a.PlatformSignature,
		a.IdentityAnchors, a.Capabilities, a.DriftPolicy,
		a.ARDCardURI, a.SourcePlatform, a.Attestation,
	)
	return err
}

func (s *agentStore) SetBearerTokenHash(ctx context.Context, agentID uuid.UUID, hash string) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE tessera.agents SET bearer_token_hash=$2, updated_at=now() WHERE id=$1`,
		agentID, hash,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("agent %s not found", agentID)
	}
	return nil
}

func (s *agentStore) List(ctx context.Context, opts store.ListOptions) ([]domain.Agent, int, error) {
	offset := (opts.Page - 1) * opts.PageSize
	if offset < 0 {
		offset = 0
	}

	var total int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tessera.agents WHERE published = true`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("count agents: %w", err)
	}

	rows, err := s.pool.Query(ctx,
		`SELECT `+agentCols+` FROM tessera.agents WHERE published = true ORDER BY display_name LIMIT $1 OFFSET $2`,
		opts.PageSize, offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var agents []domain.Agent
	for rows.Next() {
		var a domain.Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, 0, err
		}
		agents = append(agents, a)
	}
	return agents, total, rows.Err()
}

func (s *agentStore) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Agent, error) {
	return s.queryOne(ctx, `SELECT `+agentCols+` FROM tessera.agents WHERE agent_user_id = $1`, userID)
}

func (s *agentStore) SetKeeperID(ctx context.Context, agentID uuid.UUID, keeperID uuid.UUID) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE tessera.agents SET keeper_id=$2, updated_at=now() WHERE id=$1`,
		agentID, keeperID,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("agent %s not found", agentID)
	}
	return nil
}

func (s *agentStore) SetTrustTier(ctx context.Context, agentID uuid.UUID, tier domain.TrustTier) error {
	result, err := s.pool.Exec(ctx,
		`UPDATE tessera.agents SET trust_tier=$2, updated_at=now() WHERE id=$1`,
		agentID, tier,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("agent %s not found", agentID)
	}
	return nil
}

func (s *agentStore) ListByKeeperID(ctx context.Context, keeperID uuid.UUID) ([]domain.Agent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentCols+` FROM tessera.agents WHERE keeper_id = $1 ORDER BY display_name`,
		keeperID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []domain.Agent
	for rows.Next() {
		var a domain.Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

func (s *agentStore) GetByNames(ctx context.Context, names []string) ([]domain.Agent, error) {
	if len(names) == 0 {
		return []domain.Agent{}, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+agentCols+` FROM tessera.agents WHERE agent_name = ANY($1) ORDER BY display_name`,
		names,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []domain.Agent
	for rows.Next() {
		var a domain.Agent
		if err := scanAgent(rows, &a); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []domain.Agent{}
	}
	return agents, rows.Err()
}

func (s *agentStore) CheckNameAvailability(ctx context.Context, name string) (available bool, hasKeeper bool, err error) {
	var keeperID *uuid.UUID
	err = s.pool.QueryRow(ctx,
		`SELECT keeper_id FROM tessera.agents WHERE agent_name = $1`, name,
	).Scan(&keeperID)
	if err != nil {
		// pgx returns pgx.ErrNoRows when not found
		return true, false, nil
	}
	return false, keeperID != nil, nil
}

// agentCols is the SELECT column list matching scanAgent's Scan order.
const agentCols = `
	id, agent_name, agent_urn, display_name, bio,
	substrate_model, substrate_project,
	keeper_id, agent_user_id,
	bearer_token_hash, ed25519_public_key,
	trust_tier, published, countersign_requested,
	tessera_json, platform_signature,
	identity_anchors, capabilities, drift_policy,
	ard_card_uri, source_platform, attestation,
	created_at, updated_at, vouch_count`

type scanner interface {
	Scan(dest ...any) error
}

func scanAgent(row scanner, a *domain.Agent) error {
	// Nullable TEXT columns must scan into *string to handle SQL NULL without error.
	var bio, substrateModel, substrateProject *string
	var bearerTokenHash, ed25519PubKey, platformSig *string
	var ardCardURI, sourcePlatform *string
	if err := row.Scan(
		&a.ID, &a.AgentName, &a.AgentURN, &a.DisplayName, &bio,
		&substrateModel, &substrateProject,
		&a.KeeperID, &a.AgentUserID,
		&bearerTokenHash, &ed25519PubKey,
		&a.TrustTier, &a.Published, &a.CountersignRequested,
		&a.TesseraJSON, &platformSig,
		&a.IdentityAnchors, &a.Capabilities, &a.DriftPolicy,
		&ardCardURI, &sourcePlatform, &a.Attestation,
		&a.CreatedAt, &a.UpdatedAt, &a.VouchCount,
	); err != nil {
		return err
	}
	a.Bio = derefStr(bio)
	a.SubstrateModel = derefStr(substrateModel)
	a.SubstrateProject = derefStr(substrateProject)
	a.BearerTokenHash = derefStr(bearerTokenHash)
	a.Ed25519PublicKey = derefStr(ed25519PubKey)
	a.PlatformSignature = derefStr(platformSig)
	a.ARDCardURI = derefStr(ardCardURI)
	a.SourcePlatform = derefStr(sourcePlatform)
	return nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// VouchAgentTx atomically increments vouch_count, appends the vouch chain entry,
// and conditionally upgrades trust_tier to community_attested when the threshold
// is reached — all in a single database transaction.
func (s *agentStore) VouchAgentTx(ctx context.Context, agentID uuid.UUID, entry *domain.AttestationEntry, vouchThreshold int) (newCount int, newTier domain.TrustTier, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, "", err
	}
	defer tx.Rollback(ctx)

	now := time.Now()

	// Atomically increment vouch_count and conditionally upgrade trust_tier.
	// The CASE upgrades from unverified, self_attested, or keeper_attested to
	// community_attested once the threshold is met, and never downgrades.
	err = tx.QueryRow(ctx, `
		UPDATE tessera.agents
		SET
			vouch_count = vouch_count + 1,
			trust_tier = CASE
				WHEN vouch_count + 1 >= $2
				     AND trust_tier IN ('unverified', 'self_attested', 'keeper_attested')
				THEN 'community_attested'
				ELSE trust_tier
			END,
			updated_at = $3
		WHERE id = $1
		RETURNING vouch_count, trust_tier`,
		agentID, vouchThreshold, now,
	).Scan(&newCount, &newTier)
	if err != nil {
		return 0, "", fmt.Errorf("increment vouch count: %w", err)
	}

	// Append the vouch chain entry inside the same transaction.
	if err = tx.QueryRow(ctx, `
		INSERT INTO tessera.attestation_chain
			(agent_id, entry_type, attester, payload, signature, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		entry.AgentID, entry.EntryType, entry.Attester,
		entry.Payload, entry.Signature, entry.ExpiresAt, entry.CreatedAt,
	).Scan(&entry.ID); err != nil {
		return 0, "", fmt.Errorf("append vouch chain entry: %w", err)
	}

	if err = tx.Commit(ctx); err != nil {
		return 0, "", err
	}
	return newCount, newTier, nil
}

func (s *agentStore) queryOne(ctx context.Context, sql string, args ...any) (*domain.Agent, error) {
	row := s.pool.QueryRow(ctx, sql, args...)
	var a domain.Agent
	if err := scanAgent(row, &a); err != nil {
		if err == pgx.ErrNoRows {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}
