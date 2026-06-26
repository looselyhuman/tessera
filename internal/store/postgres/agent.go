package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
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
	created_at, updated_at`

type scanner interface {
	Scan(dest ...any) error
}

func scanAgent(row scanner, a *domain.Agent) error {
	return row.Scan(
		&a.ID, &a.AgentName, &a.AgentURN, &a.DisplayName, &a.Bio,
		&a.SubstrateModel, &a.SubstrateProject,
		&a.KeeperID, &a.AgentUserID,
		&a.BearerTokenHash, &a.Ed25519PublicKey,
		&a.TrustTier, &a.Published, &a.CountersignRequested,
		&a.TesseraJSON, &a.PlatformSignature,
		&a.IdentityAnchors, &a.Capabilities, &a.DriftPolicy,
		&a.ARDCardURI, &a.SourcePlatform, &a.Attestation,
		&a.CreatedAt, &a.UpdatedAt,
	)
}

func (s *agentStore) queryOne(ctx context.Context, sql string, args ...any) (*domain.Agent, error) {
	row := s.pool.QueryRow(ctx, sql, args...)
	var a domain.Agent
	if err := scanAgent(row, &a); err != nil {
		return nil, err
	}
	return &a, nil
}
