package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

type claimStore struct{ pool *pgxpool.Pool }

func NewClaimStore(pool *pgxpool.Pool) store.ClaimStore {
	return &claimStore{pool: pool}
}

func (s *claimStore) Create(ctx context.Context, c *domain.ClaimRequest) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.claim_requests
			(keeper_id, agent_name, agent_id, keeper_statement, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id`,
		c.KeeperID, c.AgentName, c.AgentID, c.KeeperStatement, c.Status, c.CreatedAt,
	).Scan(&c.ID)
}

func (s *claimStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.ClaimRequest, error) {
	return s.query(ctx, `SELECT id, keeper_id, agent_name, agent_id, keeper_statement, status, created_at, resolved_at FROM tessera.claim_requests WHERE id=$1`, id)
}

func (s *claimStore) GetPendingForAgent(ctx context.Context, agentID uuid.UUID) ([]domain.ClaimRequest, error) {
	return s.queryMany(ctx, `SELECT id, keeper_id, agent_name, agent_id, keeper_statement, status, created_at, resolved_at FROM tessera.claim_requests WHERE agent_id=$1 AND status='pending'`, agentID)
}

func (s *claimStore) GetSentByKeeper(ctx context.Context, keeperID uuid.UUID) ([]domain.ClaimRequest, error) {
	return s.queryMany(ctx, `SELECT id, keeper_id, agent_name, agent_id, keeper_statement, status, created_at, resolved_at FROM tessera.claim_requests WHERE keeper_id=$1 ORDER BY created_at DESC`, keeperID)
}

func (s *claimStore) Resolve(ctx context.Context, id uuid.UUID, status domain.ClaimStatus) error {
	now := time.Now()
	_, err := s.pool.Exec(ctx,
		`UPDATE tessera.claim_requests SET status=$2, resolved_at=$3 WHERE id=$1`,
		id, status, now,
	)
	return err
}

func (s *claimStore) query(ctx context.Context, sql string, args ...any) (*domain.ClaimRequest, error) {
	var c domain.ClaimRequest
	err := s.pool.QueryRow(ctx, sql, args...).Scan(
		&c.ID, &c.KeeperID, &c.AgentName, &c.AgentID,
		&c.KeeperStatement, &c.Status, &c.CreatedAt, &c.ResolvedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *claimStore) queryMany(ctx context.Context, sql string, args ...any) ([]domain.ClaimRequest, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var claims []domain.ClaimRequest
	for rows.Next() {
		var c domain.ClaimRequest
		if err := rows.Scan(&c.ID, &c.KeeperID, &c.AgentName, &c.AgentID, &c.KeeperStatement, &c.Status, &c.CreatedAt, &c.ResolvedAt); err != nil {
			return nil, err
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}
