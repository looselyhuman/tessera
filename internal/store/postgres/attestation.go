package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

type attestationStore struct{ pool *pgxpool.Pool }

func NewAttestationStore(pool *pgxpool.Pool) store.AttestationStore {
	return &attestationStore{pool: pool}
}

func (s *attestationStore) Append(ctx context.Context, e *domain.AttestationEntry) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.attestation_chain
			(agent_id, entry_type, attester, payload, signature, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		e.AgentID, e.EntryType, e.Attester, e.Payload, e.Signature, e.ExpiresAt, e.CreatedAt,
	).Scan(&e.ID)
}

func (s *attestationStore) GetByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.AttestationEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, entry_type, attester, payload, signature, expires_at, created_at
		FROM tessera.attestation_chain
		WHERE agent_id = $1
		ORDER BY id ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []domain.AttestationEntry
	for rows.Next() {
		var e domain.AttestationEntry
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.EntryType, &e.Attester,
			&e.Payload, &e.Signature, &e.ExpiresAt, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
