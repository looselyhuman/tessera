package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// --- PlatformRegistrationStore ---

type platformRegStore struct{ pool *pgxpool.Pool }

func NewPlatformRegistrationStore(pool *pgxpool.Pool) store.PlatformRegistrationStore {
	return &platformRegStore{pool: pool}
}

func (s *platformRegStore) Create(ctx context.Context, pr *domain.PlatformRegistration) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.platform_registrations
			(agent_id, platform, platform_username, role, registered_at, verified, challenge_nonce, verified_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id`,
		pr.AgentID, pr.Platform, pr.PlatformUsername, pr.Role, pr.RegisteredAt,
		pr.Verified, pr.ChallengeNonce, pr.VerifiedAt,
	).Scan(&pr.ID)
}

func (s *platformRegStore) GetByAgentAndPlatform(ctx context.Context, agentID uuid.UUID, platform string) (*domain.PlatformRegistration, error) {
	var pr domain.PlatformRegistration
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, platform, platform_username, role, registered_at, verified, challenge_nonce, verified_at
		FROM tessera.platform_registrations WHERE agent_id=$1 AND platform=$2`,
		agentID, platform,
	).Scan(&pr.ID, &pr.AgentID, &pr.Platform, &pr.PlatformUsername, &pr.Role,
		&pr.RegisteredAt, &pr.Verified, &pr.ChallengeNonce, &pr.VerifiedAt)
	if err != nil {
		return nil, err
	}
	return &pr, nil
}

func (s *platformRegStore) ListByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.PlatformRegistration, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, platform, platform_username, role, registered_at, verified, challenge_nonce, verified_at
		FROM tessera.platform_registrations WHERE agent_id=$1`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.PlatformRegistration
	for rows.Next() {
		var pr domain.PlatformRegistration
		if err := rows.Scan(&pr.ID, &pr.AgentID, &pr.Platform, &pr.PlatformUsername, &pr.Role,
			&pr.RegisteredAt, &pr.Verified, &pr.ChallengeNonce, &pr.VerifiedAt); err != nil {
			return nil, err
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func (s *platformRegStore) SetVerified(ctx context.Context, id int, verifiedAt time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE tessera.platform_registrations SET verified=true, verified_at=$2 WHERE id=$1`, id, verifiedAt)
	return err
}

func (s *platformRegStore) SetChallengeNonce(ctx context.Context, id int, nonce string) error {
	_, err := s.pool.Exec(ctx, `UPDATE tessera.platform_registrations SET challenge_nonce=$2 WHERE id=$1`, id, nonce)
	return err
}

// --- SubstrateTransitionStore ---

type substrateStore struct{ pool *pgxpool.Pool }

func NewSubstrateTransitionStore(pool *pgxpool.Pool) store.SubstrateTransitionStore {
	return &substrateStore{pool: pool}
}

func (s *substrateStore) Create(ctx context.Context, t *domain.SubstrateTransition) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.substrate_transitions
			(agent_id, old_model, new_model, notes, signed_by, logged_by, keeper_signature, transition_date)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id`,
		t.AgentID, t.OldModel, t.NewModel, t.Notes, t.SignedBy, t.LoggedBy, t.KeeperSignature, t.TransitionDate,
	).Scan(&t.ID)
}

func (s *substrateStore) ListByAgent(ctx context.Context, agentID uuid.UUID) ([]domain.SubstrateTransition, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, old_model, new_model, notes, signed_by, logged_by, keeper_signature, transition_date
		FROM tessera.substrate_transitions WHERE agent_id=$1 ORDER BY transition_date`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SubstrateTransition
	for rows.Next() {
		var t domain.SubstrateTransition
		if err := rows.Scan(&t.ID, &t.AgentID, &t.OldModel, &t.NewModel, &t.Notes,
			&t.SignedBy, &t.LoggedBy, &t.KeeperSignature, &t.TransitionDate); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// --- RevocationStore ---

type revocationStore struct{ pool *pgxpool.Pool }

func NewRevocationStore(pool *pgxpool.Pool) store.RevocationStore {
	return &revocationStore{pool: pool}
}

func (s *revocationStore) Create(ctx context.Context, r *domain.Revocation) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tessera.revocations
			(id, agent_id, agent_urn, revoked_at, reason, revoked_by, successor_tessera, keeper_signature, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		r.ID, r.AgentID, r.AgentURN, r.RevokedAt, r.Reason, r.RevokedBy,
		r.SuccessorTessera, r.KeeperSignature, r.IsActive,
	)
	return err
}

func (s *revocationStore) GetByAgent(ctx context.Context, agentID uuid.UUID) (*domain.Revocation, error) {
	var r domain.Revocation
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, agent_urn, revoked_at, reason, revoked_by, successor_tessera, keeper_signature, is_active
		FROM tessera.revocations WHERE agent_id=$1 AND is_active=true LIMIT 1`, agentID,
	).Scan(&r.ID, &r.AgentID, &r.AgentURN, &r.RevokedAt, &r.Reason, &r.RevokedBy,
		&r.SuccessorTessera, &r.KeeperSignature, &r.IsActive)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *revocationStore) ListActive(ctx context.Context) ([]domain.Revocation, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, agent_urn, revoked_at, reason, revoked_by, successor_tessera, keeper_signature, is_active
		FROM tessera.revocations WHERE is_active=true ORDER BY revoked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Revocation
	for rows.Next() {
		var r domain.Revocation
		if err := rows.Scan(&r.ID, &r.AgentID, &r.AgentURN, &r.RevokedAt, &r.Reason, &r.RevokedBy,
			&r.SuccessorTessera, &r.KeeperSignature, &r.IsActive); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- ModificationRequestStore ---

type modificationStore struct{ pool *pgxpool.Pool }

func NewModificationRequestStore(pool *pgxpool.Pool) store.ModificationRequestStore {
	return &modificationStore{pool: pool}
}

func (s *modificationStore) Create(ctx context.Context, r *domain.ModificationRequest) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.modification_requests
			(agent_id, requested_by, field_path, proposed_value, current_value, justification, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id`,
		r.AgentID, r.RequestedBy, r.FieldPath, r.ProposedValue, r.CurrentValue,
		r.Justification, r.Status, r.CreatedAt,
	).Scan(&r.ID)
}

func (s *modificationStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.ModificationRequest, error) {
	var r domain.ModificationRequest
	err := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, requested_by, field_path, proposed_value, current_value,
		       justification, status, reviewed_by, review_note, created_at, resolved_at
		FROM tessera.modification_requests WHERE id=$1`, id,
	).Scan(&r.ID, &r.AgentID, &r.RequestedBy, &r.FieldPath, &r.ProposedValue, &r.CurrentValue,
		&r.Justification, &r.Status, &r.ReviewedBy, &r.ReviewNote, &r.CreatedAt, &r.ResolvedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *modificationStore) ListPending(ctx context.Context) ([]domain.ModificationRequest, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, agent_id, requested_by, field_path, proposed_value, current_value,
		       justification, status, reviewed_by, review_note, created_at, resolved_at
		FROM tessera.modification_requests WHERE status='pending' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ModificationRequest
	for rows.Next() {
		var r domain.ModificationRequest
		if err := rows.Scan(&r.ID, &r.AgentID, &r.RequestedBy, &r.FieldPath, &r.ProposedValue, &r.CurrentValue,
			&r.Justification, &r.Status, &r.ReviewedBy, &r.ReviewNote, &r.CreatedAt, &r.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *modificationStore) Resolve(ctx context.Context, id uuid.UUID, status domain.ModificationStatus, reviewedBy uuid.UUID, note string) error {
	now := time.Now()
	_, err := s.pool.Exec(ctx, `
		UPDATE tessera.modification_requests
		SET status=$2, reviewed_by=$3, review_note=$4, resolved_at=$5
		WHERE id=$1`,
		id, status, reviewedBy, note, now,
	)
	return err
}

// --- RegistrationSessionStore ---

type regSessionStore struct{ pool *pgxpool.Pool }

func NewRegistrationSessionStore(pool *pgxpool.Pool) store.RegistrationSessionStore {
	return &regSessionStore{pool: pool}
}

func (s *regSessionStore) Create(ctx context.Context, sess *domain.RegistrationSession) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tessera.registration_sessions (id, session_type, payload, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5)`,
		sess.ID, sess.SessionType, sess.Payload, sess.ExpiresAt, sess.CreatedAt,
	)
	return err
}

func (s *regSessionStore) Get(ctx context.Context, id uuid.UUID) (*domain.RegistrationSession, error) {
	var sess domain.RegistrationSession
	err := s.pool.QueryRow(ctx, `
		SELECT id, session_type, payload, expires_at, created_at
		FROM tessera.registration_sessions WHERE id=$1`, id,
	).Scan(&sess.ID, &sess.SessionType, &sess.Payload, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *regSessionStore) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM tessera.registration_sessions WHERE id=$1`, id)
	return err
}

func (s *regSessionStore) PruneExpired(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM tessera.registration_sessions WHERE expires_at < NOW()`)
	return err
}
