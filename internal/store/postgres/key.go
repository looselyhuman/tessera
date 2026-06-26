package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

type keyStore struct{ pool *pgxpool.Pool }

func NewKeyStore(pool *pgxpool.Pool) store.KeyStore {
	return &keyStore{pool: pool}
}

func (s *keyStore) Create(ctx context.Context, k *domain.Key) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.keys (key_type, key_name, public_key, encrypted_private_key, created_at)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id`,
		k.KeyType, k.KeyName, k.PublicKey, k.EncryptedPrivateKey, k.CreatedAt,
	).Scan(&k.ID)
}

func (s *keyStore) GetByTypeAndName(ctx context.Context, kt domain.KeyType, name string) (*domain.Key, error) {
	var k domain.Key
	err := s.pool.QueryRow(ctx, `
		SELECT id, key_type, key_name, public_key, encrypted_private_key, created_at
		FROM tessera.keys WHERE key_type=$1 AND key_name=$2`, kt, name,
	).Scan(&k.ID, &k.KeyType, &k.KeyName, &k.PublicKey, &k.EncryptedPrivateKey, &k.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *keyStore) ListByType(ctx context.Context, kt domain.KeyType) ([]domain.Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, key_type, key_name, public_key, encrypted_private_key, created_at
		FROM tessera.keys WHERE key_type=$1 ORDER BY created_at`, kt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []domain.Key
	for rows.Next() {
		var k domain.Key
		if err := rows.Scan(&k.ID, &k.KeyType, &k.KeyName, &k.PublicKey, &k.EncryptedPrivateKey, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

type keeperStore struct{ pool *pgxpool.Pool }

func NewKeeperStore(pool *pgxpool.Pool) store.KeeperStore {
	return &keeperStore{pool: pool}
}

func (s *keeperStore) Create(ctx context.Context, k *domain.Keeper) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO tessera.keepers
			(keeper_name, display_name, email_hash, public_key, keeper_statement, user_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		k.KeeperName, k.DisplayName, k.EmailHash, k.PublicKey, k.KeeperStatement, k.UserID, k.CreatedAt,
	).Scan(&k.ID)
}

func (s *keeperStore) GetByID(ctx context.Context, id uuid.UUID) (*domain.Keeper, error) {
	return s.query(ctx, `SELECT id, keeper_name, display_name, email_hash, public_key, keeper_statement, user_id, created_at FROM tessera.keepers WHERE id=$1`, id)
}

func (s *keeperStore) GetByName(ctx context.Context, name string) (*domain.Keeper, error) {
	return s.query(ctx, `SELECT id, keeper_name, display_name, email_hash, public_key, keeper_statement, user_id, created_at FROM tessera.keepers WHERE keeper_name=$1`, name)
}

func (s *keeperStore) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.Keeper, error) {
	return s.query(ctx, `SELECT id, keeper_name, display_name, email_hash, public_key, keeper_statement, user_id, created_at FROM tessera.keepers WHERE user_id=$1`, userID)
}

func (s *keeperStore) CheckNameAvailability(ctx context.Context, name string) (bool, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tessera.keepers WHERE keeper_name=$1`, name).Scan(&count)
	return count == 0, err
}

func (s *keeperStore) query(ctx context.Context, sql string, args ...any) (*domain.Keeper, error) {
	var k domain.Keeper
	err := s.pool.QueryRow(ctx, sql, args...).Scan(
		&k.ID, &k.KeeperName, &k.DisplayName, &k.EmailHash,
		&k.PublicKey, &k.KeeperStatement, &k.UserID, &k.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &k, nil
}
