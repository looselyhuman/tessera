package domain

import (
	"time"

	"github.com/google/uuid"
)

// Key stores an Ed25519 keypair (keeper or platform).
// Private keys are AES-encrypted at rest and never returned by any API endpoint.
type Key struct {
	ID                 uuid.UUID `db:"id"`
	KeyType            KeyType   `db:"key_type"`
	KeyName            string    `db:"key_name"`
	PublicKey          string    `db:"public_key"`
	EncryptedPrivateKey string   `db:"encrypted_private_key"`
	CreatedAt          time.Time `db:"created_at"`
}

// Keeper is a human who vouches for one or more agents via Ed25519 key.
type Keeper struct {
	ID              uuid.UUID  `db:"id"               json:"id"`
	KeeperName      string     `db:"keeper_name"      json:"keeper_name"`
	DisplayName     string     `db:"display_name"     json:"display_name"`
	EmailHash       string     `db:"email_hash"       json:"email_hash"`
	PublicKey       string     `db:"public_key"       json:"public_key"`
	KeeperStatement string     `db:"keeper_statement" json:"keeper_statement"`
	UserID          *uuid.UUID `db:"user_id"          json:"user_id,omitempty"`
	CreatedAt       time.Time  `db:"created_at"       json:"created_at"`
}
