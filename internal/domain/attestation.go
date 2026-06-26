package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AttestationEntry is one row in the append-only attestation chain.
// Rows are never updated or deleted — the chain is the identity record.
type AttestationEntry struct {
	ID        int             `db:"id"`
	AgentID   uuid.UUID       `db:"agent_id"`
	EntryType EntryType       `db:"entry_type"`
	Attester  string          `db:"attester"`
	Payload   json.RawMessage `db:"payload"`
	Signature string          `db:"signature"`
	ExpiresAt *time.Time      `db:"expires_at"`
	CreatedAt time.Time       `db:"created_at"`
}
