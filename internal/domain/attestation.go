package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// AttestationEntry is one row in the append-only attestation chain.
// Rows are never updated or deleted — the chain is the identity record.
type AttestationEntry struct {
	ID        int             `db:"id"         json:"id"`
	AgentID   uuid.UUID       `db:"agent_id"   json:"agent_id"`
	EntryType EntryType       `db:"entry_type" json:"entry_type"`
	Attester  string          `db:"attester"   json:"attester"`
	Payload   json.RawMessage `db:"payload"    json:"payload,omitempty"`
	Signature string          `db:"signature"  json:"signature,omitempty"`
	ExpiresAt *time.Time      `db:"expires_at" json:"expires_at,omitempty"`
	CreatedAt time.Time       `db:"created_at" json:"created_at"`
}
