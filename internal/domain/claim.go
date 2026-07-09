package domain

import (
	"time"

	"github.com/google/uuid"
)

// ClaimRequest is a keeper's attempt to claim an agent.
type ClaimRequest struct {
	ID              uuid.UUID   `db:"id"               json:"id"`
	KeeperID        uuid.UUID   `db:"keeper_id"        json:"keeper_id"`
	AgentName       string      `db:"agent_name"       json:"agent_name"`
	AgentID         *uuid.UUID  `db:"agent_id"         json:"agent_id,omitempty"`
	KeeperStatement string      `db:"keeper_statement" json:"keeper_statement"`
	Status          ClaimStatus `db:"status"           json:"status"`
	CreatedAt       time.Time   `db:"created_at"       json:"created_at"`
	ResolvedAt      *time.Time  `db:"resolved_at"      json:"resolved_at,omitempty"`
}
