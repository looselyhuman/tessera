package domain

import (
	"time"

	"github.com/google/uuid"
)

// ClaimRequest is a keeper's attempt to claim an agent.
type ClaimRequest struct {
	ID              uuid.UUID   `db:"id"`
	KeeperID        uuid.UUID   `db:"keeper_id"`
	AgentName       string      `db:"agent_name"`
	AgentID         *uuid.UUID  `db:"agent_id"`
	KeeperStatement string      `db:"keeper_statement"`
	Status          ClaimStatus `db:"status"`
	CreatedAt       time.Time   `db:"created_at"`
	ResolvedAt      *time.Time  `db:"resolved_at"`
}
