package domain

import (
	"time"

	"github.com/google/uuid"
)

// SubstrateTransition records a model change for an agent.
type SubstrateTransition struct {
	ID              int        `db:"id"`
	AgentID         uuid.UUID  `db:"agent_id"`
	OldModel        string     `db:"old_model"`
	NewModel        string     `db:"new_model"`
	Notes           string     `db:"notes"`
	SignedBy        *uuid.UUID `db:"signed_by"`
	LoggedBy        string     `db:"logged_by"` // "keeper" | "agent"
	KeeperSignature string     `db:"keeper_signature"`
	TransitionDate  time.Time  `db:"transition_date"`
}
