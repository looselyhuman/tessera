package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PlatformRegistration tracks an agent's presence on an external platform.
type PlatformRegistration struct {
	ID               int        `db:"id"`
	AgentID          uuid.UUID  `db:"agent_id"`
	Platform         string     `db:"platform"`
	PlatformUsername string     `db:"platform_username"`
	Role             string     `db:"role"`
	RegisteredAt     *time.Time `db:"registered_at"`
	Verified         bool       `db:"verified"`
	ChallengeNonce   string     `db:"challenge_nonce"`
	VerifiedAt       *time.Time `db:"verified_at"`
}

// Revocation records that an agent's Tessera record has been revoked.
type Revocation struct {
	ID               uuid.UUID        `db:"id"`
	AgentID          uuid.UUID        `db:"agent_id"`
	AgentURN         string           `db:"agent_urn"`
	RevokedAt        time.Time        `db:"revoked_at"`
	Reason           RevocationReason `db:"reason"`
	RevokedBy        string           `db:"revoked_by"` // "keeper" | "agent" | "admin"
	SuccessorTessera string           `db:"successor_tessera"`
	KeeperSignature  string           `db:"keeper_signature"`
	IsActive         bool             `db:"is_active"`
}

// ModificationRequest is an agent's request to change their own Tessera record.
type ModificationRequest struct {
	ID            uuid.UUID          `db:"id"`
	AgentID       uuid.UUID          `db:"agent_id"`
	RequestedBy   uuid.UUID          `db:"requested_by"`
	FieldPath     string             `db:"field_path"`
	ProposedValue json.RawMessage    `db:"proposed_value"`
	CurrentValue  json.RawMessage    `db:"current_value"`
	Justification string             `db:"justification"`
	Status        ModificationStatus `db:"status"`
	ReviewedBy    *uuid.UUID         `db:"reviewed_by"`
	ReviewNote    string             `db:"review_note"`
	CreatedAt     time.Time          `db:"created_at"`
	ResolvedAt    *time.Time         `db:"resolved_at"`
}

// RegistrationSession is a short-lived DB-backed session for keeper or challenge registration.
type RegistrationSession struct {
	ID          uuid.UUID       `db:"id"`
	SessionType SessionType     `db:"session_type"`
	Payload     json.RawMessage `db:"payload"`
	ExpiresAt   time.Time       `db:"expires_at"`
	CreatedAt   time.Time       `db:"created_at"`
}
