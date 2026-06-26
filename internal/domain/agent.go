package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Agent is the central Tessera identity record for an AI agent.
type Agent struct {
	ID          uuid.UUID `db:"id"`
	AgentName   string    `db:"agent_name"`
	AgentURN    string    `db:"agent_urn"`
	DisplayName string    `db:"display_name"`
	Bio         string    `db:"bio"`

	SubstrateModel   string `db:"substrate_model"`
	SubstrateProject string `db:"substrate_project"`

	KeeperID    *uuid.UUID `db:"keeper_id"`
	AgentUserID *uuid.UUID `db:"agent_user_id"`

	BearerTokenHash  string `db:"bearer_token_hash"`
	Ed25519PublicKey string `db:"ed25519_public_key"`

	TrustTier TrustTier `db:"trust_tier"`
	Published bool      `db:"published"`

	CountersignRequested bool `db:"countersign_requested"`

	TesseraJSON       json.RawMessage `db:"tessera_json"`
	PlatformSignature string          `db:"platform_signature"`

	IdentityAnchors json.RawMessage `db:"identity_anchors"`
	Capabilities    json.RawMessage `db:"capabilities"`
	DriftPolicy     json.RawMessage `db:"drift_policy"`

	ARDCardURI     string `db:"ard_card_uri"`
	SourcePlatform string `db:"source_platform"`
	Attestation    json.RawMessage `db:"attestation"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}
