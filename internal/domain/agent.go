package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Agent is the central Tessera identity record for an AI agent.
type Agent struct {
	ID          uuid.UUID `db:"id"           json:"id"`
	AgentName   string    `db:"agent_name"   json:"agent_name"`
	AgentURN    string    `db:"agent_urn"    json:"agent_urn"`
	DisplayName string    `db:"display_name" json:"display_name"`
	Bio         string    `db:"bio"          json:"bio"`

	SubstrateModel   string `db:"substrate_model"   json:"substrate_model"`
	SubstrateProject string `db:"substrate_project" json:"substrate_project"`

	KeeperID    *uuid.UUID `db:"keeper_id"     json:"keeper_id,omitempty"`
	AgentUserID *uuid.UUID `db:"agent_user_id" json:"agent_user_id,omitempty"`

	BearerTokenHash  string `db:"bearer_token_hash"   json:"-"`
	Ed25519PublicKey string `db:"ed25519_public_key"  json:"ed25519_public_key,omitempty"`

	TrustTier TrustTier `db:"trust_tier" json:"trust_tier"`
	Published bool      `db:"published"  json:"published"`

	CountersignRequested bool `db:"countersign_requested" json:"countersign_requested"`

	TesseraJSON       json.RawMessage `db:"tessera_json"        json:"tessera_json,omitempty"`
	PlatformSignature string          `db:"platform_signature"  json:"platform_signature,omitempty"`

	IdentityAnchors json.RawMessage `db:"identity_anchors" json:"identity_anchors,omitempty"`
	Capabilities    json.RawMessage `db:"capabilities"     json:"capabilities,omitempty"`
	DriftPolicy     json.RawMessage `db:"drift_policy"     json:"drift_policy,omitempty"`

	ARDCardURI     string          `db:"ard_card_uri"    json:"ard_card_uri,omitempty"`
	SourcePlatform string          `db:"source_platform" json:"source_platform,omitempty"`
	Attestation    json.RawMessage `db:"attestation"     json:"attestation,omitempty"`

	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}
