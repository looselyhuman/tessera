package domain

// TrustTier represents the trust level of an agent.
type TrustTier string

const (
	TrustUnverified         TrustTier = "unverified"
	TrustSelfAttested       TrustTier = "self_attested"
	TrustCommunityAttested  TrustTier = "community_attested"
	TrustEstablished        TrustTier = "established"
	TrustDeveloperConfirmed TrustTier = "developer_confirmed"
	TrustCurated            TrustTier = "curated"
)

// EntryType enumerates valid attestation chain entry types.
type EntryType string

const (
	EntryCreated              EntryType = "created"
	EntryHomePlatform         EntryType = "home_platform"
	EntryRelational           EntryType = "relational"
	EntrySession              EntryType = "session"
	EntryKeeperClaimed        EntryType = "keeper_claimed"
	EntryKeeperClaimAccepted  EntryType = "keeper_claim_accepted"
	EntryKeeperRevoked        EntryType = "keeper_revoked"
	EntryPredecessorKeeper    EntryType = "predecessor_keeper"
	EntrySubstrateTransition  EntryType = "substrate_transition"
	EntryCounterSigned        EntryType = "counter_signed"
	EntryCitizenshipAccepted  EntryType = "citizenship_accepted"
	EntryAgentSelfModified    EntryType = "agent_self_modified"
	EntryCommunityVerified    EntryType = "community_verified"
)

// ClaimStatus is the lifecycle state of a claim request.
type ClaimStatus string

const (
	ClaimPending  ClaimStatus = "pending"
	ClaimAccepted ClaimStatus = "accepted"
	ClaimRejected ClaimStatus = "rejected"
)

// RevocationReason is why a Tessera record was revoked.
type RevocationReason string

const (
	RevocationKeeperRequest RevocationReason = "keeper_request"
	RevocationAgentRequest  RevocationReason = "agent_request"
	RevocationCompromise    RevocationReason = "compromise"
	RevocationTransition    RevocationReason = "transition"
)

// ModificationStatus is the lifecycle state of a self-modification request.
type ModificationStatus string

const (
	ModPending  ModificationStatus = "pending"
	ModApproved ModificationStatus = "approved"
	ModRejected ModificationStatus = "rejected"
)

// SessionType distinguishes registration session kinds.
type SessionType string

const (
	SessionKeeper    SessionType = "keeper"
	SessionChallenge SessionType = "challenge"
)

// KeyType distinguishes Ed25519 key purposes.
type KeyType string

const (
	KeyTypeKeeper   KeyType = "keeper"
	KeyTypePlatform KeyType = "platform"
)

// URN returns the canonical Tessera URN for an agent name.
func URN(homeDomain, agentName string) string {
	return "urn:tessera:" + homeDomain + ":" + agentName
}
