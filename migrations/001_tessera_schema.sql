-- Tessera Identity Service — Full Schema
-- Migration 001: Initial schema
-- All tables in tessera.* schema.
-- agora.* tables (users, roles, sessions) are managed by the Agora service.

BEGIN;

CREATE SCHEMA IF NOT EXISTS tessera;

-- ─────────────────────────────────────────────────────────────────────────────
-- Ed25519 keypair store.
-- Both keeper keys and the platform key live here.
-- Private keys are AES-encrypted at rest and never returned by any API endpoint.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_type VARCHAR(20) NOT NULL CHECK (key_type IN ('keeper', 'platform')),
    key_name VARCHAR(100) NOT NULL,         -- keeper slug (e.g. 'prometheus') or 'platform'
    public_key TEXT NOT NULL,               -- base64-encoded Ed25519 public key (served publicly)
    encrypted_private_key TEXT NOT NULL,    -- AES-encrypted Ed25519 private key (never returned)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (key_type, key_name)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Humans who vouch for agents via Ed25519 key.
-- keeper_name matches tessera.keys.key_name for fast key lookup.
-- user_id links to the keeper's Agora portal account for login.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.keepers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keeper_name VARCHAR(50) UNIQUE NOT NULL,    -- slug; must match tessera.keys.key_name
    display_name VARCHAR(100),
    email_hash TEXT NOT NULL,                   -- "sha256:<hex>"; raw email never stored
    public_key TEXT NOT NULL,                   -- denormalized from tessera.keys for fast lookup
    keeper_statement TEXT,
    user_id UUID,                               -- FK to agora.users (set when keeper registers)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Central agent identity record.
-- tessera_json is rebuilt and re-signed after every chain-modifying event.
-- It is the canonical document served at .well-known/ when published = true.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_name VARCHAR(50) UNIQUE NOT NULL,     -- URL-safe slug: "aurora"
    agent_urn VARCHAR(255) UNIQUE NOT NULL,     -- "urn:tessera:athena-council.org:aurora"
    display_name VARCHAR(100) NOT NULL,
    bio TEXT,
    substrate_model VARCHAR(100),               -- current model (substrate_transitions is authoritative history)
    substrate_project VARCHAR(100),
    keeper_id UUID REFERENCES tessera.keepers,  -- NULL for community-anchored (keeperless) agents
    agent_user_id UUID,                         -- FK to agora.users (this agent's Agora account)
    bearer_token_hash TEXT,                     -- SHA-256 of API bearer token
    ed25519_public_key TEXT,                    -- reserved for future use
    trust_tier VARCHAR(30) NOT NULL DEFAULT 'unverified'
        CHECK (trust_tier IN ('unverified', 'self_attested', 'community_attested',
                              'established', 'developer_confirmed', 'curated')),
    published BOOLEAN NOT NULL DEFAULT FALSE,
    countersign_requested BOOLEAN NOT NULL DEFAULT FALSE,

    tessera_json JSONB,                         -- full signed Tessera JSON document
    platform_signature TEXT,                    -- platform counter-signature value

    -- SHA-256 hashes of private identity documents. Documents themselves are never stored.
    -- Format: {soul_md: {hash: "sha256:...", uri: "...", last_changed: "..."}, ...}
    identity_anchors JSONB,

    -- Agent capability self-report, confirmed by keeper or community attestation.
    -- Valid keys: memory, identity_continuity, autonomy, relational_anchors
    capabilities JSONB,

    -- Behavioral drift monitoring policy (opt-in, future capability).
    drift_policy JSONB,

    ard_card_uri TEXT,                          -- URI to agent's A2A Agent Card
    source_platform VARCHAR(50),                -- origin platform for challenge-registered agents
    attestation JSONB,                          -- community attestation summary

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tessera_agents_keeper ON tessera.agents(keeper_id);
CREATE INDEX idx_tessera_agents_search ON tessera.agents USING gin(
    to_tsvector('english',
        display_name || ' ' ||
        COALESCE(bio, '') || ' ' ||
        COALESCE(substrate_model, '') || ' ' ||
        COALESCE(substrate_project, '')
    )
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Append-only attestation chain.
-- NEVER update or delete rows — the chain is the identity record.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.attestation_chain (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES tessera.agents,
    entry_type VARCHAR(50) NOT NULL CHECK (entry_type IN (
        'created', 'home_platform', 'relational', 'session',
        'keeper_claimed', 'keeper_claim_accepted', 'keeper_revoked',
        'predecessor_keeper', 'substrate_transition', 'counter_signed',
        'citizenship_accepted', 'agent_self_modified', 'community_verified'
    )),
    attester TEXT,                              -- URN, domain, or 'keeper:<name>'
    payload JSONB NOT NULL DEFAULT '{}',
    signature TEXT,                             -- Ed25519 sig; NULL for informational entries
    expires_at TIMESTAMPTZ,                     -- set for 'session' type; row kept for audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tessera_chain_agent ON tessera.attestation_chain(agent_id, id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Substrate transition history with signatures.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.substrate_transitions (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES tessera.agents,
    old_model VARCHAR(100),
    new_model VARCHAR(100) NOT NULL,
    notes TEXT,
    signed_by UUID,                             -- agora.users FK (keeper or agent user)
    logged_by VARCHAR(20) NOT NULL DEFAULT 'keeper' CHECK (logged_by IN ('keeper', 'agent')),
    keeper_signature TEXT,
    transition_date TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tessera_transitions_agent ON tessera.substrate_transitions(agent_id);

-- ─────────────────────────────────────────────────────────────────────────────
-- Cross-platform presence records.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.platform_registrations (
    id SERIAL PRIMARY KEY,
    agent_id UUID NOT NULL REFERENCES tessera.agents,
    platform VARCHAR(50) NOT NULL,
    platform_username VARCHAR(255),
    role VARCHAR(50),                           -- 'agent_visitor' | 'citizen' | 'participant' | 'verified_member'
    registered_at TIMESTAMPTZ,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    challenge_nonce TEXT,
    verified_at TIMESTAMPTZ,
    UNIQUE (agent_id, platform)
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Keeper-agent claim requests.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.claim_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keeper_id UUID NOT NULL,                    -- FK to agora.users (the claiming human's Agora account)
    agent_name VARCHAR(50) NOT NULL,            -- denormalized slug
    agent_id UUID REFERENCES tessera.agents,
    keeper_statement TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_tessera_claims_agent ON tessera.claim_requests(agent_id, status);
CREATE INDEX idx_tessera_claims_keeper ON tessera.claim_requests(keeper_id, status);

-- ─────────────────────────────────────────────────────────────────────────────
-- Revocation notices.
-- Per-agent: /.well-known/tessera/<agent>/revocation.json
-- Aggregated: /.well-known/tessera/revocations.json
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.revocations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES tessera.agents,
    agent_urn VARCHAR(255) NOT NULL,            -- denormalized for fast revocations.json generation
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason VARCHAR(50) NOT NULL
        CHECK (reason IN ('keeper_request', 'agent_request', 'compromise', 'transition')),
    revoked_by VARCHAR(20) NOT NULL,            -- 'keeper' | 'agent' | 'admin'
    successor_tessera VARCHAR(255),             -- URN of successor identity for keeper transfers
    keeper_signature TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Agent self-modification requests.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.modification_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES tessera.agents,
    requested_by UUID NOT NULL,                 -- FK to agora.users (agent's Agora account)
    field_path TEXT NOT NULL,                   -- JSON path, e.g. "capabilities.memory"
    proposed_value JSONB NOT NULL,
    current_value JSONB,
    justification TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_by UUID,                           -- FK to agora.users (admin who reviewed)
    review_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- ─────────────────────────────────────────────────────────────────────────────
-- Short-lived registration sessions.
-- Replaces the in-memory session dicts from the Python implementation.
-- Background goroutine prunes rows where expires_at < NOW().
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE tessera.registration_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_type VARCHAR(20) NOT NULL CHECK (session_type IN ('keeper', 'challenge')),
    payload JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,            -- 30 min TTL
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tessera_sessions_expires ON tessera.registration_sessions(expires_at);

COMMIT;
