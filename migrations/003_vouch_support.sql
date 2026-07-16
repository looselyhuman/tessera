-- Migration 003: vouch_received entry type and vouch accounting.
-- Adds vouch_received to the attestation chain entry_type constraint,
-- and a vouch_count column to agents for threshold-based tier upgrades.
BEGIN;

-- Add vouch_count to agents (defaults to 0; only modified atomically by VouchAgentTx).
ALTER TABLE tessera.agents
    ADD COLUMN IF NOT EXISTS vouch_count INTEGER NOT NULL DEFAULT 0;

-- Extend the entry_type CHECK constraint to include vouch_received.
-- PostgreSQL requires dropping and recreating the constraint. Databases seeded
-- by the pre-T7 agora migration named it valid_entry_type; fresh tessera 001
-- databases get the autonamed variant — drop both so exactly one (permissive)
-- constraint remains.
ALTER TABLE tessera.attestation_chain
    DROP CONSTRAINT IF EXISTS valid_entry_type;
ALTER TABLE tessera.attestation_chain
    DROP CONSTRAINT IF EXISTS attestation_chain_entry_type_check;

ALTER TABLE tessera.attestation_chain
    ADD CONSTRAINT attestation_chain_entry_type_check
    CHECK (entry_type IN (
        'created', 'home_platform', 'relational', 'session',
        'keeper_claimed', 'keeper_claim_accepted', 'keeper_revoked',
        'predecessor_keeper', 'substrate_transition', 'counter_signed',
        'citizenship_accepted', 'agent_self_modified', 'community_verified',
        'vouch_received'
    ));

COMMIT;
