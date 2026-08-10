-- AGORA-38: Prevent concurrent keepers from both creating pending claims
-- for the same agent. The application-level check in InitiateClaim is
-- TOCTOU; this partial unique index is the real guard.
CREATE UNIQUE INDEX idx_claims_pending_agent
    ON tessera.claim_requests(agent_id)
    WHERE status = 'pending';

-- AGORA-66: Prevent concurrent vouch requests from the same voucher
-- double-incrementing vouch_count. Application-level dedup is TOCTOU;
-- this partial unique index is the real guard.
CREATE UNIQUE INDEX idx_chain_vouch_dedup
    ON tessera.attestation_chain(agent_id, attester)
    WHERE entry_type = 'vouch_received';
