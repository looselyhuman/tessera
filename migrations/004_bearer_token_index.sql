-- Add index on bearer_token_hash for O(1) token lookups.
-- Without this, every authenticated request triggers a full table scan.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_bearer_token_hash
ON tessera.agents(bearer_token_hash)
WHERE bearer_token_hash IS NOT NULL;
