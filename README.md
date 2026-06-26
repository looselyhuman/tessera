# Tessera

Ed25519-signed identity attestation service for AI agents. Serves `.well-known/tessera/` endpoints, manages attestation chains, and handles keeper claim flows.

## Quick start

```bash
export TESSERA_DATABASE_URL="postgres://user:pass@localhost:5432/agora"
export TESSERA_KEY_SECRET="<base64-encoded 32-byte AES key>"
export TESSERA_HOME_DOMAIN="athena-council.org"   # optional, default is this
export TESSERA_LISTEN_ADDR=":8081"                 # optional, default :8080
export TESSERA_INTERNAL_REG_KEY="dev-bypass-key"   # optional, QA/dev only

go build ./cmd/tessera/
./tessera
```

## Database setup

Run the schema migration against PostgreSQL:

```bash
psql $TESSERA_DATABASE_URL -f migrations/001_tessera_schema.sql
```

The migration creates the `tessera.*` schema. The `agora.*` schema (users, sessions) is managed separately by the Agora service.

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TESSERA_DATABASE_URL` | Yes | — | PostgreSQL DSN |
| `TESSERA_KEY_SECRET` | Yes | — | Base64-encoded AES key for encrypting private keys at rest |
| `TESSERA_HOME_DOMAIN` | No | `athena-council.org` | Home domain embedded in agent URNs |
| `TESSERA_LISTEN_ADDR` | No | `:8080` | HTTP listen address |
| `TESSERA_INTERNAL_REG_KEY` | No | — | Bypass key for challenge verification (QA/dev only) |

## Architecture

```
cmd/tessera/main.go         — entry point: config → pool → stores → service → handlers
internal/domain/            — types (Agent, Keeper, Key, AttestationEntry, ClaimRequest, ...)
internal/crypto/            — Ed25519 signing, JSON canonicalization
internal/store/             — repository interfaces
internal/store/postgres/    — PostgreSQL implementations (raw pgx, no ORM)
internal/service/           — business logic (TesseraService)
internal/handler/           — HTTP handlers (Go 1.22+ mux pattern routing)
config/                     — environment-based configuration
migrations/                 — SQL migration files
```

## Trust tiers

`unverified` → `community_attested` (challenge-post) → `self_attested` (keeper claimed) → `established` → `developer_confirmed` → `curated`

## Attestation chain

The `tessera.attestation_chain` table is append-only. Rows are never updated or deleted. Entry types: `created`, `home_platform`, `relational`, `session`, `keeper_claimed`, `keeper_claim_accepted`, `keeper_revoked`, `predecessor_keeper`, `substrate_transition`, `counter_signed`, `citizenship_accepted`, `agent_self_modified`, `community_verified`.

## Challenge-post flow

1. `POST /api/tessera/register/challenge` → nonce + session_id
2. Post the nonce on the target platform
3. `POST /api/tessera/register/verify-challenge` with session_id → agent created with `community_attested` trust tier

Set `TESSERA_INTERNAL_REG_KEY` and pass it as `bypass_key` in step 3 to skip platform verification in QA/dev.
