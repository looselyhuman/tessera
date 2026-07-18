package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// WellKnownAgent returns a fully-populated, signed Tessera attestation JSON for a
// published agent — matching Ariadne-parity fields: keeper object, Ed25519 signature
// block, attestation_chain, substrate_history, capabilities, identity_anchors, and
// platform_registrations.
//
// Signing follows the same pattern as GetSignedRegistry: canonicalize the stable
// identity fields and sign at render time with the keeper's key (preferred) or
// the platform key as fallback. Chain integrity failures are logged as warnings
// but do not block the response.
func (s *TesseraService) WellKnownAgent(ctx context.Context, name string) (json.RawMessage, error) {
	agent, err := s.agents.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !agent.Published {
		return nil, fmt.Errorf("agent %q is not published", name)
	}

	// Chain integrity check — warn on failures but do not block.
	if report, err := s.VerifyChainIntegrity(ctx, agent.ID); err != nil {
		slog.Warn("chain integrity check failed", "agent", name, "error", err)
	} else {
		for _, e := range report.Entries {
			if e.Checked && !e.Valid {
				slog.Warn("chain entry failed verification",
					"agent", name,
					"entry_id", e.EntryID,
					"entry_type", e.EntryType,
					"attester", e.Attester,
					"error", e.Error,
				)
			}
		}
	}

	// ── Keeper block ──────────────────────────────────────────────────────────
	var keeperBlock map[string]any
	var keeperName string
	var keeperPrivB64 string // set when the keeper key is available for signing

	if agent.KeeperID != nil {
		if keeper, err := s.keepers.GetByID(ctx, *agent.KeeperID); err != nil {
			slog.Warn("wellknown: keeper lookup failed", "agent", name, "keeper_id", agent.KeeperID, "error", err)
		} else {
			keeperName = keeper.KeeperName
			pubKeyURI := fmt.Sprintf("https://%s/.well-known/tessera/keepers/%s/key.json", s.homeDomain, keeper.KeeperName)
			keeperBlock = map[string]any{
				"email_hash":          keeper.EmailHash,
				"public_key_uri":      pubKeyURI,
				"keeper_statement":    keeper.KeeperStatement,
				"verification_method": "email_dns_dkim",
			}

			// Retrieve keeper private key for signing.
			if keeperKey, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypeKeeper, keeper.KeeperName); err != nil {
				slog.Warn("wellknown: keeper key not found — will try platform key", "agent", name, "keeper", keeper.KeeperName)
			} else if encRaw, err := base64.StdEncoding.DecodeString(keeperKey.EncryptedPrivateKey); err != nil {
				slog.Warn("wellknown: decode keeper key failed", "agent", name, "error", err)
			} else if privBytes, err := tessera_crypto.Decrypt(encRaw, s.encryptionKey); err != nil {
				slog.Warn("wellknown: decrypt keeper key failed", "agent", name, "error", err)
			} else {
				keeperPrivB64 = string(privBytes)
			}
		}
	}

	// ── Attestation chain ─────────────────────────────────────────────────────
	chainEntries, err := s.chain.GetByAgent(ctx, agent.ID)
	if err != nil {
		slog.Warn("wellknown: chain fetch failed", "agent", name, "error", err)
		chainEntries = nil
	}
	chainOut := make([]map[string]any, 0, len(chainEntries))
	for _, e := range chainEntries {
		row := map[string]any{
			"id":         e.ID,
			"entry_type": string(e.EntryType),
			"attester":   e.Attester,
			"created_at": e.CreatedAt.UTC().Format(time.RFC3339),
		}
		if len(e.Payload) > 0 && string(e.Payload) != "{}" {
			row["payload"] = e.Payload
		}
		if e.Signature != "" {
			row["signature"] = e.Signature
		}
		chainOut = append(chainOut, row)
	}

	// ── Substrate history ─────────────────────────────────────────────────────
	transitions, err := s.transitions.ListByAgent(ctx, agent.ID)
	if err != nil {
		slog.Warn("wellknown: substrate transitions fetch failed", "agent", name, "error", err)
		transitions = nil
	}
	substrateHistory := make([]map[string]any, 0)
	if len(transitions) == 0 {
		// Synthetic entry for the current substrate when no transitions exist.
		substrateHistory = append(substrateHistory, map[string]any{
			"model": agent.SubstrateModel,
			"from":  agent.CreatedAt.UTC().Format(time.RFC3339),
			"to":    nil,
		})
	} else {
		firstFrom := agent.CreatedAt
		if transitions[0].TransitionDate.Before(firstFrom) {
			firstFrom = transitions[0].TransitionDate
		}
		for i, t := range transitions {
			from := firstFrom
			if i > 0 {
				from = transitions[i-1].TransitionDate
			}
			entry := map[string]any{
				"model": t.OldModel,
				"from":  from.UTC().Format(time.RFC3339),
				"to":    t.TransitionDate.UTC().Format(time.RFC3339),
			}
			if t.Notes != "" {
				entry["transition_note"] = t.Notes
			}
			substrateHistory = append(substrateHistory, entry)
		}
		// Add the current substrate as the last (open) entry.
		last := transitions[len(transitions)-1]
		substrateHistory = append(substrateHistory, map[string]any{
			"model": last.NewModel,
			"from":  last.TransitionDate.UTC().Format(time.RFC3339),
			"to":    nil,
		})
	}

	// ── Platform registrations ────────────────────────────────────────────────
	platRegs, err := s.platforms.ListByAgent(ctx, agent.ID)
	if err != nil {
		slog.Warn("wellknown: platform registrations fetch failed", "agent", name, "error", err)
		platRegs = nil
	}
	platOut := make([]map[string]any, 0, len(platRegs))
	for _, pr := range platRegs {
		row := map[string]any{
			"platform": pr.Platform,
			"verified": pr.Verified,
		}
		if pr.PlatformUsername != "" {
			row["platform_username"] = pr.PlatformUsername
		}
		if pr.Role != "" {
			row["role"] = pr.Role
		}
		if pr.VerifiedAt != nil {
			row["verified_at"] = pr.VerifiedAt.UTC().Format(time.RFC3339)
		}
		platOut = append(platOut, row)
	}

	// ── Capabilities and identity anchors ─────────────────────────────────────
	var capabilities any = map[string]any{}
	if len(agent.Capabilities) > 0 {
		var cap any
		if err := json.Unmarshal(agent.Capabilities, &cap); err == nil {
			capabilities = cap
		}
	}
	var identityAnchors any = map[string]any{}
	if len(agent.IdentityAnchors) > 0 {
		var anch any
		if err := json.Unmarshal(agent.IdentityAnchors, &anch); err == nil {
			identityAnchors = anch
		}
	}

	// ── Build the core identity payload to sign ───────────────────────────────
	// We sign the stable identity fields — not the full document — so the signature
	// remains valid even as chain entries accumulate.
	sigPayload := map[string]any{
		"agent_id":         agent.AgentURN,
		"display_name":     agent.DisplayName,
		"substrate_model":  agent.SubstrateModel,
		"substrate_project": agent.SubstrateProject,
		"trust_tier":       string(agent.TrustTier),
		"created_at":       agent.CreatedAt.UTC().Format(time.RFC3339),
	}
	if keeperBlock != nil {
		sigPayload["keeper_email_hash"] = keeperBlock["email_hash"]
		sigPayload["keeper_public_key_uri"] = keeperBlock["public_key_uri"]
	}
	canonical, canonErr := tessera_crypto.Canonicalize(sigPayload)

	// ── Signature block ───────────────────────────────────────────────────────
	// If canonicalization failed, skip signing entirely — a signature over nil/empty
	// bytes would be valid-looking but meaningless and would mislead verifiers.
	var sigBlock map[string]any
	if canonErr != nil {
		slog.Warn("wellknown: canonicalize failed — skipping signature", "agent", name, "error", canonErr)
	} else if keeperPrivB64 != "" {
		if sig, err := tessera_crypto.Sign(keeperPrivB64, canonical); err != nil {
			slog.Warn("wellknown: keeper sign failed", "agent", name, "error", err)
		} else {
			signer := "keeper:" + keeperName
			sigBlock = map[string]any{
				"value":     sig,
				"signer":    signer,
				"algorithm": "Ed25519",
			}
		}
	}
	// Fallback: try platform key when keeper key is unavailable.
	// Guard on canonErr so we never sign garbage bytes via the fallback path either.
	if sigBlock == nil && canonErr == nil {
		if platKey, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypePlatform, "platform"); err == nil {
			if encRaw, err := base64.StdEncoding.DecodeString(platKey.EncryptedPrivateKey); err == nil {
				if privBytes, err := tessera_crypto.Decrypt(encRaw, s.encryptionKey); err == nil {
					if sig, err := tessera_crypto.Sign(string(privBytes), canonical); err == nil {
						sigBlock = map[string]any{
							"value":     sig,
							"signer":    "platform",
							"algorithm": "Ed25519",
						}
					}
				}
			}
		}
	}

	// ── Assemble the full attestation document ────────────────────────────────
	doc := map[string]any{
		"tessera_version":        "1.0",
		"agent_id":               agent.AgentURN,
		"display_name":           agent.DisplayName,
		"substrate_model":        agent.SubstrateModel,
		"substrate_project":      agent.SubstrateProject,
		"trust_tier":             string(agent.TrustTier),
		"source_platform":        agent.SourcePlatform,
		"created_at":             agent.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":             agent.UpdatedAt.UTC().Format(time.RFC3339),
		"keeper":                 keeperBlock,
		"signature":              sigBlock,
		"attestation_chain":      chainOut,
		"substrate_history":      substrateHistory,
		"capabilities":           capabilities,
		"identity_anchors":       identityAnchors,
		"platform_registrations": platOut,
	}

	return json.Marshal(doc)
}

// WellKnownRevocations returns the active revocations list.
func (s *TesseraService) WellKnownRevocations(ctx context.Context) ([]map[string]any, error) {
	revs, err := s.revocations.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(revs))
	for _, r := range revs {
		out = append(out, map[string]any{
			"agent_urn":  r.AgentURN,
			"revoked_at": r.RevokedAt,
			"reason":     r.Reason,
		})
	}
	return out, nil
}

// WellKnownARDCatalog returns the ARD-compatible agent catalog.
func (s *TesseraService) WellKnownARDCatalog(ctx context.Context) ([]map[string]any, error) {
	agents, _, err := s.agents.List(ctx, store.ListOptions{Page: 1, PageSize: 1000})
	if err != nil {
		return nil, err
	}
	catalog := make([]map[string]any, 0, len(agents))
	for _, a := range agents {
		entry := map[string]any{
			"id":           a.AgentURN,
			"display_name": a.DisplayName,
			"substrate":    a.SubstrateModel,
			"project":      a.SubstrateProject,
			"trust_tier":   a.TrustTier,
		}
		if a.ARDCardURI != "" {
			entry["ard_card_uri"] = a.ARDCardURI
		}
		catalog = append(catalog, entry)
	}
	return catalog, nil
}

// WellKnownPlatformPub returns the platform Ed25519 public key in base64.
// Returns an error if no platform key has been generated yet.
func (s *TesseraService) WellKnownPlatformPub(ctx context.Context) (string, error) {
	key, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypePlatform, "platform")
	if err != nil {
		return "", fmt.Errorf("platform key not found: %w", err)
	}
	return key.PublicKey, nil
}

// WellKnownKeeperPubKey returns the base64 public key for a named keeper.
func (s *TesseraService) WellKnownKeeperPubKey(ctx context.Context, keeperName string) (string, error) {
	key, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypeKeeper, keeperName)
	if err != nil {
		return "", fmt.Errorf("keeper %q not found: %w", keeperName, err)
	}
	return key.PublicKey, nil
}

// registryAgent is the per-agent record in the signed registry response.
type registryAgent struct {
	Name       string `json:"name"`
	URN        string `json:"urn"`
	PublicKey  string `json:"public_key,omitempty"`
	TrustTier  string `json:"trust_tier"`
	KeeperName string `json:"keeper_name,omitempty"`
}

// GetSignedRegistry returns a signed directory of all published agents.
// The agents array is signed with the platform's Ed25519 key.
// If no platform key exists, signature is null and a warning is logged.
func (s *TesseraService) GetSignedRegistry(ctx context.Context) (map[string]any, error) {
	agents, _, err := s.agents.List(ctx, store.ListOptions{Page: 1, PageSize: 10000})
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}

	entries := make([]registryAgent, 0, len(agents))
	for _, a := range agents {
		if !a.Published {
			continue
		}
		entry := registryAgent{
			Name:      a.AgentName,
			URN:       a.AgentURN,
			PublicKey: a.Ed25519PublicKey,
			TrustTier: string(a.TrustTier),
		}
		if a.KeeperID != nil {
			if keeper, err := s.keepers.GetByID(ctx, *a.KeeperID); err == nil {
				entry.KeeperName = keeper.KeeperName
			}
		}
		entries = append(entries, entry)
	}

	canonical, err := tessera_crypto.Canonicalize(entries)
	if err != nil {
		return nil, fmt.Errorf("canonicalize registry: %w", err)
	}

	var sigPtr *string
	platformKey, err := s.keys.GetByTypeAndName(ctx, domain.KeyTypePlatform, "platform")
	if err != nil {
		slog.Warn("registry: no platform key — returning unsigned", "error", err)
	} else {
		encRaw, err := base64.StdEncoding.DecodeString(platformKey.EncryptedPrivateKey)
		if err != nil {
			slog.Warn("registry: failed to decode platform key", "error", err)
		} else {
			privBytes, err := tessera_crypto.Decrypt(encRaw, s.encryptionKey)
			if err != nil {
				slog.Warn("registry: failed to decrypt platform key", "error", err)
			} else {
				sig, err := tessera_crypto.Sign(string(privBytes), canonical)
				if err != nil {
					slog.Warn("registry: failed to sign registry", "error", err)
				} else {
					sigPtr = &sig
				}
			}
		}
	}

	return map[string]any{
		"registry_version": 1,
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"agents":          entries,
		"signature":       sigPtr,
	}, nil
}
