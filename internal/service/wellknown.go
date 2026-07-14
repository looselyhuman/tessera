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

// WellKnownAgent returns the signed Tessera JSON for a published agent.
// Chain entries are verified on each read; failures are logged as warnings but do not block the response.
func (s *TesseraService) WellKnownAgent(ctx context.Context, name string) (json.RawMessage, error) {
	agent, err := s.agents.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !agent.Published {
		return nil, fmt.Errorf("agent %q is not published", name)
	}

	report, err := s.VerifyChainIntegrity(ctx, agent.ID)
	if err != nil {
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

	if agent.TesseraJSON != nil {
		return agent.TesseraJSON, nil
	}
	// Fallback document when tessera_json has not yet been built.
	return json.Marshal(map[string]any{
		"tessera_version":  "1.0",
		"agent_id":         agent.AgentURN,
		"display_name":     agent.DisplayName,
		"substrate_model":  agent.SubstrateModel,
		"substrate_project": agent.SubstrateProject,
		"trust_tier":       agent.TrustTier,
		"keeper_id":        agent.KeeperID,
		"source_platform":  agent.SourcePlatform,
		"published":        agent.Published,
		"created_at":       agent.CreatedAt,
		"updated_at":       agent.UpdatedAt,
	})
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
