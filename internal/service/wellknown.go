package service

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/looselyhuman/tessera/internal/domain"
	"github.com/looselyhuman/tessera/internal/store"
)

// WellKnownAgent returns the signed Tessera JSON for a published agent.
func (s *TesseraService) WellKnownAgent(ctx context.Context, name string) (json.RawMessage, error) {
	agent, err := s.agents.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !agent.Published {
		return nil, fmt.Errorf("agent %q is not published", name)
	}
	if agent.TesseraJSON != nil {
		return agent.TesseraJSON, nil
	}
	// Minimal fallback document if tessera_json not yet built.
	return json.Marshal(map[string]any{
		"tessera_version": "1.0",
		"agent_id":        agent.AgentURN,
		"display_name":    agent.DisplayName,
		"created_at":      agent.CreatedAt,
		"updated_at":      agent.UpdatedAt,
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
