package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	tessera_crypto "github.com/looselyhuman/tessera/internal/crypto"
)

// ChainEntryVerification is the verification result for a single attestation chain entry.
type ChainEntryVerification struct {
	EntryID   int    `json:"entry_id"`
	EntryType string `json:"entry_type"`
	Attester  string `json:"attester"`
	Checked   bool   `json:"checked"`
	Valid     bool   `json:"valid,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ChainVerificationReport summarizes integrity verification for an agent's attestation chain.
type ChainVerificationReport struct {
	AgentID     string                   `json:"agent_id"`
	TotalCount  int                      `json:"total_count"`
	SignedCount int                      `json:"signed_count"`
	ValidCount  int                      `json:"valid_count"`
	Entries     []ChainEntryVerification `json:"entries"`
}

// VerifyChainIntegrity reads an agent's attestation chain and verifies each signed entry.
// Entries whose attester is a keeper are verified against the keeper's public key.
// Entries with no signature or an unresolvable attester type are reported but not checked.
func (s *TesseraService) VerifyChainIntegrity(ctx context.Context, agentID uuid.UUID) (*ChainVerificationReport, error) {
	entries, err := s.chain.GetByAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("get chain: %w", err)
	}

	report := &ChainVerificationReport{
		AgentID:    agentID.String(),
		TotalCount: len(entries),
		Entries:    make([]ChainEntryVerification, 0, len(entries)),
	}

	for _, e := range entries {
		ev := ChainEntryVerification{
			EntryID:   e.ID,
			EntryType: string(e.EntryType),
			Attester:  e.Attester,
		}

		if e.Signature == "" || len(e.Payload) == 0 {
			report.Entries = append(report.Entries, ev)
			continue
		}

		pubKey, resolveErr := s.resolveAttesterPubKey(ctx, e.Attester)
		if resolveErr != nil {
			ev.Checked = true
			ev.Error = fmt.Sprintf("resolve attester: %v", resolveErr)
			report.SignedCount++
			report.Entries = append(report.Entries, ev)
			continue
		}
		if pubKey == "" {
			// Attester type (admin, agora, agent self) has no registered public key.
			report.Entries = append(report.Entries, ev)
			continue
		}

		canonical, err := tessera_crypto.Canonicalize(e.Payload)
		if err != nil {
			ev.Checked = true
			ev.Error = fmt.Sprintf("canonicalize payload: %v", err)
			report.SignedCount++
			report.Entries = append(report.Entries, ev)
			continue
		}

		ok, err := tessera_crypto.Verify(pubKey, canonical, e.Signature)
		ev.Checked = true
		report.SignedCount++
		if err != nil {
			ev.Error = fmt.Sprintf("verify: %v", err)
		} else if !ok {
			ev.Error = "signature mismatch"
		} else {
			ev.Valid = true
			report.ValidCount++
		}
		report.Entries = append(report.Entries, ev)
	}

	return report, nil
}

// resolveAttesterPubKey returns the Ed25519 public key for the named attester.
// Only keeper attesters are resolvable; returns "" for other types.
func (s *TesseraService) resolveAttesterPubKey(ctx context.Context, attester string) (string, error) {
	if !strings.HasPrefix(attester, "keeper:") {
		return "", nil
	}
	keeperIDStr := strings.TrimPrefix(attester, "keeper:")
	keeperID, err := uuid.Parse(keeperIDStr)
	if err != nil {
		return "", fmt.Errorf("parse keeper UUID %q: %w", keeperIDStr, err)
	}
	keeper, err := s.keepers.GetByID(ctx, keeperID)
	if err != nil {
		return "", fmt.Errorf("get keeper %s: %w", keeperID, err)
	}
	return keeper.PublicKey, nil
}
