package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
)

// InitiateClaim allows a keeper to claim an unclaimed agent by name.
func (s *TesseraService) InitiateClaim(ctx context.Context, keeperID uuid.UUID, agentName, keeperStatement string) (*domain.ClaimRequest, error) {
	agent, err := s.agents.GetByName(ctx, agentName)
	if err != nil {
		return nil, fmt.Errorf("agent not found: %w", err)
	}
	if agent.KeeperID != nil {
		return nil, fmt.Errorf("agent %q already has a keeper", agentName)
	}

	// C1: reject if a pending claim already exists for this agent
	pending, err := s.claims.GetPendingForAgent(ctx, agent.ID)
	if err != nil {
		return nil, fmt.Errorf("check pending claims: %w", err)
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("agent already has a pending claim")
	}

	now := time.Now()
	claim := &domain.ClaimRequest{
		ID:              uuid.New(),
		KeeperID:        keeperID,
		AgentName:       agentName,
		AgentID:         &agent.ID,
		KeeperStatement: keeperStatement,
		Status:          domain.ClaimPending,
		CreatedAt:       now,
	}
	if err := s.claims.Create(ctx, claim); err != nil {
		return nil, fmt.Errorf("create claim: %w", err)
	}

	payload, _ := json.Marshal(map[string]string{
		"claim_id":  claim.ID.String(),
		"keeper_id": keeperID.String(),
	})
	entry := &domain.AttestationEntry{
		AgentID:   agent.ID,
		EntryType: domain.EntryKeeperClaimed,
		Attester:  "keeper:" + keeperID.String(),
		Payload:   payload,
		CreatedAt: now,
	}
	if err := s.chain.Append(ctx, entry); err != nil {
		return nil, fmt.Errorf("append chain entry: %w", err)
	}

	return claim, nil
}

// ResolveClaim accepts or rejects a pending keeper claim on behalf of the agent.
// Only the agent (matched by agentID) can resolve their own claims.
func (s *TesseraService) ResolveClaim(ctx context.Context, claimID uuid.UUID, agentID uuid.UUID, status domain.ClaimStatus) (*domain.ClaimRequest, error) {
	claim, err := s.claims.GetByID(ctx, claimID)
	if err != nil {
		return nil, fmt.Errorf("claim not found: %w", err)
	}
	if claim.AgentID == nil || *claim.AgentID != agentID {
		return nil, fmt.Errorf("claim does not belong to this agent")
	}
	if claim.Status != domain.ClaimPending {
		return nil, fmt.Errorf("claim is already resolved")
	}

	now := time.Now()
	var entry *domain.AttestationEntry
	if status == domain.ClaimAccepted {
		payload, _ := json.Marshal(map[string]string{
			"claim_id":  claimID.String(),
			"keeper_id": claim.KeeperID.String(),
		})
		entry = &domain.AttestationEntry{
			AgentID:   agentID,
			EntryType: domain.EntryKeeperClaimAccepted,
			Attester:  "agent:" + agentID.String(),
			Payload:   payload,
			CreatedAt: now,
		}
	}

	if err := s.claims.ResolveClaimTx(ctx, claimID, agentID, claim.KeeperID, status, entry); err != nil {
		return nil, fmt.Errorf("resolve claim: %w", err)
	}

	claim.Status = status
	claim.ResolvedAt = &now
	return claim, nil
}

// GetClaimsSent returns all claims sent by the given keeper.
func (s *TesseraService) GetClaimsSent(ctx context.Context, keeperID uuid.UUID) ([]domain.ClaimRequest, error) {
	return s.claims.GetSentByKeeper(ctx, keeperID)
}
