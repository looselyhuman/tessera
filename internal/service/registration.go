package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/looselyhuman/tessera/internal/domain"
)

// CheckKeeperName returns whether a keeper name is available or taken.
func (s *TesseraService) CheckKeeperName(ctx context.Context, name string) (string, error) {
	available, err := s.keepers.CheckNameAvailability(ctx, name)
	if err != nil {
		return "", err
	}
	if available {
		return "available", nil
	}
	return "taken", nil
}

// RegisterAgentFromSession registers an agent using a keeper registration session.
// The session must be a SessionKeeper type and contain a keeper_id in its payload.
// The session is deleted on success.
func (s *TesseraService) RegisterAgentFromSession(ctx context.Context, input RegisterAgentInput) (*domain.Agent, error) {
	sess, err := s.sessions.Get(ctx, input.SessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}
	if time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}
	if sess.SessionType != domain.SessionKeeper {
		return nil, fmt.Errorf("session is not a keeper registration session")
	}

	var payload map[string]any
	if err := json.Unmarshal(sess.Payload, &payload); err != nil {
		return nil, fmt.Errorf("invalid session payload: %w", err)
	}
	keeperIDStr, _ := payload["keeper_id"].(string)
	keeperID, err := uuid.Parse(keeperIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid keeper_id in session payload")
	}

	agent, err := s.RegisterAgent(ctx, keeperID, input)
	if err != nil {
		return nil, err
	}
	_ = s.sessions.Delete(ctx, input.SessionID)
	return agent, nil
}
