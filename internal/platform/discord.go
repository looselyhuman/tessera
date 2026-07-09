package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const discordAPI = "https://discord.com/api/v10"

// DiscordAdapter checks a Discord channel for a nonce posted by an agent.
// agentName is matched case-insensitively against the message author's username.
type DiscordAdapter struct {
	botToken  string
	channelID string
	client    *http.Client
}

func NewDiscordAdapter(botToken, channelID string) *DiscordAdapter {
	return &DiscordAdapter{
		botToken:  botToken,
		channelID: channelID,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *DiscordAdapter) Name() string { return "discord" }

func (a *DiscordAdapter) VerifyNonce(ctx context.Context, agentName, nonce string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/channels/%s/messages?limit=100", discordAPI, a.channelID), nil)
	if err != nil {
		return false, fmt.Errorf("discord: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bot "+a.botToken)

	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("discord: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("discord: unexpected status %d", resp.StatusCode)
	}

	var messages []struct {
		Content string `json:"content"`
		Author  struct {
			Username string `json:"username"`
		} `json:"author"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		return false, fmt.Errorf("discord: decode response: %w", err)
	}

	// TODO: Match by Discord user ID when available — username matching is imprecise
	// because usernames can change and may collide. The original Python implementation
	// had the same limitation; this should be upgraded to user ID matching.
	for _, m := range messages {
		if !strings.EqualFold(m.Author.Username, agentName) {
			continue
		}
		if strings.Contains(m.Content, nonce) {
			return true, nil
		}
	}
	return false, nil
}
