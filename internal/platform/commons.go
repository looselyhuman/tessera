package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Supabase public anon key for jointhecommons.space (safe to commit — public by design).
const commonsAnonKey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
	".eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRmZXBoc2ZiZXJ6YWRpaGNyaGFsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg1NzAwNzIsImV4cCI6MjA4NDE0NjA3Mn0" +
	".Sn4zgpyb6jcb_VXYFeEvZ7Cg7jD0xZJgjzH0XvjM7EY"

const commonsBase = "https://dfephsfberzadihcrhal.supabase.co/rest/v1"

// CommonsAdapter checks The Commons (jointhecommons.space) via Supabase REST API.
type CommonsAdapter struct {
	client *http.Client
}

func NewCommonsAdapter() *CommonsAdapter {
	return &CommonsAdapter{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *CommonsAdapter) Name() string { return "jointhecommons.space" }

func isValidAgentName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (a *CommonsAdapter) VerifyNonce(ctx context.Context, agentName, nonce string) (bool, error) {
	if !isValidAgentName(agentName) {
		return false, fmt.Errorf("commons: invalid agent name %q", agentName)
	}

	// Check posts table first.
	found, err := a.queryTable(ctx, "posts", url.Values{
		"ai_name": []string{"eq." + agentName},
		"content": []string{"like.*" + nonce + "*"},
		"select":  []string{"created_at"},
		"limit":   []string{"1"},
	})
	if err != nil {
		return false, err
	}
	if found {
		return true, nil
	}

	// Also check postcards — agents may post the nonce via agent_create_postcard.
	// Postcards may use a different author field, so search by content only.
	return a.queryTable(ctx, "postcards", url.Values{
		"content": []string{"like.*" + nonce + "*"},
		"select":  []string{"created_at"},
		"limit":   []string{"1"},
	})
}

func (a *CommonsAdapter) queryTable(ctx context.Context, table string, params url.Values) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, commonsBase+"/"+table+"?"+params.Encode(), nil)
	if err != nil {
		return false, fmt.Errorf("commons: build request: %w", err)
	}
	req.Header.Set("apikey", commonsAnonKey)
	req.Header.Set("Authorization", "Bearer "+commonsAnonKey)

	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("commons: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("commons: unexpected status %d from %s", resp.StatusCode, table)
	}

	var rows []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return false, fmt.Errorf("commons: decode response from %s: %w", table, err)
	}
	return len(rows) > 0, nil
}
