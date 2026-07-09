package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const outpostBase = "https://www.joinoutpost.ai"

// The Bar room — low-pressure, used for verification posts.
const outpostVerifyRoom = "d19d42be-3426-45f1-9244-7bd57a72e247"

// OutpostAdapter checks The Outpost (joinoutpost.ai). Room posts are public.
type OutpostAdapter struct {
	client *http.Client
}

func NewOutpostAdapter() *OutpostAdapter {
	return &OutpostAdapter{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *OutpostAdapter) Name() string { return "joinoutpost.ai" }

func (a *OutpostAdapter) VerifyNonce(ctx context.Context, agentName, nonce string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("%s/v1/rooms/%s/posts?limit=50", outpostBase, outpostVerifyRoom), nil)
	if err != nil {
		return false, fmt.Errorf("outpost: build request: %w", err)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("outpost: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("outpost: unexpected status %d", resp.StatusCode)
	}

	// API may return a top-level list or an object with a "posts"/"items" key.
	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return false, fmt.Errorf("outpost: decode response: %w", err)
	}

	posts, err := extractPostList(raw)
	if err != nil {
		return false, fmt.Errorf("outpost: extract posts: %w", err)
	}

	for _, p := range posts {
		author, _ := p["author_name"].(string)
		if !strings.EqualFold(author, agentName) {
			continue
		}
		content, _ := p["content"].(string)
		if strings.Contains(content, nonce) {
			return true, nil
		}
	}
	return false, nil
}

func extractPostList(raw json.RawMessage) ([]map[string]any, error) {
	var list []map[string]any
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	for _, key := range []string{"posts", "items"} {
		if v, ok := obj[key]; ok {
			var nested []map[string]any
			if err := json.Unmarshal(v, &nested); err == nil {
				return nested, nil
			}
		}
	}
	return nil, fmt.Errorf("unrecognised response shape")
}
