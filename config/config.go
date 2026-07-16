package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all environment-driven configuration for the Tessera service.
type Config struct {
	DatabaseURL    string // TESSERA_DATABASE_URL
	ListenAddr     string // TESSERA_LISTEN_ADDR (default :8080)
	HomeDomain     string // TESSERA_HOME_DOMAIN (required — the URN namespace and attestation URL base)
	KeySecret      string // TESSERA_KEY_SECRET (AES key for private key encryption, base64)
	InternalRegKey string // TESSERA_INTERNAL_REG_KEY (bypass key for challenge flow in QA/dev)
	AdminKey       string // TESSERA_ADMIN_KEY (required for admin endpoints; empty disables them)

	// Service-to-service authentication.
	// TESSERA_SERVICE_TOKENS is a comma-separated list of bearer tokens that grant
	// access to the /svc/v1/* separation API. At least one token is required for
	// the service API to be functional; an empty list disables it entirely.
	ServiceTokens []string // parsed from TESSERA_SERVICE_TOKENS

	// Rate limits (requests per minute per IP).
	RateLimitDiscovery      int // TESSERA_RATE_LIMIT_DISCOVERY       (default 120 — .well-known reads)
	RateLimitChallenge      int // TESSERA_RATE_LIMIT_CHALLENGE       (default 5   — challenge initiate, tight)
	RateLimitChallengeVerify int // TESSERA_RATE_LIMIT_CHALLENGE_VERIFY (default 10 — verify-challenge polling)
	RateLimitPublic         int // TESSERA_RATE_LIMIT_PUBLIC          (default 20  — other public endpoints)

	// Platform adapter credentials.
	CommonsAPIKey    string // TESSERA_COMMONS_API_KEY (optional override; Commons anon key is public)
	OutpostAPIKey    string // TESSERA_OUTPOST_API_KEY
	DiscordBotToken  string // TESSERA_DISCORD_BOT_TOKEN
	DiscordChannelID string // TESSERA_DISCORD_CHANNEL_ID
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:      os.Getenv("TESSERA_DATABASE_URL"),
		ListenAddr:       envOrDefault("TESSERA_LISTEN_ADDR", ":8080"),
		HomeDomain:       os.Getenv("TESSERA_HOME_DOMAIN"),
		KeySecret:        os.Getenv("TESSERA_KEY_SECRET"),
		InternalRegKey:   os.Getenv("TESSERA_INTERNAL_REG_KEY"),
		AdminKey:         os.Getenv("TESSERA_ADMIN_KEY"),
		CommonsAPIKey:    os.Getenv("TESSERA_COMMONS_API_KEY"),
		OutpostAPIKey:    os.Getenv("TESSERA_OUTPOST_API_KEY"),
		DiscordBotToken:  os.Getenv("TESSERA_DISCORD_BOT_TOKEN"),
		DiscordChannelID: os.Getenv("TESSERA_DISCORD_CHANNEL_ID"),
	}

	// Parse comma-separated service tokens; filter empty strings.
	if raw := os.Getenv("TESSERA_SERVICE_TOKENS"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if tok := strings.TrimSpace(t); tok != "" {
				cfg.ServiceTokens = append(cfg.ServiceTokens, tok)
			}
		}
	}

	cfg.RateLimitDiscovery       = envInt("TESSERA_RATE_LIMIT_DISCOVERY", 120)
	cfg.RateLimitChallenge       = envInt("TESSERA_RATE_LIMIT_CHALLENGE", 5)
	cfg.RateLimitChallengeVerify = envInt("TESSERA_RATE_LIMIT_CHALLENGE_VERIFY", 10)
	cfg.RateLimitPublic          = envInt("TESSERA_RATE_LIMIT_PUBLIC", 20)

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("TESSERA_DATABASE_URL is required")
	}
	if cfg.KeySecret == "" {
		return nil, fmt.Errorf("TESSERA_KEY_SECRET is required")
	}
	if cfg.HomeDomain == "" {
		// No default on purpose: the home domain is the URN namespace and the
		// base of every attestation URL. A silent default would mint identities
		// in someone else's namespace for anyone running this from the public repo.
		return nil, fmt.Errorf("TESSERA_HOME_DOMAIN is required (your domain — it namespaces every URN and attestation URL this service issues)")
	}

	return cfg, nil
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
