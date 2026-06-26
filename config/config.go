package config

import (
	"fmt"
	"os"
)

// Config holds all environment-driven configuration for the Tessera service.
type Config struct {
	DatabaseURL    string // TESSERA_DATABASE_URL
	ListenAddr     string // TESSERA_LISTEN_ADDR (default :8080)
	HomeDomain     string // TESSERA_HOME_DOMAIN (default athena-council.org)
	KeySecret      string // TESSERA_KEY_SECRET (AES key for private key encryption, base64)
	InternalRegKey string // TESSERA_INTERNAL_REG_KEY (bypass key for challenge flow in QA/dev)
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:    os.Getenv("TESSERA_DATABASE_URL"),
		ListenAddr:     envOrDefault("TESSERA_LISTEN_ADDR", ":8080"),
		HomeDomain:     envOrDefault("TESSERA_HOME_DOMAIN", "athena-council.org"),
		KeySecret:      os.Getenv("TESSERA_KEY_SECRET"),
		InternalRegKey: os.Getenv("TESSERA_INTERNAL_REG_KEY"),
	}

	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("TESSERA_DATABASE_URL is required")
	}
	if cfg.KeySecret == "" {
		return nil, fmt.Errorf("TESSERA_KEY_SECRET is required")
	}

	return cfg, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
