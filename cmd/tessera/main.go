package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/looselyhuman/tessera/config"
	"github.com/looselyhuman/tessera/internal/handler"
	"github.com/looselyhuman/tessera/internal/platform"
	"github.com/looselyhuman/tessera/internal/ratelimit"
	"github.com/looselyhuman/tessera/internal/service"
	"github.com/looselyhuman/tessera/internal/store/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()

	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer pool.Close()

	// Decode TESSERA_KEY_SECRET (must be base64-encoded 32-byte AES-256 key).
	encryptionKey, err := base64.StdEncoding.DecodeString(cfg.KeySecret)
	if err != nil {
		log.Fatalf("decode TESSERA_KEY_SECRET (must be base64): %v", err)
	}
	if len(encryptionKey) != 32 {
		log.Fatalf("TESSERA_KEY_SECRET must decode to exactly 32 bytes (got %d)", len(encryptionKey))
	}

	// Wire up stores.
	agents := postgres.NewAgentStore(pool)
	keepers := postgres.NewKeeperStore(pool)
	keys := postgres.NewKeyStore(pool)
	chain := postgres.NewAttestationStore(pool)
	claims := postgres.NewClaimStore(pool)
	platforms := postgres.NewPlatformRegistrationStore(pool)
	transitions := postgres.NewSubstrateTransitionStore(pool)
	revocations := postgres.NewRevocationStore(pool)
	modifications := postgres.NewModificationRequestStore(pool)
	sessions := postgres.NewRegistrationSessionStore(pool)

	// Wire up platform adapters.
	adapters := map[string]platform.Adapter{
		"jointhecommons.space": platform.NewCommonsAdapter(),
		"joinoutpost.ai":       platform.NewOutpostAdapter(),
	}
	if cfg.DiscordBotToken != "" && cfg.DiscordChannelID != "" {
		adapters["discord"] = platform.NewDiscordAdapter(cfg.DiscordBotToken, cfg.DiscordChannelID)
	}

	// Wire up service.
	svc := service.NewTesseraService(service.ServiceConfig{
		Agents:           agents,
		Keepers:          keepers,
		Keys:             keys,
		Chain:            chain,
		Claims:           claims,
		Platforms:        platforms,
		Transitions:      transitions,
		Revocations:      revocations,
		Modifications:    modifications,
		Sessions:         sessions,
		PlatformAdapters: adapters,
		HomeDomain:       cfg.HomeDomain,
		InternalKey:      cfg.InternalRegKey,
		EncryptionKey:    encryptionKey,
	})

	// Wire up HTTP handlers.
	mux := http.NewServeMux()
	h := handler.New(handler.HandlerConfig{
		Svc:              svc,
		AdminKey:         cfg.AdminKey,
		ServiceTokens:    cfg.ServiceTokens,
		DiscoveryLimiter:       ratelimit.New(cfg.RateLimitDiscovery),
		ChallengeLimiter:       ratelimit.New(cfg.RateLimitChallenge),
		ChallengeVerifyLimiter: ratelimit.New(cfg.RateLimitChallengeVerify),
		PublicLimiter:          ratelimit.New(cfg.RateLimitPublic),
	})
	handler.Register(mux, h)

	// Session pruning goroutine — runs every 5 minutes.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := sessions.PruneExpired(context.Background()); err != nil {
				log.Printf("prune sessions: %v", err)
			}
		}
	}()

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGTERM/SIGINT.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("tessera listening on %s (domain: %s)", cfg.ListenAddr, cfg.HomeDomain)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
