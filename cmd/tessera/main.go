package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/looselyhuman/tessera/config"
	"github.com/looselyhuman/tessera/internal/handler"
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

	// Wire up service.
	svc := service.NewTesseraService(
		agents, keepers, keys, chain, claims,
		platforms, transitions, revocations, modifications, sessions,
		cfg.HomeDomain, cfg.InternalRegKey,
	)

	// Wire up HTTP handlers.
	mux := http.NewServeMux()
	h := handler.New(svc)
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
