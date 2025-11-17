package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentracore/internal/auth"
	"sentracore/internal/config"
	"sentracore/internal/db"
	"sentracore/internal/events"
	"sentracore/internal/httpserver"
	"sentracore/internal/incidents"
	"sentracore/internal/logging"
)

func main() {
	ctx := context.Background()
	logger := logging.New()

	cfg := config.Load()

	dbConn, err := db.Open(ctx, cfg.DBDSN)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer dbConn.Close()

	if err := db.RunMigrations(ctx, dbConn, "sql"); err != nil {
		log.Fatalf("run migrations: %v", err)
	}

	userStore := auth.NewStore(dbConn)
	if err := userStore.SeedFromFile(ctx, cfg.UsersPath); err != nil {
		log.Fatalf("seed users: %v", err)
	}
	authSvc := auth.NewService(userStore, cfg.JWTSecret)

	eventStore := events.NewStore(dbConn)
	incidentStore := incidents.NewStore(dbConn)

	rules, err := incidents.LoadRules(cfg.RulesPath)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}
	correlator := incidents.NewCorrelator(rules, incidentStore, eventStore, logger)

	handler := httpserver.NewRouter(logger, authSvc, eventStore, incidentStore, correlator, cfg.IngestToken)
	server := httpserver.New(cfg.HTTPAddr, handler, logger)

	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("http server: %v", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctxShutdown); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
