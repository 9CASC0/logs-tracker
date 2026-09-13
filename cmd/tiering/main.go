package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/store"
	"auditlogd/internal/tiering"
	_ "github.com/lib/pq"
)

func main() {
	pgURL := flag.String("postgres-url", os.Getenv("POSTGRES_URL"), "PostgreSQL connection URL")
	wormDir := flag.String("worm-dir", os.Getenv("WORM_DIR"), "WORM storage directory")
	webhookURL := flag.String("webhook-url", os.Getenv("ALERT_WEBHOOK_URL"), "Discord/Telegram alert webhook URL")
	days := flag.Int("retention-days", 90, "Retention window in days")
	flag.Parse()

	if *pgURL == "" {
		*pgURL = "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable"
	}
	if *wormDir == "" {
		*wormDir = "./worm-storage"
	}

	db, err := sql.Open("postgres", *pgURL)
	if err != nil {
		log.Fatalf("Failed to open postgres: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Printf("Warning: failed to ping postgres: %v", err)
	}

	archStore, err := archive.NewLocalDirArchiveStore(*wormDir)
	if err != nil {
		log.Fatalf("Failed to initialize archive store: %v", err)
	}

	pgStore := store.NewPostgresStore(db)

	var sinks []alerting.AlertSink
	if *webhookURL != "" {
		sinks = append(sinks, alerting.NewWebhookSink(*webhookURL))
	}
	dispatcher := alerting.NewDispatcher(5*time.Minute, sinks...)

	service := tiering.NewService(
		tiering.Config{
			RetentionWindow: time.Duration(*days) * 24 * time.Hour,
		},
		pgStore,
		archStore,
		dispatcher,
	)

	log.Printf("Starting retention tiering job (retention window: %d days, WORM dir: %s)...", *days, *wormDir)
	ctx := context.Background()
	res, err := service.RunOnce(ctx)
	if err != nil {
		log.Fatalf("Retention tiering run failed: %v", err)
	}

	fmt.Printf("Tiering run complete: %d batches tiered, %d records purged. Errors: %d\n",
		res.BatchesTiered, res.RecordsPurged, len(res.Errors))
	if len(res.Errors) > 0 {
		os.Exit(1)
	}
}
