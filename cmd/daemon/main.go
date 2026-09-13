package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"auditlogd/internal/alerting"
	"auditlogd/internal/archive"
	"auditlogd/internal/attribution"
	"auditlogd/internal/batch"
	"auditlogd/internal/binlog"
	"auditlogd/internal/bootstrap"
	"auditlogd/internal/config"
	"auditlogd/internal/pipeline"
	"auditlogd/internal/snapshot"
	"auditlogd/internal/source"
	"auditlogd/internal/store"
	"auditlogd/internal/signing"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func main() {
	mysqlHost := flag.String("mysql-host", envOrDefault("MYSQL_HOST", "127.0.0.1"), "MySQL host")
	mysqlPort := flag.Int("mysql-port", 3306, "MySQL port")
	mysqlUser := flag.String("mysql-user", envOrDefault("MYSQL_USER", "root"), "MySQL replication user")
	mysqlPass := flag.String("mysql-pass", envOrDefault("MYSQL_PASSWORD", "root"), "MySQL password")
	mysqlDBName := flag.String("mysql-db", envOrDefault("MYSQL_DATABASE", "app"), "Audited database name")
	mysqlServerID := flag.Uint("mysql-server-id", 1001, "Replication slave server ID")

	pgURL := flag.String("postgres-url", envOrDefault("POSTGRES_URL", "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable"), "Postgres hot store connection string")
	wormDir := flag.String("worm-dir", envOrDefault("WORM_DIR", "./worm-storage"), "WORM local write-once directory")
	keyfilePath := flag.String("keyfile", envOrDefault("KEYFILE_PATH", "keys.enc"), "Encrypted keyfile path")
	passphrase := flag.String("passphrase", envOrDefault("KEYFILE_PASSPHRASE", ""), "Keyfile unlock passphrase")
	webhookURL := flag.String("webhook-url", envOrDefault("ALERT_WEBHOOK_URL", ""), "Discord/Telegram alert webhook")

	batchInterval := flag.Duration("batch-interval", 60*time.Second, "Max batch interval")
	batchMaxEvents := flag.Int("batch-max-events", 5000, "Max batch events before flush")
	flag.Parse()

	log.Println("Starting Global Audit Logger (auditlogd)...")

	// 1. Load or initialize encrypted keyfile
	if *passphrase == "" {
		*passphrase = "dev-insecure-passphrase"
	}
	keyMgr, err := signing.LoadKeyfile(*keyfilePath, *passphrase)
	if err != nil {
		log.Printf("Keyfile not found or unlock failed (%v). Creating initial dev keyfile at %s...", err, *keyfilePath)
		keyMgr, err = signing.GenerateAndSaveKeyfile(*keyfilePath, *passphrase, "v1")
		if err != nil {
			log.Fatalf("Failed to initialize keyfile: %v", err)
		}
	}
	pubKey, _ := keyMgr.PublicKey(context.Background(), "")
	log.Printf("Loaded signing key (version: %s, public key: %x)", keyMgr.CurrentVersion(), pubKey)

	// 2. Initialize WORM archive directory
	archStore, err := archive.NewLocalDirArchiveStore(*wormDir)
	if err != nil {
		log.Fatalf("Failed to initialize WORM archive directory: %v", err)
	}

	// 3. Connect to Postgres hot store
	pgDB, err := sql.Open("postgres", *pgURL)
	if err != nil {
		log.Fatalf("Failed to open Postgres connection: %v", err)
	}
	defer pgDB.Close()
	pgStore := store.NewPostgresStore(pgDB)

	// 4. Retrieve latest checkpoint from Postgres
	lastFile, lastPos, err := pgStore.GetLatestCheckpoint(context.Background())
	if err != nil {
		log.Fatalf("Failed to query latest checkpoint: %v", err)
	}
	if lastFile != "" {
		log.Printf("Resuming binlog consumption from checkpoint %s:%d", lastFile, lastPos)
	} else {
		log.Println("No previous checkpoint found. Starting from current binlog head.")
	}

	// 5. Connect to MySQL database
	mysqlDSN := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true",
		*mysqlUser, *mysqlPass, *mysqlHost, *mysqlPort, *mysqlDBName)
	mysqlDB, err := sql.Open("mysql", mysqlDSN)
	if err != nil {
		log.Fatalf("Failed to open MySQL connection: %v", err)
	}
	defer mysqlDB.Close()

	// 6. Setup Config Manager and load _audit_config
	cfgMgr := config.NewManager()
	if err := cfgMgr.LoadFromDB(context.Background(), mysqlDB); err != nil {
		log.Printf("Warning: failed to load _audit_config from MySQL: %v", err)
	} else {
		log.Printf("Loaded %d audited table configuration(s)", len(cfgMgr.GetAllConfigs()))
	}

	// 7. Setup Alerting Dispatcher
	var sinks []alerting.AlertSink
	if *webhookURL != "" {
		sinks = append(sinks, alerting.NewWebhookSink(*webhookURL))
	}
	dispatcher := alerting.NewDispatcher(5*time.Minute, sinks...)

	// 8. Setup Batcher
	batcher := batch.NewBatcher(
		batch.Config{
			MaxInterval: *batchInterval,
			MaxEvents:   *batchMaxEvents,
		},
		keyMgr,
		pgStore,
		archStore,
		dispatcher,
	)

	// 9. Check for tables requiring bootstrap
	snapBuilder := snapshot.NewBuilder(keyMgr)
	bootRunner := bootstrap.NewRunner(mysqlDB, cfgMgr, snapBuilder, batcher, dispatcher)
	for _, tbl := range cfgMgr.GetAllConfigs() {
		if tbl.Enabled && tbl.BootstrapRequired && tbl.BootstrapStatus == "not_started" {
			log.Printf("Table %s requires bootstrap snapshot. Executing...", tbl.TableName)
			if err := bootRunner.BootstrapTable(context.Background(), tbl.TableName); err != nil {
				log.Printf("Error bootstrapping table %s: %v", tbl.TableName, err)
			}
		}
	}

	// 10. Initialize CDC Binlog Source
	cdcSource := binlog.NewMySQLBinlogSource(binlog.Config{
		Host:     *mysqlHost,
		Port:     uint16(*mysqlPort),
		User:     *mysqlUser,
		Password: *mysqlPass,
		ServerID: uint32(*mysqlServerID),
		Flavor:   "mysql",
	})
	if lastFile != "" {
		_ = cdcSource.ResumeFrom(source.Position{File: lastFile, Position: lastPos})
	}

	// 11. Assemble Pipeline
	correlator := attribution.NewCorrelator(cfgMgr)
	pipe := pipeline.NewPipeline(cdcSource, cfgMgr, correlator, snapBuilder, batcher, dispatcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v. Flusing batch and shutting down...", sig)
		cancel()
	}()

	log.Println("Audit daemon running and processing CDC stream...")
	if err := pipe.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Daemon run exited with error: %v", err)
	}

	log.Println("Daemon gracefully stopped.")
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
