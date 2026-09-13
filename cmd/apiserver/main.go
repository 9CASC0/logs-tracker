package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"auditlogd/internal/alerting"
	"auditlogd/internal/api"
	"auditlogd/internal/config"
	"auditlogd/internal/merkle"
	"auditlogd/internal/signing"
	"auditlogd/internal/store"
	_ "github.com/lib/pq"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	pgURL := flag.String("postgres-url", os.Getenv("POSTGRES_URL"), "PostgreSQL connection URL")
	keyfilePath := flag.String("keyfile", os.Getenv("KEYFILE_PATH"), "Path to encrypted keyfile")
	passphrase := flag.String("passphrase", os.Getenv("KEYFILE_PASSPHRASE"), "Passphrase to unlock keyfile")
	adminToken := flag.String("admin-token", os.Getenv("ADMIN_TOKEN"), "Admin bearer token")
	appToken := flag.String("app-token", os.Getenv("APP_TOKEN"), "App service bearer token")
	flag.Parse()

	if *pgURL == "" {
		*pgURL = "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable"
	}
	if *keyfilePath == "" {
		*keyfilePath = "keys.enc"
	}
	if *adminToken == "" {
		*adminToken = "admin-secret-token"
	}
	if *appToken == "" {
		*appToken = "app-service-token"
	}

	keyMgr, err := signing.LoadKeyfile(*keyfilePath, *passphrase)
	if err != nil {
		log.Printf("Warning: failed to load keyfile (%v); continuing with mock key for read operations", err)
		keyMgr, _ = signing.GenerateAndSaveKeyfile("keys.tmp.enc", "temporary-pass", "v1")
	}

	db, err := sql.Open("postgres", *pgURL)
	if err != nil {
		log.Fatalf("Failed to open postgres: %v", err)
	}
	defer db.Close()

	pgStore := store.NewPostgresStore(db)
	cfgMgr := config.NewManager()
	verifier := merkle.NewRecordVerifier(pgStore, keyMgr)
	memSink := alerting.NewMemorySink()

	handler := api.NewHandler(pgStore, cfgMgr, verifier, keyMgr, keyMgr, memSink)

	validator := api.NewStaticTokenValidator(map[string][]api.Permission{
		*adminToken: api.RolePermissions["admin"],
		*appToken:   api.RolePermissions["app_service"],
	})

	server := api.NewServer(handler, validator)

	fmt.Printf("Audit Log API server listening on %s...\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, server.Handler()))
}
