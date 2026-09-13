package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"auditlogd/internal/merkle"
	"auditlogd/internal/signing"
	"auditlogd/internal/store"
	_ "github.com/lib/pq"
)

func main() {
	recordID := flag.String("record", "", "Audit record ID to verify")
	proofFile := flag.String("proof-file", "", "Path to proof JSON file (for independent offline verification)")
	pgURL := flag.String("postgres-url", os.Getenv("POSTGRES_URL"), "PostgreSQL connection string")
	keyfilePath := flag.String("keyfile", "keys.enc", "Path to keyfile")
	passphrase := flag.String("passphrase", "", "Passphrase to unlock keyfile")
	pubKeyHex := flag.String("pubkey", "", "Hex-encoded public key (for verification without keyfile)")
	flag.Parse()

	ctx := context.Background()

	// Mode 1: Verify using an offline proof file
	if *proofFile != "" {
		verifyOfflineProof(ctx, *proofFile, *pubKeyHex)
		return
	}

	// Mode 2: Verify record against PostgreSQL store
	if *recordID == "" {
		fmt.Fprintln(os.Stderr, "Error: either -record <id> or -proof-file <path> is required")
		flag.Usage()
		os.Exit(1)
	}

	if *pgURL == "" {
		*pgURL = "postgres://postgres:postgres@localhost:5432/auditlog?sslmode=disable"
	}

	db, err := sql.Open("postgres", *pgURL)
	if err != nil {
		log.Fatalf("Failed to open postgres connection: %v", err)
	}
	defer db.Close()

	var signer signing.Signer
	if *pubKeyHex != "" {
		pkBytes, err := hex.DecodeString(*pubKeyHex)
		if err != nil {
			log.Fatalf("Invalid hex public key: %v", err)
		}
		signer = &singlePubKeySigner{pubKey: pkBytes}
	} else if *passphrase != "" {
		km, err := signing.LoadKeyfile(*keyfilePath, *passphrase)
		if err != nil {
			log.Fatalf("Failed to unlock keyfile: %v", err)
		}
		signer = km
	} else {
		log.Fatalf("Verification requires either -pubkey <hex> or -passphrase <pass> to verify signature")
	}

	pgStore := store.NewPostgresStore(db)
	verifier := merkle.NewRecordVerifier(pgStore, signer)

	fmt.Printf("Cryptographically verifying record %s...\n", *recordID)
	result, err := verifier.VerifyRecord(ctx, *recordID)
	if err != nil {
		log.Fatalf("Verification process failed: %v", err)
	}

	printResult(result)
}

func verifyOfflineProof(ctx context.Context, path string, pubKeyHex string) {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read proof file: %v", err)
	}

	type ProofDoc struct {
		RecordCanonical merkle.RecordCanonicalPayload `json:"record"`
		Proof           []merkle.ProofNode            `json:"proof"`
		MerkleRootHex   string                        `json:"merkle_root_hex"`
		SignatureHex    string                        `json:"signature_hex"`
		KeyVersion      string                        `json:"key_version"`
		PublicKeyHex    string                        `json:"public_key_hex,omitempty"`
	}

	var doc ProofDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Fatalf("Failed to parse proof document: %v", err)
	}

	pkToUse := pubKeyHex
	if pkToUse == "" {
		pkToUse = doc.PublicKeyHex
	}
	if pkToUse == "" {
		log.Fatalf("Public key must be provided either in proof file or via -pubkey flag")
	}

	pubBytes, err := hex.DecodeString(pkToUse)
	if err != nil {
		log.Fatalf("Invalid public key hex: %v", err)
	}
	rootBytes, err := hex.DecodeString(doc.MerkleRootHex)
	if err != nil {
		log.Fatalf("Invalid root hex: %v", err)
	}
	sigBytes, err := hex.DecodeString(doc.SignatureHex)
	if err != nil {
		log.Fatalf("Invalid signature hex: %v", err)
	}

	signer := &singlePubKeySigner{pubKey: pubBytes}
	sigValid, err := signer.Verify(ctx, rootBytes, sigBytes, doc.KeyVersion)
	if err != nil || !sigValid {
		fmt.Printf("FAILED: Digital signature is INVALID against public key %s\n", pkToUse)
		os.Exit(1)
	}

	leafHash, err := merkle.ComputeRecordLeafHash(doc.RecordCanonical)
	if err != nil {
		log.Fatalf("Failed to compute leaf hash: %v", err)
	}

	proofValid := merkle.VerifyProof(leafHash, doc.Proof, rootBytes)
	if !proofValid {
		fmt.Println("FAILED: Merkle authentication path does NOT lead to the signed root.")
		os.Exit(1)
	}

	fmt.Println("SUCCESS: Record is mathematically authentic and signed!")
	fmt.Printf("Record ID:       %s\n", doc.RecordCanonical.ID)
	fmt.Printf("Batch Root:      %s\n", doc.MerkleRootHex)
	fmt.Printf("Signature:       %s\n", doc.SignatureHex)
	fmt.Printf("Public Key:      %s\n", pkToUse)
}

func printResult(res merkle.VerificationResult) {
	if res.Valid {
		fmt.Println("==================================================")
		fmt.Println("  RESULT: RECORD AUTHENTIC & UNTAMPERED (VALID)   ")
		fmt.Println("==================================================")
		fmt.Printf("Record ID:       %s\n", res.RecordID)
		fmt.Printf("Batch ID:        %s\n", res.BatchID)
		fmt.Printf("Merkle Root:     %s\n", res.MerkleRootHex)
		fmt.Printf("Signature:       %s\n", res.SignatureHex)
		fmt.Printf("Key Version:     %s\n", res.KeyVersion)
		fmt.Printf("Verified At:     %s\n", res.VerifiedAt.Format("2006-01-02 15:04:05 UTC"))
	} else {
		fmt.Println("==================================================")
		fmt.Println("  RESULT: VERIFICATION FAILED (INVALID)          ")
		fmt.Println("==================================================")
		fmt.Printf("Record ID:       %s\n", res.RecordID)
		fmt.Printf("Batch ID:        %s\n", res.BatchID)
		fmt.Printf("Failure Reason:  %s\n", res.FailureReason)
		os.Exit(1)
	}
}

type singlePubKeySigner struct {
	pubKey []byte
}

func (s *singlePubKeySigner) Sign(ctx context.Context, digest []byte) ([]byte, string, error) {
	return nil, "", fmt.Errorf("read-only verifier cannot sign")
}

func (s *singlePubKeySigner) Verify(ctx context.Context, digest, signature []byte, keyVersion string) (bool, error) {
	if len(s.pubKey) != 32 || len(signature) != 64 {
		return false, fmt.Errorf("invalid ed25519 key or signature size")
	}
	return ed25519.Verify(s.pubKey, digest, signature), nil
}

func (s *singlePubKeySigner) PublicKey(ctx context.Context, keyVersion string) ([]byte, error) {
	return s.pubKey, nil
}
