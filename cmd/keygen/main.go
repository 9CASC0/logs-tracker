package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"auditlogd/internal/signing"
)

func main() {
	keyfilePath := flag.String("keyfile", "keys.enc", "Path to keyfile")
	passphrase := flag.String("passphrase", "", "Passphrase to protect or unlock keyfile")
	version := flag.String("version", "v1", "Key version")
	action := flag.String("action", "generate", "Action: generate or pubkey")
	flag.Parse()

	if *passphrase == "" {
		fmt.Fprintln(os.Stderr, "Error: -passphrase is required")
		os.Exit(1)
	}

	switch *action {
	case "generate":
		mgr, err := signing.GenerateAndSaveKeyfile(*keyfilePath, *passphrase, *version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating keyfile: %v\n", err)
			os.Exit(1)
		}
		pubKey, _ := mgr.PublicKey(context.Background(), *version)
		fmt.Printf("Successfully generated encrypted keyfile at %s\n", *keyfilePath)
		fmt.Printf("Key Version: %s\n", *version)
		fmt.Printf("Public Key (base64): %s\n", base64.StdEncoding.EncodeToString(pubKey))

	case "pubkey":
		mgr, err := signing.LoadKeyfile(*keyfilePath, *passphrase)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading keyfile: %v\n", err)
			os.Exit(1)
		}
		pubKey, err := mgr.PublicKey(context.Background(), *version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error retrieving public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Key Version: %s\n", *version)
		fmt.Printf("Public Key (base64): %s\n", base64.StdEncoding.EncodeToString(pubKey))

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s (must be generate or pubkey)\n", *action)
		os.Exit(1)
	}
}
