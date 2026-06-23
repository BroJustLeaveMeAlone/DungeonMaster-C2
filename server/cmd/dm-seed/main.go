package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/BroJustLeaveMeAlone/C2-Adversary/server/internal/db"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	username := flag.String("username", "admin", "operator username")
	password := flag.String("password", "", "operator password (required)")
	role     := flag.String("role", "operator", "operator role: operator | admin")
	flag.Parse()

	if *password == "" {
		fmt.Fprintln(os.Stderr, "error: -password is required")
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	if err := db.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "db init: %v\n", err)
		os.Exit(1)
	}
	defer db.Pool.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bcrypt: %v\n", err)
		os.Exit(1)
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "DungeonMaster",
		AccountName: *username,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "totp generate: %v\n", err)
		os.Exit(1)
	}

	var id string
	err = db.Pool.QueryRow(ctx,
		`INSERT INTO operators (username, password_hash, totp_secret, role)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (username) DO UPDATE
		   SET password_hash = EXCLUDED.password_hash,
		       totp_secret   = EXCLUDED.totp_secret,
		       role          = EXCLUDED.role,
		       is_active     = TRUE
		 RETURNING id`,
		*username, string(hash), key.Secret(), *role,
	).Scan(&id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "insert operator: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("operator created\n")
	fmt.Printf("  id:       %s\n", id)
	fmt.Printf("  username: %s\n", *username)
	fmt.Printf("  role:     %s\n", *role)
	fmt.Printf("\nScan this URI into your authenticator app:\n\n  %s\n\n", key.URL())
	fmt.Printf("TOTP secret (manual entry): %s\n", key.Secret())
}
