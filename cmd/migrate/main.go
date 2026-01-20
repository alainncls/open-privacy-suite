package main

import (
	"context"
	"log"
	"os"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
)

func main() {
	ctx := context.Background()

	cfg := config.Load()

	// Create a temporary DB connection just for migration status
	database, err := openDBWithoutMigrate(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Check current status
	currentVersion, pending, err := database.GetMigrationStatus(ctx)
	if err != nil {
		log.Printf("Could not get migration status (may be first run): %v", err)
	} else {
		log.Printf("Current schema version: %d", currentVersion)
		log.Printf("Pending migrations: %d", pending)
	}

	if pending == 0 && err == nil {
		log.Println("Database is up to date")
		os.Exit(0)
	}

	log.Println("Running database migrations...")

	err = database.MigrateWithProgress(ctx, func(sequence int32, name, direction, _ string) {
		log.Printf("Applying migration %03d_%s (%s)...", sequence, name, direction)
	})
	if err != nil {
		log.Fatalf("Migration failed: %v", err)
	}

	// Show final status
	finalVersion, _, err := database.GetMigrationStatus(ctx)
	if err != nil {
		log.Printf("Warning: could not get final status: %v", err)
	} else {
		log.Printf("Migrations completed. Schema version: %d", finalVersion)
	}
}

// openDBWithoutMigrate opens a database connection without running migrations.
// This is used to check migration status before running them.
func openDBWithoutMigrate(databaseURL string) (*db.DB, error) {
	return db.NewWithoutMigrate(databaseURL)
}
