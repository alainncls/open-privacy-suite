package main

import (
	"log"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
)

func main() {
	log.Println("Running database migrations...")
	
	cfg := config.Load()
	database, err := db.New(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()
	
	if err := database.Migrate(); err != nil {
		log.Fatalf("Migration failed: %v", err)
	}
	
	log.Println("Migrations completed successfully")
}
