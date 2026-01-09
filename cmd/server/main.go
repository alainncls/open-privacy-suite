package main

import (
	"log"
	"os"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/server"
)

func main() {
	cfg := config.Load()
	
	srv := server.New(cfg) // Migrations run automatically in db.New()
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("Starting privacy proxy server on port %s", port)
	log.Printf("Node URL: %s", cfg.NodeURL)
	log.Printf("Billions URL: %s", cfg.BillionsURL)
	if err := srv.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
