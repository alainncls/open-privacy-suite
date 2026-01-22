package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/server"
)

func main() {
	cfg := config.Load()

	// Warn loudly if mock signatures mode is enabled
	if cfg.MockSignatures {
		log.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		log.Println("!!! WARNING: MOCK_SIGNATURES=true - Signature verification DISABLED")
		log.Println("!!! This should ONLY be used for demo recording, never in production!")
		log.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	}

	srv, err := server.New(cfg) // Migrations run automatically in db.New()
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP server for graceful shutdown
	httpServer := &http.Server{
		Addr: ":" + port,
	}

	// Channel to listen for errors from ListenAndServe
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Starting privacy proxy server on port %s", port)
		log.Printf("Node URL: %s", cfg.NodeURL)
		serverErrors <- srv.RunWithServer(httpServer)
	}()

	// Channel to listen for interrupt/terminate signals
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or server error
	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)

	case sig := <-shutdown:
		log.Printf("Received signal %v, shutting down...", sig)

		// Give outstanding requests 10 seconds to complete
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// Stop accepting new requests and wait for existing ones
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
			httpServer.Close()
		}

		// Stop background goroutines
		srv.Stop()
		log.Println("Server stopped gracefully")
	}
}
