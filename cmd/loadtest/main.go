// Package main implements a load testing tool for the privacy proxy.
// It deploys DeFi contracts, authenticates multiple accounts, and sends
// signed transactions at high throughput via eth_sendRawTransaction.
//
// The proxy validates transactions using runtime tracing (debug_traceCall)
// to ensure cross-org isolation before forwarding to the node.
//
// Requirements:
//   - Privacy proxy with ENABLE_RUNTIME_TRACING=true
//   - Node with eth_sendRawTransaction and debug_traceCall support
//
// Usage:
//
//	go run ./cmd/loadtest --proxy-url http://localhost:8080 \
//	  --node-url http://localhost:8545 \
//	  --funding-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
//	  --accounts 10 --duration 60s
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Config struct {
	// URLs
	ProxyURL string
	NodeURL  string

	// Funding
	FundingKey string

	// Test parameters
	NumAccounts    int
	Duration       time.Duration
	MaxPoolSize    int
	VerifyReceipts bool

	// Contract deployment
	SkipSetup bool

	// Direct mode - bypass proxy, send directly to node
	Direct bool
}

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.ProxyURL, "proxy-url", "http://localhost:8080", "Privacy proxy URL")
	flag.StringVar(&cfg.NodeURL, "node-url", "http://localhost:62644", "Direct node URL (for funding and pool monitoring)")
	flag.StringVar(&cfg.FundingKey, "funding-key", "", "Private key for funding accounts (hex, with or without 0x prefix)")
	flag.IntVar(&cfg.NumAccounts, "accounts", 10, "Number of test accounts")
	flag.DurationVar(&cfg.Duration, "duration", 60*time.Second, "Load test duration")
	flag.IntVar(&cfg.MaxPoolSize, "max-pool", 10000, "Max txpool size before throttling")
	flag.BoolVar(&cfg.VerifyReceipts, "verify", false, "Wait for receipts to verify txs succeed (slower, for debugging)")
	flag.BoolVar(&cfg.SkipSetup, "skip-setup", false, "Skip setup phase (use existing contracts)")
	flag.BoolVar(&cfg.Direct, "direct", false, "Direct mode - send txs directly to node, bypass proxy")
	flag.Parse()

	if cfg.FundingKey == "" {
		log.Fatal("--funding-key is required")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nReceived shutdown signal, stopping...")
		cancel()
	}()

	// Initialize load tester
	lt, err := NewLoadTester(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize load tester: %v", err)
	}

	// Phase 1: Setup
	if !cfg.SkipSetup {
		fmt.Println("=== Phase 1: Setup ===")
		if err := lt.Setup(ctx); err != nil {
			log.Fatalf("Setup failed: %v", err)
		}
		fmt.Println("Setup complete!")
		fmt.Println()
	}

	// Phase 2: Load Test
	fmt.Println("=== Phase 2: Load Test ===")
	fmt.Printf("Duration: %v, Accounts: %d, Max Pool: %d\n", cfg.Duration, cfg.NumAccounts, cfg.MaxPoolSize)
	fmt.Println()

	if err := lt.Run(ctx); err != nil {
		log.Fatalf("Load test failed: %v", err)
	}

	// Print results
	lt.PrintResults()
}
