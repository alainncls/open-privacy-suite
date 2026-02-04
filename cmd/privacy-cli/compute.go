package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"privacy-proxy/internal/evm/create3"
)

func runComputeAddress(cmd *flag.FlagSet, args []string) {
	// Define flags
	factory := cmd.String("factory", "", "CREATE3 factory address (required)")
	salt := cmd.String("salt", "", "Salt value (hex string, required)")
	deployer := cmd.String("deployer", "", "Deployer address (optional, for info only)")
	configPath := cmd.String("config", "", "Path to privacy.toml config file")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Load configuration for factory address if not provided
	if *factory == "" {
		cfg, err := LoadConfig(*configPath)
		if err == nil && cfg.Factory.Address != "" {
			*factory = cfg.Factory.Address
		}
	}

	// Validate required flags
	if *factory == "" {
		fmt.Fprintln(os.Stderr, "Error: --factory is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli compute-address --factory <address> --salt <hex> [options]")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	if *salt == "" {
		fmt.Fprintln(os.Stderr, "Error: --salt is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli compute-address --factory <address> --salt <hex> [options]")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	// Normalize factory address
	factoryAddr := *factory
	if !strings.HasPrefix(factoryAddr, "0x") {
		factoryAddr = "0x" + factoryAddr
	}

	// Normalize salt
	saltHex := *salt
	if !strings.HasPrefix(saltHex, "0x") {
		saltHex = "0x" + saltHex
	}

	// Compute the CREATE3 address
	address, err := create3.CalculateCREATE3AddressFromHex(factoryAddr, saltHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error computing address: %v\n", err)
		os.Exit(1)
	}

	// Output results
	fmt.Println("CREATE3 Address Computation")
	fmt.Println("===========================")
	fmt.Printf("Factory:  %s\n", factoryAddr)
	fmt.Printf("Salt:     %s\n", saltHex)
	if *deployer != "" {
		fmt.Printf("Deployer: %s\n", *deployer)
	}
	fmt.Println()
	fmt.Printf("Computed Address: %s\n", strings.ToLower(address.Hex()))
}
