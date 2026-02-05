package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"privacy-proxy/internal/evm/create3"
)

func runPrepare(cmd *flag.FlagSet, args []string) {
	// Define flags
	broadcastFile := cmd.String("broadcast-file", "", "Path to Foundry broadcast JSON file (required)")
	configPath := cmd.String("config", "", "Path to privacy.toml config file")
	apiURL := cmd.String("api-url", "", "Privacy Proxy API URL")
	orgID := cmd.String("org-id", "", "Organization ID")
	factoryAddr := cmd.String("factory", "", "CREATE3 factory address")
	token := cmd.String("token", "", "Authentication token")
	dryRun := cmd.Bool("dry-run", false, "Show what would be registered without calling API")
	verbose := cmd.Bool("verbose", false, "Show verbose output")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *broadcastFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --broadcast-file is required")
		fmt.Fprintln(os.Stderr, "\nUsage: privacy-cli prepare --broadcast-file <path> [options]")
		cmd.PrintDefaults()
		os.Exit(1)
	}

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Merge flags with config
	cfg.MergeWithFlags(*apiURL, "", *orgID, *factoryAddr, *token)

	// Validate config (unless dry-run)
	if !*dryRun {
		if err := cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
			os.Exit(1)
		}
	}

	// Parse broadcast file
	fmt.Println("Analyzing Foundry broadcast file...")
	broadcast, err := ParseBroadcastFile(*broadcastFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing broadcast file: %v\n", err)
		os.Exit(1)
	}

	// Extract deployments
	deployments, err := ExtractDeployments(broadcast)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting deployments: %v\n", err)
		os.Exit(1)
	}

	if len(deployments) == 0 {
		fmt.Println("No contract deployments found in broadcast file.")
		os.Exit(0)
	}

	fmt.Printf("\nFound %d contract deployments:\n", len(deployments))
	for _, d := range deployments {
		deps := "no address dependencies"
		if len(d.Dependencies) > 0 {
			deps = fmt.Sprintf("depends on: %s", strings.Join(d.Dependencies, ", "))
		}
		fmt.Printf("  - %s (%s)\n", d.Name, deps)
	}

	// Discover or use factory address
	factory := cfg.Factory.Address
	if factory == "" && !*dryRun {
		fmt.Println("\nDiscovering CREATE3 factory...")
		client := NewProxyClient(cfg.Proxy.APIURL, cfg.Auth.Token)
		factory, err = client.DiscoverFactory()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not discover factory: %v\n", err)
			fmt.Fprintln(os.Stderr, "Use --factory flag to specify the factory address")
		}
	}

	if factory == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "\nError: CREATE3 factory address is required")
		fmt.Fprintln(os.Stderr, "Set factory.address in privacy.toml, use --factory flag, or ensure the proxy has a factory deployed")
		os.Exit(1)
	}

	// Compute CREATE3 addresses
	fmt.Println("\nComputed CREATE3 addresses:")
	prepareContracts := make([]ContractPrepareInfo, 0, len(deployments))

	for i, d := range deployments {
		// Generate a deterministic salt based on contract name and deployer
		salt := generateSalt(d.Name, d.DeployerAddress, i)

		var address string
		if factory != "" {
			addr, err := create3.CalculateCREATE3AddressFromHex(factory, salt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error computing address for %s: %v\n", d.Name, err)
				os.Exit(1)
			}
			address = strings.ToLower(addr.Hex())
		} else {
			address = "(factory address required)"
		}

		fmt.Printf("  - %s: %s\n", d.Name, address)

		if *verbose {
			fmt.Printf("    Salt: %s\n", salt)
			fmt.Printf("    Bytecode hash: %s\n", d.BytecodeHash)
		}

		prepareContracts = append(prepareContracts, ContractPrepareInfo{
			Name:         d.Name,
			Salt:         salt,
			BytecodeHash: d.BytecodeHash,
		})
	}

	// If dry-run, stop here
	if *dryRun {
		fmt.Println("\n[Dry run] Would register the above contracts with Privacy Proxy")
		fmt.Printf("API URL: %s\n", cfg.Proxy.APIURL)
		fmt.Printf("Org ID: %s\n", cfg.Org.ID)
		fmt.Printf("Factory: %s\n", factory)
		return
	}

	// Register with proxy
	fmt.Println("\nRegistering with Privacy Proxy...")
	client := NewProxyClient(cfg.Proxy.APIURL, cfg.Auth.Token)

	req := &PrepareRequest{
		Contracts: prepareContracts,
		Factory:   factory,
	}

	resp, err := client.PrepareDeployment(cfg.Org.ID, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error registering deployment: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nRegistered with Privacy Proxy")
	fmt.Printf("  Deployment ID: %s\n", resp.DeploymentID)
	fmt.Printf("  Expires at: %s\n", resp.ExpiresAt)

	if len(resp.Addresses) > 0 {
		fmt.Println("\nRegistered addresses:")
		for name, addr := range resp.Addresses {
			fmt.Printf("  - %s: %s\n", name, addr)
		}
	}

	fmt.Println("\nNext steps:")
	fmt.Println("  1. Deploy your contracts using Foundry:")
	fmt.Printf("     forge script <your-script> --rpc-url %s --broadcast\n", cfg.Proxy.RPCURL)
	fmt.Println("  2. Verify the deployment:")
	fmt.Printf("     privacy-cli verify --deployment-id %s\n", resp.DeploymentID)
}

// generateSalt generates a deterministic salt for a contract deployment.
func generateSalt(contractName, deployer string, index int) string {
	// Create a deterministic salt from contract name, deployer, and index
	data := fmt.Sprintf("%s:%s:%d", contractName, strings.ToLower(deployer), index)
	hash := sha256.Sum256([]byte(data))
	return "0x" + hex.EncodeToString(hash[:])
}
