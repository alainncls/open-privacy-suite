// Package main provides the privacy-cli command-line tool for integrating
// Foundry deployments with the Privacy Proxy service.
package main

import (
	"flag"
	"fmt"
	"os"
)

const Version = "0.1.0"

func main() {
	// Define subcommands
	prepareCmd := flag.NewFlagSet("prepare", flag.ExitOnError)
	verifyCmd := flag.NewFlagSet("verify", flag.ExitOnError)
	listCmd := flag.NewFlagSet("list", flag.ExitOnError)
	computeCmd := flag.NewFlagSet("compute-address", flag.ExitOnError)

	// Check for subcommand
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "prepare":
		runPrepare(prepareCmd, os.Args[2:])
	case "verify":
		runVerify(verifyCmd, os.Args[2:])
	case "list":
		runList(listCmd, os.Args[2:])
	case "compute-address":
		runComputeAddress(computeCmd, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("privacy-cli version %s\n", Version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`privacy-cli - Privacy Proxy CLI for Foundry integration

Usage:
  privacy-cli <command> [options]

Commands:
  prepare           Analyze Foundry broadcast and register addresses with Privacy Proxy
  verify            Verify deployment matches registration
  list              List pending deployments for an organization
  compute-address   Compute a CREATE3 address

Options:
  -h, --help        Show this help message
  -v, --version     Show version

Examples:
  # Analyze broadcast and register addresses
  privacy-cli prepare --broadcast-file broadcast/Deploy.s.sol/31337/run-latest.json

  # Verify deployment matches registration
  privacy-cli verify --deployment-id dep_xyz789

  # List pending deployments
  privacy-cli list --org-id org_abc123

  # Compute a single CREATE3 address
  privacy-cli compute-address --factory 0x... --salt 0x... --deployer 0x...

Configuration:
  Create a privacy.toml file in your project root:

  [proxy]
  api_url = "http://localhost:8080/api/v1"
  rpc_url = "http://localhost:8080/rpc"

  [org]
  id = "org_abc123"

  [factory]
  address = "0x..."  # Optional, auto-discovered

  [auth]
  token = "${PRIVACY_PROXY_TOKEN}"
`)
}
