// Package broadcast provides types and parsing for Foundry broadcast files.
package broadcast

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ParseFile parses a Foundry broadcast JSON file and returns the broadcast data.
func ParseFile(path string) (*BroadcastFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read broadcast file: %w", err)
	}

	return Parse(data)
}

// Parse parses broadcast JSON data and returns the broadcast data.
func Parse(data []byte) (*BroadcastFile, error) {
	var broadcast BroadcastFile
	if err := json.Unmarshal(data, &broadcast); err != nil {
		return nil, fmt.Errorf("failed to parse broadcast JSON: %w", err)
	}

	return &broadcast, nil
}

// KnownCREATE3Factories is a list of known CREATE3 factory contract addresses.
// These are used to identify CREATE3 deployments when a CALL is made to one of these addresses.
var KnownCREATE3Factories = map[string]bool{
	// Solmate/Solady CREATE3 factory
	"0x0000000000ffe8b47b3e2130213b802212439497": true,
	// Additional common factory addresses can be added here
}

// ExtractDeploymentAddresses extracts all contract addresses that will be deployed
// from a broadcast file. It supports CREATE, CREATE2, and CREATE3 (via factory) deployments.
//
// For CREATE3 detection, it checks:
// 1. Explicit CREATE3 transaction type
// 2. CALL to a known CREATE3 factory with additional contracts
// 3. CALL with additional contracts where transaction has CREATE3-like patterns
func ExtractDeploymentAddresses(broadcast *BroadcastFile, customFactories []string) []DeploymentAddress {
	// Build factory lookup set
	factories := make(map[string]bool)
	for addr := range KnownCREATE3Factories {
		factories[strings.ToLower(addr)] = true
	}
	for _, addr := range customFactories {
		factories[strings.ToLower(addr)] = true
	}

	var addresses []DeploymentAddress

	for _, tx := range broadcast.Transactions {
		txType := strings.ToUpper(tx.Type)

		switch txType {
		case "CREATE":
			// Direct CREATE deployment
			if tx.ContractAddress != "" {
				addresses = append(addresses, DeploymentAddress{
					Address:        strings.ToLower(tx.ContractAddress),
					ContractName:   tx.ContractName,
					DeploymentType: DeploymentCREATE,
				})
			}

		case "CREATE2":
			// Direct CREATE2 deployment
			if tx.ContractAddress != "" {
				addresses = append(addresses, DeploymentAddress{
					Address:        strings.ToLower(tx.ContractAddress),
					ContractName:   tx.ContractName,
					DeploymentType: DeploymentCREATE2,
				})
			}

		case "CALL":
			// Check if this is a CREATE3 factory call
			targetAddr := strings.ToLower(tx.ContractAddress)
			isFactoryCall := factories[targetAddr]

			// Extract additional contracts deployed by this call
			for _, additional := range tx.AdditionalContracts {
				addr := DeploymentAddress{
					Address:      strings.ToLower(additional.Address),
					ContractName: tx.ContractName, // Use parent tx contract name
				}

				additionalType := strings.ToUpper(additional.TransactionType)
				switch additionalType {
				case "CREATE":
					// If this CREATE was from a factory call, it's likely CREATE3
					if isFactoryCall {
						addr.DeploymentType = DeploymentCREATE3
						addr.FactoryAddress = targetAddr
					} else {
						addr.DeploymentType = DeploymentCREATE
					}
				case "CREATE2":
					addr.DeploymentType = DeploymentCREATE2
				default:
					// Default to CREATE3 if from factory, otherwise CREATE
					if isFactoryCall {
						addr.DeploymentType = DeploymentCREATE3
						addr.FactoryAddress = targetAddr
					} else {
						addr.DeploymentType = DeploymentCREATE
					}
				}

				addresses = append(addresses, addr)
			}
		}
	}

	return addresses
}

// ExtractAddresses is a convenience function that returns just the addresses as strings.
func ExtractAddresses(broadcast *BroadcastFile, customFactories []string) []string {
	deployments := ExtractDeploymentAddresses(broadcast, customFactories)
	addresses := make([]string, len(deployments))
	for i, d := range deployments {
		addresses[i] = d.Address
	}
	return addresses
}

// FilterByType filters deployment addresses by deployment type.
func FilterByType(addresses []DeploymentAddress, deploymentType DeploymentType) []DeploymentAddress {
	var filtered []DeploymentAddress
	for _, addr := range addresses {
		if addr.DeploymentType == deploymentType {
			filtered = append(filtered, addr)
		}
	}
	return filtered
}
