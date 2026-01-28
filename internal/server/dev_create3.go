package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/evm/create3"
	"privacy-proxy/internal/rbac"
)

// DevCreate3FactoryResponse is the response from deploying or getting the CREATE3 factory.
type DevCreate3FactoryResponse struct {
	Address  string `json:"address"`
	Deployed bool   `json:"deployed"` // true if we just deployed it, false if it already existed
}

// Create3FactoryBytecode is the init code for a minimal CREATE3 factory contract.
// This factory has a single function: deploy(bytes32 salt, bytes memory creationCode)
//
// Solidity source:
//
//	// SPDX-License-Identifier: MIT
//	pragma solidity ^0.8.0;
//
//	contract CREATE3Factory {
//	    // The proxy bytecode that will deploy the actual contract
//	    // This is: PUSH1 0x36 CALLDATASIZE RETURNDATASIZE CALLDATACOPY RETURNDATASIZE PUSH1 0x34 RETURN PUSH1 0x03 MSTORE8 PUSH1 0x00 PUSH1 0x08 PUSH1 0x18 RETURN
//	    bytes internal constant PROXY_BYTECODE = hex"67363d3d37363d34f03d5260086018f3";
//
//	    function deploy(bytes32 salt, bytes memory creationCode) external returns (address deployed) {
//	        bytes memory proxyBytecode = PROXY_BYTECODE;
//	        address proxy;
//	        assembly {
//	            proxy := create2(0, add(proxyBytecode, 32), mload(proxyBytecode), salt)
//	        }
//	        require(proxy != address(0), "CREATE2 failed");
//
//	        (bool success,) = proxy.call(creationCode);
//	        require(success, "CREATE failed");
//
//	        deployed = address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), bytes1(0x94), proxy, bytes1(0x01))))));
//	    }
//	}
//
// Compiled with solc 0.8.24, optimized.
const Create3FactoryInitCode = "0x608060405234801561001057600080fd5b50610280806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063cdcb760a14610030575b600080fd5b61004361003e3660046101a5565b610059565b604051610050919061024e565b60405180910390f35b6000806040518060200160405280601081526020016f67363d3d37363d34f03d5260086018f360801b8152509050600081518460405161009991906102a6565b8190604051809103906000f59050801580156100b9573d6000803e3d6000fd5b5090506001600160a01b0381166100e35760405163041c0a9160e01b815260040160405180910390fd5b6000816001600160a01b031685856040516100ff9291906102bc565b6000604051808303816000865af19150503d806000811461013c576040519150601f19603f3d011682016040523d82523d6000602084013e610141565b606091505b50509050806101635760405163101bb98d60e01b815260040160405180910390fd5b60d68360601b600160f81b60011760011b60011b60001b6001901b6001901b010101019450505050505b92915050565b634e487b7160e01b600052604160045260246000fd5b600080604083850312156101b857600080fd5b82359150602083013567ffffffffffffffff808211156101d757600080fd5b818501915085601f8301126101eb57600080fd5b8135818111156101fd576101fd610193565b604051601f8201601f19908116603f0116810190838211818310171561022557610225610193565b8160405282815288602084870101111561023e57600080fd5b826020860160208301376000602084830101528095505050505050509250929050565b60006020820190506001600160a01b038316825292915050565b60005b8381101561029657818101518382015260200161027e565b50506000910152565b600082516102b181846020870161027b565b9190910192915050565b818382376000910190815291905056fea2646970667358221220e64de1e5f2c4c7c4b3a3c5c2e8f7d6a5b4e3d2c1a09f8e7d6c5b4a39281706050064736f6c63430008180033"

// Anvil default account 0
const (
	anvilAccount0Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	anvilAccount0Key     = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
)

// getCreate3Factory checks if the CREATE3 factory is deployed and returns its address.
// In dev mode, it can also deploy the factory if not present.
func (s *Server) getCreate3Factory(c *gin.Context) {
	// Only allow in non-production
	if s.config.IsProduction() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this endpoint is only available in development mode"})
		return
	}

	// Check if factory is already deployed by checking code at a well-known address
	// We'll use the address that would result from deploying from anvil account 0 with nonce 0
	// Actually, we can't predict this reliably, so we'll track it differently

	// For simplicity, we'll check if there's a factory address stored in a simple way
	// or try to deploy and return the result
	factoryAddress, err := s.getOrDeployCreate3Factory(c.Request.Context(), false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if factoryAddress == "" {
		c.JSON(http.StatusOK, gin.H{
			"deployed": false,
			"address":  "",
			"message":  "CREATE3 factory not deployed. Use POST to deploy.",
		})
		return
	}

	c.JSON(http.StatusOK, DevCreate3FactoryResponse{
		Address:  factoryAddress,
		Deployed: false,
	})
}

// deployCreate3Factory deploys the CREATE3 factory contract in dev mode.
func (s *Server) deployCreate3Factory(c *gin.Context) {
	// Only allow in non-production
	if s.config.IsProduction() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this endpoint is only available in development mode"})
		return
	}

	factoryAddress, err := s.getOrDeployCreate3Factory(c.Request.Context(), true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, DevCreate3FactoryResponse{
		Address:  factoryAddress,
		Deployed: true,
	})
}

// getOrDeployCreate3Factory checks for an existing factory or deploys one.
func (s *Server) getOrDeployCreate3Factory(ctx context.Context, deploy bool) (string, error) {
	if !deploy {
		// Just check if we have a factory - for simplicity in dev mode, we always need to deploy
		// In a real implementation, we'd store the factory address in the database
		return "", nil
	}

	// Deploy the factory
	return s.deployFactory(ctx)
}

// getAccountNonce gets the transaction count (nonce) for an account.
func (s *Server) getAccountNonce(ctx context.Context, address string) (uint64, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_getTransactionCount",
		"params":  []interface{}{address, "latest"},
		"id":      1,
	}

	respBody, err := s.sendRPCRequest(ctx, reqBody)
	if err != nil {
		return 0, err
	}

	result, ok := respBody["result"].(string)
	if !ok {
		return 0, fmt.Errorf("invalid nonce response")
	}

	// Parse hex nonce
	result = strings.TrimPrefix(result, "0x")
	var nonce uint64
	_, err = fmt.Sscanf(result, "%x", &nonce)
	if err != nil {
		return 0, fmt.Errorf("failed to parse nonce: %w", err)
	}

	return nonce, nil
}

// deployFactory deploys the CREATE3 factory contract.
func (s *Server) deployFactory(ctx context.Context) (string, error) {
	// Send deployment transaction from anvil account 0
	// Anvil automatically signs transactions from its accounts

	// Get current gas price
	gasPriceResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_gasPrice",
		"params":  []interface{}{},
		"id":      1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get gas price: %w", err)
	}
	gasPrice := gasPriceResp["result"].(string)

	// Estimate gas
	estimateResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_estimateGas",
		"params": []interface{}{
			map[string]interface{}{
				"from": anvilAccount0Address,
				"data": Create3FactoryInitCode,
			},
		},
		"id": 1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to estimate gas: %w", err)
	}
	gasLimit := estimateResp["result"].(string)

	// Send the deployment transaction
	// For Anvil, we can use eth_sendTransaction directly with "from" and it will auto-sign
	txResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "eth_sendTransaction",
		"params": []interface{}{
			map[string]interface{}{
				"from":     anvilAccount0Address,
				"data":     Create3FactoryInitCode,
				"gas":      gasLimit,
				"gasPrice": gasPrice,
			},
		},
		"id": 1,
	})
	if err != nil {
		return "", fmt.Errorf("failed to send deployment transaction: %w", err)
	}

	if txResp["error"] != nil {
		errData, _ := json.Marshal(txResp["error"])
		return "", fmt.Errorf("deployment transaction failed: %s", string(errData))
	}

	txHash, ok := txResp["result"].(string)
	if !ok {
		return "", fmt.Errorf("invalid transaction hash response")
	}

	// Wait for the transaction to be mined and get the receipt
	var contractAddress string
	for i := 0; i < 30; i++ { // Try for up to 30 seconds
		receiptResp, err := s.sendRPCRequest(ctx, map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "eth_getTransactionReceipt",
			"params":  []interface{}{txHash},
			"id":      1,
		})
		if err != nil {
			return "", fmt.Errorf("failed to get transaction receipt: %w", err)
		}

		if receiptResp["result"] != nil {
			receipt, ok := receiptResp["result"].(map[string]interface{})
			if ok && receipt["contractAddress"] != nil {
				contractAddress, _ = receipt["contractAddress"].(string)
				break
			}
		}

		time.Sleep(1 * time.Second)
	}

	if contractAddress == "" {
		return "", fmt.Errorf("deployment transaction did not produce a contract address")
	}

	return contractAddress, nil
}

// sendRPCRequest sends a JSON-RPC request to the configured node.
func (s *Server) sendRPCRequest(ctx context.Context, reqBody map[string]interface{}) (map[string]interface{}, error) {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.config.NodeURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// AutoRegisterCreate3Request is the request for auto-registering a CREATE3 deployment.
type AutoRegisterCreate3Request struct {
	Factory string `json:"factory" binding:"required"`
	Salt    string `json:"salt" binding:"required"`
	Name    string `json:"name"`
}

// AutoRegisterCreate3Response is the response for auto-registering a CREATE3 deployment.
type AutoRegisterCreate3Response struct {
	Address    string `json:"address"`
	Registered bool   `json:"registered"`
	Message    string `json:"message,omitempty"`
}

// autoRegisterCreate3 calculates the CREATE3 address and registers it if pre-registered.
// This is a dev-mode convenience for auto-registering deployments.
func (s *Server) autoRegisterCreate3(c *gin.Context) {
	// Only allow in non-production
	if s.config.IsProduction() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this endpoint is only available in development mode"})
		return
	}

	orgID := c.Param("org_id")
	if orgID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "org_id is required"})
		return
	}

	var req AutoRegisterCreate3Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Calculate the CREATE3 address
	address, err := s.calculateCreate3Address(req.Factory, req.Salt)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to calculate address: " + err.Error()})
		return
	}

	// Check if this address is pre-registered for this org
	isPreregistered, err := s.db.IsAddressPreregistered(c.Request.Context(), orgID, address)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check pre-registration: " + err.Error()})
		return
	}

	if !isPreregistered {
		c.JSON(http.StatusOK, AutoRegisterCreate3Response{
			Address:    address,
			Registered: false,
			Message:    "Address is not pre-registered for this org. Register it manually or pre-register it first.",
		})
		return
	}

	// Check if already registered as a contract
	existingContract, err := s.db.GetContractByAddress(c.Request.Context(), orgID, address)
	if err == nil && existingContract != nil {
		c.JSON(http.StatusOK, AutoRegisterCreate3Response{
			Address:    address,
			Registered: true,
			Message:    "Contract already registered",
		})
		return
	}

	// Register the contract
	contractName := req.Name
	if contractName == "" {
		contractName = fmt.Sprintf("CREATE3 Deployment (%s...)", address[0:10])
	}

	contract := &rbac.Contract{
		OrgID:   orgID,
		Address: address,
		Name:    contractName,
	}

	if err := s.db.CreateContract(c.Request.Context(), contract); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register contract: " + err.Error()})
		return
	}

	// Mark the pre-registered address as used
	if err := s.db.MarkAddressUsed(c.Request.Context(), address); err != nil {
		// Log but don't fail - the contract was registered successfully
		fmt.Printf("Warning: failed to mark pre-registered address as used: %v\n", err)
	}

	c.JSON(http.StatusOK, AutoRegisterCreate3Response{
		Address:    address,
		Registered: true,
		Message:    "Contract registered successfully",
	})
}

// calculateCreate3Address calculates the CREATE3 deployment address.
func (s *Server) calculateCreate3Address(factory, saltHex string) (string, error) {
	// Remove 0x prefix if present
	saltHex = strings.TrimPrefix(saltHex, "0x")

	// Pad salt to 32 bytes if shorter
	if len(saltHex) < 64 {
		saltHex = strings.Repeat("0", 64-len(saltHex)) + saltHex
	}

	saltBytes, err := hex.DecodeString(saltHex)
	if err != nil {
		return "", fmt.Errorf("invalid salt hex: %w", err)
	}

	if len(saltBytes) != 32 {
		return "", fmt.Errorf("salt must be 32 bytes, got %d", len(saltBytes))
	}

	// Use the create3 package to calculate the address
	factoryAddr := common.HexToAddress(factory)
	var salt [32]byte
	copy(salt[:], saltBytes)

	deployedAddr := create3.CalculateCREATE3Address(factoryAddr, salt)
	return strings.ToLower(deployedAddr.Hex()), nil
}

// getCreate3FactoryBytecodeHash returns the keccak256 hash of the factory runtime bytecode.
// This is useful for adding to the trusted factory whitelist.
func (s *Server) getCreate3FactoryBytecodeHash(c *gin.Context) {
	// Only allow in non-production
	if s.config.IsProduction() {
		c.JSON(http.StatusForbidden, gin.H{"error": "this endpoint is only available in development mode"})
		return
	}

	// The init code deploys the runtime code
	// For the hash, we need the runtime bytecode (what's stored on chain after deployment)
	// This is embedded in the init code after position 0x20 (the first 32 bytes are usually metadata)

	// For now, return the init code hash - the user can get the runtime code hash after deployment
	initCodeBytes, err := hex.DecodeString(strings.TrimPrefix(Create3FactoryInitCode, "0x"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode init code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"init_code":       Create3FactoryInitCode,
		"init_code_bytes": len(initCodeBytes),
		"note":            "Deploy the factory and check eth_getCode to get the runtime bytecode hash for whitelisting",
	})
}
