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

// Create3FactoryBytecode is the init code for the CREATE3 factory contract.
// This factory has two functions: deploy(bytes32 salt, bytes memory creationCode) and getDeployed(bytes32 salt)
//
// Source: src/CREATE3Factory.sol
// Compiled with solc 0.8.22 (matching foundry.toml).
const Create3FactoryInitCode = "0x608060405234801561000f575f80fd5b5061094b8061001d5f395ff3fe608060405260043610610028575f3560e01c8063cdcb760a1461002c578063df20e2521461005c575b5f80fd5b610046600480360381019061004191906104fe565b610098565b6040516100539190610597565b60405180910390f35b348015610067575f80fd5b50610082600480360381019061007d91906105b0565b6102c8565b60405161008f9190610597565b60405180910390f35b5f805f6040518060400160405280601081526020017f67363d3d37363d34f03d5260086018f3000000000000000000000000000000008152509050848151602083015ff591505f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361014c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161014390610635565b60405180910390fd5b5f8273ffffffffffffffffffffffffffffffffffffffff16348660405161017391906106bf565b5f6040518083038185875af1925050503d805f81146101ad576040519150601f19603f3d011682016040523d82523d5f602084013e6101b2565b606091505b50509050806101f6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016101ed9061071f565b60405180910390fd5b60d660f81b609460f81b84600160f81b60405160200161021994939291906107cd565b604051602081830303815290604052805190602001205f1c93505f843b90505f811161027a576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102719061088a565b60405180910390fd5b868573ffffffffffffffffffffffffffffffffffffffff167fb085ff794f342ed78acc7791d067e28a931e614b52476c0305795e1ff0a154bc60405160405180910390a35050505092915050565b5f8060ff60f81b30846040518060400160405280601081526020017f67363d3d37363d34f03d5260086018f3000000000000000000000000000000008152508051906020012060405160200161032194939291906108c8565b604051602081830303815290604052805190602001205f1c905060d660f81b609460f81b82600160f81b60405160200161035e94939291906107cd565b604051602081830303815290604052805190602001205f1c915050919050565b5f604051905090565b5f80fd5b5f80fd5b5f819050919050565b6103a18161038f565b81146103ab575f80fd5b50565b5f813590506103bc81610398565b92915050565b5f80fd5b5f80fd5b5f601f19601f8301169050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b610410826103ca565b810181811067ffffffffffffffff8211171561042f5761042e6103da565b5b80604052505050565b5f61044161037e565b905061044d8282610407565b919050565b5f67ffffffffffffffff82111561046c5761046b6103da565b5b610475826103ca565b9050602081019050919050565b828183375f83830152505050565b5f6104a261049d84610452565b610438565b9050828152602081018484840111156104be576104bd6103c6565b5b6104c9848285610482565b509392505050565b5f82601f8301126104e5576104e46103c2565b5b81356104f5848260208601610490565b91505092915050565b5f806040838503121561051457610513610387565b5b5f610521858286016103ae565b925050602083013567ffffffffffffffff8111156105425761054161038b565b5b61054e858286016104d1565b9150509250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61058182610558565b9050919050565b61059181610577565b82525050565b5f6020820190506105aa5f830184610588565b92915050565b5f602082840312156105c5576105c4610387565b5b5f6105d2848285016103ae565b91505092915050565b5f82825260208201905092915050565b7f435245415445333a2070726f7879206465706c6f796d656e74206661696c65645f82015250565b5f61061f6020836105db565b915061062a826105eb565b602082019050919050565b5f6020820190508181035f83015261064c81610613565b9050919050565b5f81519050919050565b5f81905092915050565b5f5b83811015610684578082015181840152602081019050610669565b5f8484015250505050565b5f61069982610653565b6106a3818561065d565b93506106b3818560208601610667565b80840191505092915050565b5f6106ca828461068f565b915081905092915050565b7f435245415445333a206465706c6f796d656e74206661696c65640000000000005f82015250565b5f610709601a836105db565b9150610714826106d5565b602082019050919050565b5f6020820190508181035f830152610736816106fd565b9050919050565b5f7fff0000000000000000000000000000000000000000000000000000000000000082169050919050565b5f819050919050565b61078261077d8261073d565b610768565b82525050565b5f8160601b9050919050565b5f61079e82610788565b9050919050565b5f6107af82610794565b9050919050565b6107c76107c282610577565b6107a5565b82525050565b5f6107d88287610771565b6001820191506107e88286610771565b6001820191506107f882856107b6565b6014820191506108088284610771565b60018201915081905095945050505050565b7f435245415445333a206465706c6f796d656e7420766572696669636174696f6e5f8201527f206661696c656400000000000000000000000000000000000000000000000000602082015250565b5f6108746027836105db565b915061087f8261081a565b604082019050919050565b5f6020820190508181035f8301526108a181610868565b9050919050565b5f819050919050565b6108c26108bd8261038f565b6108a8565b82525050565b5f6108d38287610771565b6001820191506108e382866107b6565b6014820191506108f382856108b1565b60208201915061090382846108b1565b6020820191508190509594505050505056fea26469706673582212206dca21e0d9789ce5783c77b66871d7f11e2ab0871c9ccff77fb9982a5713aafe64736f6c63430008160033"

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

	// Verify the organization exists
	org, err := s.db.GetOrganization(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
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
