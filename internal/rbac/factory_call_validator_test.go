package rbac

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"privacy-proxy/internal/evm/create3"
)

// factoryCallTestStore extends the mock store with factory call validation support
type factoryCallTestStore struct {
	*MockStore
	preregisteredAddrs map[string]map[string]bool // orgID -> address -> preregistered
	orgOwnedAddresses  map[string]map[string]bool // orgID -> address -> owned
	anyOrgContracts    map[string]bool            // address -> registered to any org
}

func newFactoryCallTestStore() *factoryCallTestStore {
	return &factoryCallTestStore{
		MockStore:          NewMockStore(),
		preregisteredAddrs: make(map[string]map[string]bool),
		orgOwnedAddresses:  make(map[string]map[string]bool),
		anyOrgContracts:    make(map[string]bool),
	}
}

func (s *factoryCallTestStore) setAddressPreregistered(orgID, address string) {
	if s.preregisteredAddrs[orgID] == nil {
		s.preregisteredAddrs[orgID] = make(map[string]bool)
	}
	s.preregisteredAddrs[orgID][strings.ToLower(address)] = true
}

func (s *factoryCallTestStore) setOrgOwnsAddress(orgID, address string) {
	if s.orgOwnedAddresses[orgID] == nil {
		s.orgOwnedAddresses[orgID] = make(map[string]bool)
	}
	s.orgOwnedAddresses[orgID][strings.ToLower(address)] = true
}

func (s *factoryCallTestStore) setAnyOrgOwns(address string) {
	s.anyOrgContracts[strings.ToLower(address)] = true
}

func (s *factoryCallTestStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	if addrs, ok := s.preregisteredAddrs[orgID]; ok {
		return addrs[strings.ToLower(address)], nil
	}
	return false, nil
}

func (s *factoryCallTestStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if addrs, ok := s.orgOwnedAddresses[orgID]; ok {
		return addrs[strings.ToLower(address)], nil
	}
	return false, nil
}

func (s *factoryCallTestStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	addr := strings.ToLower(address)
	for orgID, addrs := range s.orgOwnedAddresses {
		if addrs[addr] {
			return orgID, nil
		}
	}
	return "", nil
}

func (s *factoryCallTestStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	return s.anyOrgContracts[strings.ToLower(address)], nil
}

// buildDeployCalldata builds calldata for factory.deploy(bytes32 salt, bytes creationCode)
// Selector: 0xcdcb760a
func buildDeployCalldata(salt [32]byte, creationCode []byte) []byte {
	// Function selector
	selector, _ := hex.DecodeString("cdcb760a")

	// ABI encoding:
	// - 4 bytes: selector
	// - 32 bytes: salt (bytes32)
	// - 32 bytes: offset to creationCode (always 0x40 = 64)
	// - 32 bytes: length of creationCode
	// - N bytes: creationCode (padded to 32-byte boundary)

	calldata := make([]byte, 0, 4+32+32+32+len(creationCode)+32)
	calldata = append(calldata, selector...)
	calldata = append(calldata, salt[:]...)

	// Offset to bytes parameter (64 = 0x40)
	offset := make([]byte, 32)
	offset[31] = 0x40
	calldata = append(calldata, offset...)

	// Length of creationCode
	length := make([]byte, 32)
	length[31] = byte(len(creationCode))
	if len(creationCode) > 255 {
		length[30] = byte(len(creationCode) >> 8)
	}
	calldata = append(calldata, length...)

	// CreationCode (padded to 32-byte boundary)
	calldata = append(calldata, creationCode...)
	padding := (32 - len(creationCode)%32) % 32
	calldata = append(calldata, make([]byte, padding)...)

	return calldata
}

func TestFactoryCallValidator_DeployToPreregisteredAddress(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	// Calculate what the CREATE3 address will be for our salt
	var salt [32]byte
	copy(salt[:], []byte("test-salt-for-deployment-123456"))

	targetAddr, err := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	if err != nil {
		t.Fatalf("failed to calculate CREATE3 address: %v", err)
	}

	// Preregister this address
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Simple bytecode (no external calls)
	creationCode, _ := hex.DecodeString("600000") // PUSH1 0x00, STOP

	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy to preregistered address succeeds", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.IsFactoryCall {
			t.Error("expected IsFactoryCall to be true")
		}
		if !result.IsDeployCall {
			t.Error("expected IsDeployCall to be true")
		}
		if !result.Allowed {
			t.Errorf("expected deployment to preregistered address to be allowed, got denied: %s", result.Reason)
		}
		if result.TargetAddress != strings.ToLower(targetAddr.Hex()) {
			t.Errorf("expected target address %s, got %s", strings.ToLower(targetAddr.Hex()), result.TargetAddress)
		}
	})
}

func TestFactoryCallValidator_DeployToNonPreregisteredAddress(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	// Use a salt that produces an address that is NOT preregistered
	var salt [32]byte
	copy(salt[:], []byte("unregistered-salt-00000000000000"))

	// Don't preregister the resulting address

	creationCode, _ := hex.DecodeString("600000")
	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy to non-preregistered address fails", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.IsFactoryCall {
			t.Error("expected IsFactoryCall to be true")
		}
		if !result.IsDeployCall {
			t.Error("expected IsDeployCall to be true")
		}
		if result.Allowed {
			t.Error("expected deployment to non-preregistered address to be denied")
		}
		if !strings.Contains(result.Reason, "not preregistered") {
			t.Errorf("expected reason to mention 'not preregistered', got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_DeployBytecodeCallingOtherOrgAddress(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("test-salt-with-bad-bytecode-000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Bytecode that calls another org's address
	// PUSH20 <other_org_address> PUSH1 0 ... CALL
	otherOrgAddr := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store.setAnyOrgOwns("0x" + otherOrgAddr) // Registered to some other org

	creationCode, _ := hex.DecodeString("73" + otherOrgAddr + "600060006000600060006000f100")
	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy bytecode calling other org address fails", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			// Expected - bytecode validation should fail
			if !strings.Contains(result.Reason, "not allowed") && !strings.Contains(result.Reason, "validation failed") {
				t.Logf("Reason: %s", result.Reason)
			}
		} else {
			t.Error("expected deployment with bytecode calling other org's address to be denied")
		}
	})
}

func TestFactoryCallValidator_DeployBytecodeCallingOrgOwnedAddress(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("test-salt-with-good-bytecode-00"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Bytecode that calls org's own address
	orgOwnedAddr := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	store.setOrgOwnsAddress(orgID, "0x"+orgOwnedAddr)

	creationCode, _ := hex.DecodeString("73" + orgOwnedAddr + "600060006000600060006000f100")
	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy bytecode calling org-owned address succeeds", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected deployment with bytecode calling org-owned address to be allowed, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_NonFactoryCall(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	otherAddress := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	orgID := "org1"

	calldata, _ := hex.DecodeString("cdcb760a" + strings.Repeat("00", 96)) // deploy selector + some data

	t.Run("call to non-factory address passes through", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, otherAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsFactoryCall {
			t.Error("expected IsFactoryCall to be false for non-factory address")
		}
		if !result.Allowed {
			t.Error("expected non-factory call to be allowed (passed through)")
		}
	})
}

func TestFactoryCallValidator_NonDeploySelector(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	// Some other function selector (not deploy)
	calldata, _ := hex.DecodeString("12345678" + strings.Repeat("00", 32))

	t.Run("non-deploy call to factory passes through", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.IsFactoryCall {
			t.Error("expected IsFactoryCall to be true")
		}
		if result.IsDeployCall {
			t.Error("expected IsDeployCall to be false for non-deploy selector")
		}
		if !result.Allowed {
			t.Error("expected non-deploy call to factory to be allowed")
		}
	})
}

func TestFactoryCallValidator_DeployWithCreateOpcodes(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("test-salt-create-opcode-0000000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Bytecode with CREATE opcode (not a trusted factory)
	creationCode, _ := hex.DecodeString("6000600060006000f000") // CREATE opcode

	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy bytecode with CREATE opcode fails (non-trusted factory)", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected deployment with CREATE opcode to be denied (not a trusted factory)")
		}
		if !strings.Contains(result.Reason, "CREATE") {
			t.Errorf("expected reason to mention CREATE, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_CrossOrgPreregisteredAddress(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	org1ID := "org1"
	org2ID := "org2"

	var salt [32]byte
	copy(salt[:], []byte("cross-org-test-salt-000000000000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))

	// Preregister for org2, but NOT for org1
	store.setAddressPreregistered(org2ID, targetAddr.Hex())

	creationCode, _ := hex.DecodeString("600000")
	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("deploy to address preregistered for different org fails", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), org1ID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected deployment to address preregistered for different org to be denied")
		}
		if !strings.Contains(result.Reason, "not preregistered") {
			t.Errorf("expected reason to mention 'not preregistered', got: %s", result.Reason)
		}
	})

	t.Run("same address deployment allowed for correct org", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), org2ID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected deployment to be allowed for org that preregistered the address, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_EmptyCreationCode(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("empty-bytecode-salt-000000000000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Empty creation code
	calldata := buildDeployCalldata(salt, []byte{})

	t.Run("deploy with empty creation code succeeds", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected deployment with empty creation code to be allowed, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_ShortCalldata(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	t.Run("calldata too short for selector", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, []byte{0xcd, 0xcb})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.IsDeployCall {
			t.Error("expected IsDeployCall to be false for short calldata")
		}
		if !result.Allowed {
			t.Error("expected short calldata to be allowed (not a deploy call)")
		}
	})

	t.Run("calldata too short for deploy parameters", func(t *testing.T) {
		calldata, _ := hex.DecodeString("cdcb760a" + strings.Repeat("00", 50)) // Not enough for full ABI encoding
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed && result.IsDeployCall {
			t.Error("expected malformed deploy call to be denied")
		}
	})
}

func TestFactoryCallValidator_CaseInsensitiveAddressComparison(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	// Factory address with mixed case
	factoryAddressLower := "0x1234567890abcdef1234567890abcdef12345678"
	factoryAddressUpper := "0x1234567890ABCDEF1234567890ABCDEF12345678"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("case-test-salt-0000000000000000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddressLower, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	creationCode, _ := hex.DecodeString("600000")
	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("factory address comparison is case-insensitive", func(t *testing.T) {
		// Call with lowercase factory configured, uppercase target
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddressLower, factoryAddressUpper, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.IsFactoryCall {
			t.Error("expected IsFactoryCall to be true despite case difference")
		}
		if !result.Allowed {
			t.Errorf("expected to be allowed, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_ProxyBytecodeAllowed(t *testing.T) {
	store := newFactoryCallTestStore()
	deployValidator := NewDeploymentValidator(store)
	validator := NewFactoryCallValidator(store, deployValidator)

	factoryAddress := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	var salt [32]byte
	copy(salt[:], []byte("proxy-deploy-salt-00000000000000"))

	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddress, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Simplified proxy-like bytecode (no external calls, just returns)
	// This mimics a minimal viable proxy that would pass validation
	creationCode, _ := hex.DecodeString("600000") // Minimal valid bytecode

	calldata := buildDeployCalldata(salt, creationCode)

	t.Run("proxy-like bytecode is allowed", func(t *testing.T) {
		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddress, factoryAddress, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected proxy-like bytecode to be allowed, got: %s", result.Reason)
		}
	})
}

// TestAccessController_FactoryCallIntegration tests the full integration in access controller
func TestAccessController_FactoryCallIntegration(t *testing.T) {
	store := newFactoryCallTestStore()

	// Setup organization with factory (must be valid 40 hex char address)
	factoryAddr := "0x1234567890abcdef1234567890abcdef12345678"
	org := &Organization{
		ID:   "org1",
		Slug: "test-org",
		Name: "Test Org",
		Settings: map[string]any{
			"factory_address": factoryAddr,
		},
	}
	store.MockStore.organizations["org1"] = org

	// Setup user and permissions
	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.MockStore.users["user1"] = user

	group := &Group{ID: "deployers", OrgID: "org1", Slug: "deployers", Name: "Deployers"}
	store.MockStore.groups["deployers"] = group
	store.MockStore.groupAccess["deployers"] = &GroupAccess{
		GroupID:        "deployers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		DefaultClaims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
	}

	// User membership
	store.MockStore.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{Membership: &UserMembership{UserID: "user1", GroupID: "deployers"}, Group: group},
	}

	// Register factory as org-owned contract
	store.setOrgOwnsAddress("org1", factoryAddr)
	store.MockStore.contracts[factoryAddr] = &Contract{
		ID:      "factory-1",
		OrgID:   "org1",
		Address: factoryAddr,
		Name:    "CREATE3 Factory",
	}

	// Preregister a target address
	var salt [32]byte
	copy(salt[:], []byte("integration-test-salt-0000000000"))
	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddr, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered("org1", targetAddr.Hex())

	// Note: Full integration test would require more complex setup
	// This test validates the basic flow works
	t.Run("factory call validator is invoked for factory calls", func(t *testing.T) {
		deployValidator := NewDeploymentValidator(store)
		validator := NewFactoryCallValidator(store, deployValidator)

		creationCode, _ := hex.DecodeString("600000")
		calldata := buildDeployCalldata(salt, creationCode)

		result, err := validator.ValidateFactoryCall(ctx(), "org1", factoryAddr, factoryAddr, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.IsFactoryCall || !result.IsDeployCall {
			t.Error("expected factory deploy call to be detected")
		}
		if !result.Allowed {
			t.Errorf("expected call to be allowed, got: %s", result.Reason)
		}
	})
}

func TestFactoryCallValidator_RuntimeTracingAllowsDynamicCalls(t *testing.T) {
	// This test verifies that when runtime tracing is enabled,
	// contracts with dynamic calls are allowed through factory deployment
	// because those calls will be validated at execution time via debug_traceCall
	store := newFactoryCallTestStore()

	factoryAddr := "0x1234567890123456789012345678901234567890"
	orgID := "org1"

	// Preregister target address
	var salt [32]byte
	copy(salt[:], []byte("runtime-trace-test-000000000000"))
	targetAddr, _ := create3.CalculateCREATE3AddressFromHex(factoryAddr, "0x"+hex.EncodeToString(salt[:]))
	store.setAddressPreregistered(orgID, targetAddr.Hex())

	// Create bytecode with dynamic calls (SLOAD then CALL - loads call target from storage)
	// This matches the bytecodeWithDynamicCall constant in deploy_validator_test.go
	// PUSH1 0x00 SLOAD ... CALL STOP - the SLOAD makes the call target dynamic
	bytecodeWithDynamicCall, _ := hex.DecodeString("600054600060006000600060006000f100")

	t.Run("without runtime tracing - dynamic calls are blocked", func(t *testing.T) {
		deployValidator := NewDeploymentValidator(store)
		// Runtime tracing NOT enabled (default)

		validator := NewFactoryCallValidator(store, deployValidator)
		calldata := buildDeployCalldata(salt, bytecodeWithDynamicCall)

		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddr, factoryAddr, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected dynamic call to be BLOCKED without runtime tracing")
		}
		if !strings.Contains(result.Reason, "dynamic") {
			t.Errorf("expected reason to mention dynamic calls, got: %s", result.Reason)
		}
	})

	t.Run("with runtime tracing - dynamic calls are allowed", func(t *testing.T) {
		deployValidator := NewDeploymentValidator(store)
		// Enable runtime tracing
		deployValidator.SetRuntimeTracingEnabled(true)

		validator := NewFactoryCallValidator(store, deployValidator)
		calldata := buildDeployCalldata(salt, bytecodeWithDynamicCall)

		result, err := validator.ValidateFactoryCall(ctx(), orgID, factoryAddr, factoryAddr, calldata)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected dynamic call to be ALLOWED with runtime tracing, got: %s", result.Reason)
		}
	})
}

// Helper function for context
func ctx() context.Context {
	return context.Background()
}
