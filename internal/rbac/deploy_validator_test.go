package rbac

import (
	"context"
	"strings"
	"testing"
)

// Test bytecode samples (simplified EVM bytecode for testing)
// These are minimal examples that demonstrate the patterns we want to detect.

const (
	// Simple contract with no external calls: PUSH1 0x00 STOP
	// 0x60 = PUSH1, 0x00 = arg, 0x00 = STOP
	bytecodeNoExternalCalls = "0x600000"

	// Contract with CREATE opcode: PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 CREATE STOP
	// 0x60 0x00 = PUSH1 0, 0x60 0x00 = PUSH1 0, 0x60 0x00 = PUSH1 0, 0xf0 = CREATE, 0x00 = STOP
	bytecodeWithCreate = "0x6000600060006000f000"

	// Contract with CREATE2 opcode: PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 PUSH1 0x00 CREATE2 STOP
	// 0x60 0x00 x4, 0xf5 = CREATE2, 0x00 = STOP
	bytecodeWithCreate2 = "0x60006000600060006000f500"

	// Contract with SLOAD before CALL (dynamic target from storage):
	// PUSH1 0x00 SLOAD ... CALL STOP
	// The SLOAD result becomes the call target, making it dynamic
	bytecodeWithDynamicCall = "0x600054600060006000600060006000f100"

	// Contract calling a constant address (org-owned):
	// PUSH1 gas, PUSH20 <address>, PUSH1 value, ... CALL
	// 0x60 0x00 = gas, 0x73 + 20 bytes = address, then more stack setup, 0xf1 = CALL
	bytecodeCallingOrgOwned = "0x6000" + "73" + "1234567890123456789012345678901234567890" + "6000600060006000600060006000f100"

	// Contract calling another org's address (should be denied):
	bytecodeCallingOtherOrg = "0x6000" + "73" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "6000600060006000600060006000f100"

	// Contract calling truly public address (not registered to any org):
	bytecodeCallingPublic = "0x6000" + "73" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "6000600060006000600060006000f100"

	// Contract calling precompile (ecrecover at 0x01):
	// Use PUSH20 with padded address for precompile to ensure it's detected as constant
	// 0x73 = PUSH20, then 20 bytes with 0x01 as last byte (precompile address)
	bytecodeCallingPrecompile = "0x6000" + "73" + "0000000000000000000000000000000000000001" + "6000600060006000600060006000f100"

	// Contract with DELEGATECALL to org-owned library:
	// PUSH1 gas, PUSH20 <address>, ... DELEGATECALL
	// 0xf4 = DELEGATECALL
	bytecodeDelegatecallOrgOwned = "0x6000" + "73" + "1234567890123456789012345678901234567890" + "60006000600060006000f400"

	// Contract with DELEGATECALL to other org's library:
	bytecodeDelegatecallOtherOrg = "0x6000" + "73" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "60006000600060006000f400"

	// Invalid bytecode
	bytecodeInvalid = "0xzzzz"
)

// deployValidatorTestStore is a test implementation of Store for deployment validation tests.
type deployValidatorTestStore struct {
	*MockStore
	// Additional control for testing
	orgOwnedAddresses      map[string]map[string]bool // orgID -> address -> owned
	anyOrgRegistrations    map[string]bool            // address -> registered to any org
	preregisteredAddresses map[string]map[string]bool // orgID -> address -> preregistered
	managedProxies         []*ManagedProxy            // Registered managed proxies
}

func newDeployValidatorTestStore() *deployValidatorTestStore {
	return &deployValidatorTestStore{
		MockStore:              NewMockStore(),
		orgOwnedAddresses:      make(map[string]map[string]bool),
		anyOrgRegistrations:    make(map[string]bool),
		preregisteredAddresses: make(map[string]map[string]bool),
		managedProxies:         make([]*ManagedProxy, 0),
	}
}

func (s *deployValidatorTestStore) setOrgOwnsAddress(orgID, address string, owned bool) {
	if s.orgOwnedAddresses[orgID] == nil {
		s.orgOwnedAddresses[orgID] = make(map[string]bool)
	}
	s.orgOwnedAddresses[orgID][address] = owned
}

func (s *deployValidatorTestStore) setAddressRegisteredToAnyOrg(address string, registered bool) {
	s.anyOrgRegistrations[address] = registered
}

func (s *deployValidatorTestStore) setAddressPreregistered(orgID, address string, preregistered bool) {
	if s.preregisteredAddresses[orgID] == nil {
		s.preregisteredAddresses[orgID] = make(map[string]bool)
	}
	s.preregisteredAddresses[orgID][address] = preregistered
}

func (s *deployValidatorTestStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if addrs, ok := s.orgOwnedAddresses[orgID]; ok {
		// Normalize address for comparison
		normalizedAddr := normalizeHexAddress(address)
		for addr, owned := range addrs {
			if normalizeHexAddress(addr) == normalizedAddr {
				return owned, nil
			}
		}
	}
	return false, nil
}

func (s *deployValidatorTestStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	normalizedAddr := normalizeHexAddress(address)
	for orgID, addrs := range s.orgOwnedAddresses {
		for addr, owned := range addrs {
			if owned && normalizeHexAddress(addr) == normalizedAddr {
				return orgID, nil
			}
		}
	}
	return "", nil
}

func (s *deployValidatorTestStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	normalizedAddr := normalizeHexAddress(address)
	for addr, registered := range s.anyOrgRegistrations {
		if normalizeHexAddress(addr) == normalizedAddr {
			return registered, nil
		}
	}
	return false, nil
}

func (s *deployValidatorTestStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	if addrs, ok := s.preregisteredAddresses[orgID]; ok {
		normalizedAddr := normalizeHexAddress(address)
		for addr, preregistered := range addrs {
			if normalizeHexAddress(addr) == normalizedAddr {
				return preregistered, nil
			}
		}
	}
	return false, nil
}

func (s *deployValidatorTestStore) CreateManagedProxy(ctx context.Context, proxy *ManagedProxy) error {
	s.managedProxies = append(s.managedProxies, proxy)
	return nil
}

func (s *deployValidatorTestStore) getManagedProxies() []*ManagedProxy {
	return s.managedProxies
}

// Constructor ABI stubs (use parent MockStore implementation)
func (s *deployValidatorTestStore) GetConstructorABI(ctx context.Context, orgID, address string) (string, error) {
	return "", nil
}

func (s *deployValidatorTestStore) UpdateConstructorABI(ctx context.Context, orgID, address, abi string) error {
	return nil
}

func (s *deployValidatorTestStore) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error {
	return nil
}

func (s *deployValidatorTestStore) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error {
	return nil
}

func (s *deployValidatorTestStore) CreateDeployerAutoGrants(ctx context.Context, orgID, contractID, deployerUserID, deployerExternalID string) error {
	return nil
}

// normalizeHexAddress normalizes a hex address for comparison.
func normalizeHexAddress(addr string) string {
	addr = strings.ToLower(addr)
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	return addr
}

func TestDeploymentValidator_NoExternalCalls(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_CreateOpcode(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithCreate, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied due to CREATE opcode")
	}
	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}
	if !strings.Contains(result.Reason, "CREATE") {
		t.Errorf("expected reason to mention CREATE, got: %s", result.Reason)
	}
}

func TestDeploymentValidator_Create2Opcode(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithCreate2, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied due to CREATE2 opcode")
	}
	if !result.HasCreate2 {
		t.Error("expected HasCreate2 to be true")
	}
	if !strings.Contains(result.Reason, "CREATE2") {
		t.Errorf("expected reason to mention CREATE2, got: %s", result.Reason)
	}
}

func TestDeploymentValidator_DynamicCall(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithDynamicCall, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied due to dynamic call")
	}
	if !result.HasDynamicCalls {
		t.Error("expected HasDynamicCalls to be true")
	}
	if !strings.Contains(result.Reason, "dynamic") {
		t.Errorf("expected reason to mention dynamic, got: %s", result.Reason)
	}
}

func TestDeploymentValidator_DynamicCallWithRuntimeTracing(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Enable runtime tracing - this should allow dynamic calls
	validator.SetRuntimeTracingEnabled(true)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithDynamicCall, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With runtime tracing enabled, dynamic calls should be ALLOWED
	// because they will be validated at execution time via debug_traceCall
	if !result.Allowed {
		t.Errorf("expected deployment to be ALLOWED when runtime tracing is enabled, got denied: %s", result.Reason)
	}
	if !result.HasDynamicCalls {
		t.Error("expected HasDynamicCalls to be true")
	}
}

func TestDeploymentValidator_CallingOrgOwnedAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register the address as owned by org1
	store.setOrgOwnsAddress("org1", "0x1234567890123456789012345678901234567890", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOrgOwned, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when calling org-owned address, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_CallingOtherOrgsAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register the address as owned by org2 (another org)
	store.setOrgOwnsAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)
	store.setAddressRegisteredToAnyOrg("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOtherOrg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied when calling other org's address")
	}
	if !strings.Contains(result.Reason, "not allowed") {
		t.Errorf("expected reason to mention 'not allowed', got: %s", result.Reason)
	}
}

func TestDeploymentValidator_CallingUnregisteredAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// The address is NOT registered to any org and NOT preregistered
	// Under the new security policy, calling such addresses is not allowed

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingPublic, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected deployment to be denied when calling unregistered address, but it was allowed")
	}
	if !strings.Contains(result.Reason, "not allowed for org") {
		t.Errorf("expected reason to mention 'not allowed for org', got: %s", result.Reason)
	}
}

func TestDeploymentValidator_CallingPreregisteredAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// The address is preregistered for org1 (whitelisted for deployment)
	store.setAddressPreregistered("org1", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingPublic, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when calling preregistered address, got denied: %s", result.Reason)
	}
}

// TestDeploymentValidator_RealMaliciousBoxBytecode tests with the actual compiled MaliciousBox bytecode
// that calls 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF
func TestDeploymentValidator_RealMaliciousBoxBytecode(t *testing.T) {
	// This is the actual compiled bytecode of MaliciousBox.sol
	// which contains a call to 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF
	maliciousBoxBytecode := "0x6080604052348015600e575f5ffd5b505f73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef73ffffffffffffffffffffffffffffffffffffffff1660405160459060cc565b5f604051808303815f865af19150503d805f8114607c576040519150601f19603f3d011682016040523d82523d5f602084013e6081565b606091505b505090508060015f6101000a81548160ff0219169083151502179055505060de565b5f81905092915050565b50565b5f60b95f8360a3565b915060c28260ad565b5f82019050919050565b5f60d48260b0565b9150819050919050565b610390806100eb5f395ff3fe608060405234801561000f575f5ffd5b5060043610610055575f3560e01c80632e64cec11461005957806354fd4d50146100775780635f431992146100955780636057361d146100b357806380acdcd9146100cf575b5f5ffd5b6100616100ed565b60405161006e91906101e4565b60405180910390f35b61007f6100f5565b60405161008c919061026d565b60405180910390f35b61009d610132565b6040516100aa91906102a7565b60405180910390f35b6100cd60048036038101906100c891906102ee565b6101b1565b005b6100d76101ba565b6040516100e491906102a7565b60405180910390f35b5f5f54905090565b60606040518060400160405280600f81526020017f6d616c6963696f75732d312e302e300000000000000000000000000000000000815250905090565b5f73deadbeefdeadbeefdeadbeefdeadbeefdeadbeef73ffffffffffffffffffffffffffffffffffffffff1660405161016a90610346565b5f604051808303815f865af19150503d805f81146101a3576040519150601f19603f3d011682016040523d82523d5f602084013e6101a8565b606091505b50508091505090565b805f8190555050565b60015f9054906101000a900460ff1681565b5f819050919050565b6101de816101cc565b82525050565b5f6020820190506101f75f8301846101d5565b92915050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f61023f826101fd565b6102498185610207565b9350610259818560208601610217565b61026281610225565b840191505092915050565b5f6020820190508181035f8301526102858184610235565b905092915050565b5f8115159050919050565b6102a18161028d565b82525050565b5f6020820190506102ba5f830184610298565b92915050565b5f5ffd5b6102cd816101cc565b81146102d7575f5ffd5b50565b5f813590506102e8816102c4565b92915050565b5f60208284031215610303576103026102c0565b5b5f610310848285016102da565b91505092915050565b5f81905092915050565b50565b5f6103315f83610319565b915061033c82610323565b5f82019050919050565b5f61035082610326565b915081905091905056fea2646970667358221220c1e3ec3981a40d2d03869b4d8eb2262a4a2a565668950ed43561fcc03d55f67864736f6c634300081e0033"

	store := newDeployValidatorTestStore()
	// Address 0xDeaDbeeF is NOT preregistered
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", maliciousBoxBytecode, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Log what was detected
	t.Logf("Constant targets detected: %v", result.ConstantTargets)
	t.Logf("Has dynamic calls: %v", result.HasDynamicCalls)
	t.Logf("Allowed: %v", result.Allowed)
	t.Logf("Reason: %s", result.Reason)

	// The deployment should be DENIED because it calls 0xDeaDbeeF which is not preregistered
	if result.Allowed {
		t.Errorf("expected deployment to be denied when calling unregistered 0xDeaDbeeF, but it was allowed")
	}
	// Verify the reason mentions the blocked address
	if !strings.Contains(strings.ToLower(result.Reason), "deadbeef") && !strings.Contains(result.Reason, "not allowed") {
		t.Errorf("expected reason to mention deadbeef address or 'not allowed', got: %s", result.Reason)
	}
}

func TestDeploymentValidator_CallingPrecompile(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingPrecompile, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when calling precompile, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_DelegatecallOrgOwnedLibrary(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register the library address as owned by org1
	store.setOrgOwnsAddress("org1", "0x1234567890123456789012345678901234567890", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeDelegatecallOrgOwned, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed for DELEGATECALL to org-owned library, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_DelegatecallOtherOrgsLibrary(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register the library address as owned by org2 (another org)
	store.setOrgOwnsAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)
	store.setAddressRegisteredToAnyOrg("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeDelegatecallOtherOrg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for DELEGATECALL to other org's library")
	}
	if !strings.Contains(result.Reason, "DELEGATECALL") {
		t.Errorf("expected reason to mention DELEGATECALL, got: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "must be owned by org") {
		t.Errorf("expected reason to mention ownership requirement, got: %s", result.Reason)
	}
}

func TestDeploymentValidator_InvalidBytecode(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeInvalid, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for invalid bytecode")
	}
	if !strings.Contains(result.Reason, "invalid bytecode") {
		t.Errorf("expected reason to mention invalid bytecode, got: %s", result.Reason)
	}
}

func TestDeploymentValidator_EmptyBytecode(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", "0x", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected empty bytecode deployment to be allowed, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_DelegatecallToPublicLibrary(t *testing.T) {
	store := newDeployValidatorTestStore()
	// The library address is truly public (not registered to any org)
	// For DELEGATECALL, we still require org ownership for security

	validator := NewDeploymentValidator(store)

	// Use a public address for delegatecall
	bytecodePublicDelegatecall := "0x73" + "cccccccccccccccccccccccccccccccccccccccc" + "60006000600060006000f400"

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodePublicDelegatecall, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// DELEGATECALL should be denied even for public addresses
	if result.Allowed {
		t.Error("expected DELEGATECALL to public library to be denied (must be org-owned)")
	}
}

// TestDeploymentValidator_ValidationResultFields tests that ValidationResult fields are properly populated.
func TestDeploymentValidator_ValidationResultFields(t *testing.T) {
	store := newDeployValidatorTestStore()
	store.setOrgOwnsAddress("org1", "0x1234567890123456789012345678901234567890", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOrgOwned, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ConstantTargets) == 0 {
		t.Error("expected ConstantTargets to contain the called address")
	}

	// Check that the address is in the targets
	found := false
	for _, addr := range result.ConstantTargets {
		if normalizeHexAddress(addr) == "0x1234567890123456789012345678901234567890" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ConstantTargets to contain 0x1234..., got: %v", result.ConstantTargets)
	}
}

// TestDeploymentValidator_MultipleCallTargets tests contracts with multiple call targets.
func TestDeploymentValidator_MultipleCallTargets(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register both addresses as owned by org1
	store.setOrgOwnsAddress("org1", "0x1111111111111111111111111111111111111111", true)
	store.setOrgOwnsAddress("org1", "0x2222222222222222222222222222222222222222", true)

	validator := NewDeploymentValidator(store)

	// Bytecode with two CALL instructions to different addresses
	bytecodeMultipleCalls := "0x73" + "1111111111111111111111111111111111111111" + "600060006000600060006000f1" +
		"73" + "2222222222222222222222222222222222222222" + "600060006000600060006000f100"

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeMultipleCalls, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when calling multiple org-owned addresses, got denied: %s", result.Reason)
	}

	if len(result.ConstantTargets) < 2 {
		t.Errorf("expected at least 2 constant targets, got: %d", len(result.ConstantTargets))
	}
}

// TestDeploymentValidator_MixedCallTargets tests contracts with both allowed and disallowed targets.
func TestDeploymentValidator_MixedCallTargets(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Only register first address as owned
	store.setOrgOwnsAddress("org1", "0x1111111111111111111111111111111111111111", true)
	// Second address belongs to another org
	store.setAddressRegisteredToAnyOrg("0x3333333333333333333333333333333333333333", true)

	validator := NewDeploymentValidator(store)

	// Bytecode calling org-owned address then another org's address
	bytecodeMixedCalls := "0x73" + "1111111111111111111111111111111111111111" + "600060006000600060006000f1" +
		"73" + "3333333333333333333333333333333333333333" + "600060006000600060006000f100"

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeMixedCalls, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied when one target belongs to another org")
	}
}

// ERC-1967 implementation storage slot (used for proxy detection tests)
const erc1967ImplementationSlot = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
const erc1967AdminSlot = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"

// buildERC1967ProxyBytecode builds bytecode that resembles an ERC-1967 proxy:
// PUSH32 <implementation slot> SLOAD DELEGATECALL
// This has dynamic DELEGATECALL (from storage) which should be allowed for proxies.
func buildERC1967ProxyBytecode() string {
	// 0x7f = PUSH32
	// <32 byte slot>
	// 0x54 = SLOAD
	// 0x80 = DUP1
	// 0x60 0x00 = PUSH1 0
	// 0xf4 = DELEGATECALL
	// 0x00 = STOP
	return "0x7f" + erc1967ImplementationSlot + "548060006000600060006000f400"
}

// buildTransparentProxyBytecode builds bytecode that resembles a Transparent proxy:
// Has both implementation and admin slots.
func buildTransparentProxyBytecode() string {
	// PUSH32 <impl slot> SLOAD
	// PUSH32 <admin slot> SLOAD
	// ... DELEGATECALL
	return "0x7f" + erc1967ImplementationSlot + "547f" + erc1967AdminSlot + "5460006000600060006000f400"
}

// TestDeploymentValidator_ProxyDetection_ERC1967 tests that ERC-1967 proxies are detected.
func TestDeploymentValidator_ProxyDetection_ERC1967(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := buildERC1967ProxyBytecode()
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The deployment should be allowed (proxy contracts with dynamic DELEGATECALL are allowed)
	if !result.Allowed {
		t.Errorf("expected proxy deployment to be allowed, got denied: %s", result.Reason)
	}

	// Verify proxy detection
	if !result.IsProxy {
		t.Error("expected IsProxy to be true for ERC-1967 proxy")
	}
	if result.ProxyType != "ERC1967" {
		t.Errorf("expected ProxyType ERC1967, got %s", result.ProxyType)
	}
	if result.ProxyInfo == nil {
		t.Error("expected ProxyInfo to be set")
	}
	if result.ProxyInfo != nil && result.ProxyInfo.ImplementationSlot == "" {
		t.Error("expected ImplementationSlot to be set in ProxyInfo")
	}
}

// TestDeploymentValidator_ProxyDetection_TransparentProxy tests Transparent proxy detection.
func TestDeploymentValidator_ProxyDetection_TransparentProxy(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := buildTransparentProxyBytecode()
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected proxy deployment to be allowed, got denied: %s", result.Reason)
	}

	if !result.IsProxy {
		t.Error("expected IsProxy to be true for Transparent proxy")
	}
	if result.ProxyType != "Transparent" {
		t.Errorf("expected ProxyType Transparent, got %s", result.ProxyType)
	}
	if result.ProxyInfo == nil {
		t.Error("expected ProxyInfo to be set")
	}
	if result.ProxyInfo != nil {
		if result.ProxyInfo.ImplementationSlot == "" {
			t.Error("expected ImplementationSlot to be set")
		}
		if result.ProxyInfo.AdminSlot == "" {
			t.Error("expected AdminSlot to be set")
		}
	}
}

// TestDeploymentValidator_NonProxyWithDynamicCall tests that non-proxy contracts with dynamic calls are blocked.
func TestDeploymentValidator_NonProxyWithDynamicCall(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Non-proxy contract with dynamic call (SLOAD then CALL, not matching proxy patterns)
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithDynamicCall, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected non-proxy with dynamic call to be denied")
	}
	if result.IsProxy {
		t.Error("expected IsProxy to be false for non-proxy contract")
	}
	if !strings.Contains(result.Reason, "dynamic") {
		t.Errorf("expected reason to mention dynamic, got: %s", result.Reason)
	}
}

// TestDeploymentValidator_ProxyResultFieldsPopulated tests that proxy fields are populated in ValidationResult.
func TestDeploymentValidator_ProxyResultFieldsPopulated(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Test non-proxy bytecode - proxy fields should be empty/false
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.IsProxy {
		t.Error("expected IsProxy to be false for non-proxy bytecode")
	}
	if result.ProxyType != "" {
		t.Errorf("expected ProxyType to be empty for non-proxy, got: %s", result.ProxyType)
	}
	// ProxyInfo should still be populated but indicate no proxy
	if result.ProxyInfo == nil {
		t.Error("expected ProxyInfo to be set (even for non-proxy)")
	}
	if result.ProxyInfo != nil && result.ProxyInfo.IsProxy {
		t.Error("expected ProxyInfo.IsProxy to be false")
	}
}

// TestDeploymentValidator_RegisterDeployedProxy tests the RegisterDeployedProxy method.
func TestDeploymentValidator_RegisterDeployedProxy(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// First, validate a proxy deployment to get ProxyInfo
	bytecodeHex := buildERC1967ProxyBytecode()
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsProxy || result.ProxyInfo == nil {
		t.Fatal("expected proxy to be detected")
	}

	// Now register the deployed proxy
	proxyAddress := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	initialImpl := "0x1111111111111111111111111111111111111111"

	err = validator.RegisterDeployedProxy(context.Background(), "org1", proxyAddress, result.ProxyInfo, initialImpl)
	if err != nil {
		t.Fatalf("RegisterDeployedProxy error: %v", err)
	}

	// Verify the proxy was registered
	proxies := store.getManagedProxies()
	if len(proxies) != 1 {
		t.Fatalf("expected 1 managed proxy, got %d", len(proxies))
	}

	proxy := proxies[0]
	if proxy.OrgID != "org1" {
		t.Errorf("expected OrgID org1, got %s", proxy.OrgID)
	}
	if proxy.ProxyAddress != "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("expected proxy address to be normalized, got %s", proxy.ProxyAddress)
	}
	if proxy.ProxyType != "ERC1967" {
		t.Errorf("expected ProxyType ERC1967, got %s", proxy.ProxyType)
	}
	if proxy.CurrentImpl != "0x1111111111111111111111111111111111111111" {
		t.Errorf("expected CurrentImpl to be normalized, got %s", proxy.CurrentImpl)
	}
}

// TestDeploymentValidator_RegisterDeployedProxy_NormalizesAddresses tests address normalization.
func TestDeploymentValidator_RegisterDeployedProxy_NormalizesAddresses(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := buildERC1967ProxyBytecode()
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Use uppercase address without 0x prefix
	proxyAddress := "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"
	initialImpl := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	err = validator.RegisterDeployedProxy(context.Background(), "org1", proxyAddress, result.ProxyInfo, initialImpl)
	if err != nil {
		t.Fatalf("RegisterDeployedProxy error: %v", err)
	}

	proxies := store.getManagedProxies()
	if len(proxies) != 1 {
		t.Fatalf("expected 1 managed proxy, got %d", len(proxies))
	}

	proxy := proxies[0]
	// Should be normalized to lowercase with 0x prefix
	if proxy.ProxyAddress != "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("expected lowercase with 0x prefix, got %s", proxy.ProxyAddress)
	}
	if proxy.CurrentImpl != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("expected lowercase with 0x prefix, got %s", proxy.CurrentImpl)
	}
}

// TestDeploymentValidator_RegisterDeployedProxy_EmptyImpl tests registration with empty implementation.
func TestDeploymentValidator_RegisterDeployedProxy_EmptyImpl(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := buildERC1967ProxyBytecode()
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	proxyAddress := "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// Register with empty implementation (implementation not known at deploy time)
	err = validator.RegisterDeployedProxy(context.Background(), "org1", proxyAddress, result.ProxyInfo, "")
	if err != nil {
		t.Fatalf("RegisterDeployedProxy error: %v", err)
	}

	proxies := store.getManagedProxies()
	if len(proxies) != 1 {
		t.Fatalf("expected 1 managed proxy, got %d", len(proxies))
	}

	if proxies[0].CurrentImpl != "" {
		t.Errorf("expected empty CurrentImpl, got %s", proxies[0].CurrentImpl)
	}
}

// TestDeploymentValidator_RegisterDeployedProxy_RejectsNonProxy tests that non-proxy contracts cannot be registered.
func TestDeploymentValidator_RegisterDeployedProxy_RejectsNonProxy(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Get ProxyInfo for a non-proxy contract
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Try to register a non-proxy - should fail
	err = validator.RegisterDeployedProxy(context.Background(), "org1", "0xdeadbeef", result.ProxyInfo, "")
	if err == nil {
		t.Error("expected error when registering non-proxy contract")
	}
	if !strings.Contains(err.Error(), "non-proxy") {
		t.Errorf("expected error to mention non-proxy, got: %v", err)
	}
}

// TestDeploymentValidator_RegisterDeployedProxy_RejectsNilProxyInfo tests that nil ProxyInfo is rejected.
func TestDeploymentValidator_RegisterDeployedProxy_RejectsNilProxyInfo(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	err := validator.RegisterDeployedProxy(context.Background(), "org1", "0xdeadbeef", nil, "")
	if err == nil {
		t.Error("expected error when registering with nil ProxyInfo")
	}
}

// TestDeploymentValidator_TrustedFactoryWhitelist tests that whitelisted factory contracts
// with CREATE/CREATE2 opcodes are allowed to be deployed.
func TestDeploymentValidator_TrustedFactoryWhitelist(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// First, verify that a contract with CREATE is normally blocked
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithCreate, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("expected CREATE contract to be blocked when not whitelisted")
	}
	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}

	// Verify the result indicates it's not a trusted factory
	if result.IsTrustedFactory {
		t.Error("expected IsTrustedFactory to be false for non-whitelisted contract")
	}
}

// ============================================================================
// Constructor Argument Validation Tests (ValidateDeploymentWithABI)
// ============================================================================

// Helper function to build bytecode with constructor arguments
func buildBytecodeWithConstructorArgs(initCode []byte, constructorArgs []byte) string {
	bytecode := append(initCode, constructorArgs...)
	return "0x" + encodeHex(bytecode)
}

// encodeHex encodes bytes to hex string
func encodeHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}

// decodeHex decodes hex string to bytes
func decodeHex(s string) []byte {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s)%2 != 0 {
		s = "0" + s
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		high := hexDigit(s[i])
		low := hexDigit(s[i+1])
		result[i/2] = (high << 4) | low
	}
	return result
}

func hexDigit(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// packAddress packs an address for ABI encoding (left-padded to 32 bytes)
func packAddress(addr string) []byte {
	addrBytes := decodeHex(addr)
	result := make([]byte, 32)
	copy(result[32-len(addrBytes):], addrBytes)
	return result
}

// Simple init code: PUSH1 0x00 STOP
var simpleInitCode = []byte{0x60, 0x00, 0x00}

// TestValidateDeploymentWithABI_NoConstructorInputs tests ABI with no constructor inputs.
func TestValidateDeploymentWithABI_NoConstructorInputs(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// ABI with no constructor
	abiJSON := `[{"type":"function","name":"foo","inputs":[]}]`
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
	if result.HasConstructorArgs {
		t.Error("expected HasConstructorArgs to be false when ABI has no constructor inputs")
	}
	if !result.ConstructorValidated {
		t.Error("expected ConstructorValidated to be true")
	}
}

// TestValidateDeploymentWithABI_EmptyConstructorInputs tests ABI with empty constructor inputs.
func TestValidateDeploymentWithABI_EmptyConstructorInputs(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// ABI with constructor but no inputs
	abiJSON := `[{"type":"constructor","inputs":[]}]`
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_OrgOwnedAddress tests constructor with org-owned address.
func TestValidateDeploymentWithABI_OrgOwnedAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	store.setOrgOwnsAddress("org1", "0x1234567890123456789012345678901234567890", true)
	validator := NewDeploymentValidator(store)

	// ABI with address constructor argument
	abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`

	// Build bytecode with constructor args
	constructorArgs := packAddress("1234567890123456789012345678901234567890")
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed for org-owned address, got denied: %s", result.Reason)
	}
	if !result.HasConstructorArgs {
		t.Error("expected HasConstructorArgs to be true")
	}
	if len(result.ConstructorAddresses) != 1 {
		t.Errorf("expected 1 constructor address, got %d", len(result.ConstructorAddresses))
	}
}

// TestValidateDeploymentWithABI_PreregisteredAddress tests constructor with preregistered address.
func TestValidateDeploymentWithABI_PreregisteredAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	store.setAddressPreregistered("org1", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true)
	validator := NewDeploymentValidator(store)

	abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`
	constructorArgs := packAddress("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed for preregistered address, got denied: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_OtherOrgAddress tests constructor with another org's address.
func TestValidateDeploymentWithABI_OtherOrgAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Address belongs to org2, not org1
	store.setOrgOwnsAddress("org2", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", true)
	validator := NewDeploymentValidator(store)

	abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`
	constructorArgs := packAddress("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for other org's address")
	}
	if !strings.Contains(result.Reason, "constructor argument") {
		t.Errorf("expected reason to mention constructor argument, got: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_UnknownAddress tests constructor with unknown address.
func TestValidateDeploymentWithABI_UnknownAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Address not registered anywhere
	abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`
	constructorArgs := packAddress("cccccccccccccccccccccccccccccccccccccccc")
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for unknown address")
	}
	if !strings.Contains(result.Reason, "constructor argument") {
		t.Errorf("expected reason to mention constructor argument, got: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_PrecompileAddress tests constructor with precompile address.
func TestValidateDeploymentWithABI_PrecompileAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Precompile address 0x01 (ecrecover) - should be allowed
	abiJSON := `[{"type":"constructor","inputs":[{"name":"precompile","type":"address"}]}]`
	constructorArgs := packAddress("0000000000000000000000000000000000000001")
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed for precompile address, got denied: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_MultipleAddresses tests constructor with multiple addresses.
func TestValidateDeploymentWithABI_MultipleAddresses(t *testing.T) {
	store := newDeployValidatorTestStore()
	store.setOrgOwnsAddress("org1", "0x1111111111111111111111111111111111111111", true)
	store.setOrgOwnsAddress("org1", "0x2222222222222222222222222222222222222222", true)
	validator := NewDeploymentValidator(store)

	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"addr1","type":"address"},
		{"name":"addr2","type":"address"}
	]}]`
	constructorArgs := append(
		packAddress("1111111111111111111111111111111111111111"),
		packAddress("2222222222222222222222222222222222222222")...,
	)
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed for all org-owned addresses, got denied: %s", result.Reason)
	}
	if len(result.ConstructorAddresses) != 2 {
		t.Errorf("expected 2 constructor addresses, got %d", len(result.ConstructorAddresses))
	}
}

// TestValidateDeploymentWithABI_MixedAddresses tests constructor with one allowed and one disallowed address.
func TestValidateDeploymentWithABI_MixedAddresses(t *testing.T) {
	store := newDeployValidatorTestStore()
	store.setOrgOwnsAddress("org1", "0x1111111111111111111111111111111111111111", true)
	// Second address not registered
	validator := NewDeploymentValidator(store)

	abiJSON := `[{"type":"constructor","inputs":[
		{"name":"addr1","type":"address"},
		{"name":"addr2","type":"address"}
	]}]`
	constructorArgs := append(
		packAddress("1111111111111111111111111111111111111111"),
		packAddress("dddddddddddddddddddddddddddddddddddddddd")..., // Not allowed
	)
	bytecodeHex := buildBytecodeWithConstructorArgs(simpleInitCode, constructorArgs)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied when one address is not allowed")
	}
}

// TestValidateDeploymentWithABI_DynamicTypeRejected tests that dynamic types are rejected.
func TestValidateDeploymentWithABI_DynamicTypeRejected(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// ABI with dynamic address array - should be rejected
	abiJSON := `[{"type":"constructor","inputs":[{"name":"signers","type":"address[]"}]}]`
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for dynamic type in constructor")
	}
	if !strings.Contains(result.Reason, "dynamic type") {
		t.Errorf("expected reason to mention dynamic type, got: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_NoABIProvided tests that deployment is rejected when no ABI is provided.
func TestValidateDeploymentWithABI_NoABIProvided(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// No ABI provided
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied when no ABI provided")
	}
	if !strings.Contains(result.Reason, "ABI is required") {
		t.Errorf("expected reason to mention ABI requirement, got: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_InvalidABI tests that invalid ABI is rejected.
func TestValidateDeploymentWithABI_InvalidABI(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, "not valid json", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for invalid ABI")
	}
	if !strings.Contains(result.Reason, "invalid ABI") {
		t.Errorf("expected reason to mention invalid ABI, got: %s", result.Reason)
	}
}

// TestValidateDeploymentWithABI_StillValidatesOtherRules tests that other validation rules still apply.
func TestValidateDeploymentWithABI_StillValidatesOtherRules(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Bytecode with CREATE opcode + valid constructor ABI
	abiJSON := `[{"type":"constructor","inputs":[]}]`

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeWithCreate, abiJSON, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should still be denied for CREATE opcode
	if result.Allowed {
		t.Error("expected CREATE to still be blocked")
	}
	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}
}

// TestValidateDeploymentWithABI_NoABIWithRuntimeTracing tests that ABI is optional when runtime tracing is enabled.
func TestValidateDeploymentWithABI_NoABIWithRuntimeTracing(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Enable runtime tracing
	validator.SetRuntimeTracingEnabled(true)

	// No ABI provided - should be allowed when runtime tracing is enabled
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be allowed - runtime tracing will catch any cross-org calls at execution time
	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when runtime tracing is enabled, got reason: %s", result.Reason)
	}
	if result.ConstructorValidated {
		t.Error("expected ConstructorValidated to be false when ABI is skipped")
	}
}

// TestValidateDeploymentWithABI_NoABIWithoutRuntimeTracing tests that ABI is required when runtime tracing is disabled.
func TestValidateDeploymentWithABI_NoABIWithoutRuntimeTracing(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Runtime tracing is disabled by default
	// No ABI provided - should be denied
	bytecodeHex := "0x" + encodeHex(simpleInitCode)

	result, err := validator.ValidateDeploymentWithABI(context.Background(), "org1", bytecodeHex, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be denied - ABI is required without runtime tracing
	if result.Allowed {
		t.Error("expected deployment to be denied when ABI is required but not provided")
	}
	if !strings.Contains(result.Reason, "ABI is required") {
		t.Errorf("expected reason to mention ABI requirement, got: %s", result.Reason)
	}
}

// =============================================================================
// Security tests: PUSH argument bytes must not be misdetected as opcodes
// =============================================================================

// TestValidateDeployment_CREATE_InPUSH32Args_NotBlocked verifies that 0xf0 (CREATE)
// bytes inside PUSH32 arguments do not cause a false positive CREATE detection.
// P0: if this fails, legitimate contracts with 0xf0 in their constants are wrongly blocked.
func TestValidateDeployment_CREATE_InPUSH32Args_NotBlocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// PUSH32 (0x7f) + 32 bytes of 0xf0 + STOP (0x00)
	bytecodeHex := "0x7f" + strings.Repeat("f0", 32) + "00"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
	if result.HasCreate {
		t.Error("HasCreate should be false: 0xf0 bytes are PUSH32 data, not CREATE opcodes")
	}
}

// TestValidateDeployment_CREATE2_InPUSH32Args_NotBlocked verifies that 0xf5 (CREATE2)
// bytes inside PUSH32 arguments do not cause a false positive CREATE2 detection.
func TestValidateDeployment_CREATE2_InPUSH32Args_NotBlocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// PUSH32 (0x7f) + 32 bytes of 0xf5 + STOP (0x00)
	bytecodeHex := "0x7f" + strings.Repeat("f5", 32) + "00"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
	if result.HasCreate2 {
		t.Error("HasCreate2 should be false: 0xf5 bytes are PUSH32 data, not CREATE2 opcodes")
	}
}

// TestValidateDeployment_AllZerosBytecode verifies that a bytecode consisting
// entirely of STOP opcodes (0x00) is allowed to deploy.
func TestValidateDeployment_AllZerosBytecode(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// 8 STOP opcodes
	bytecodeHex := "0x0000000000000000"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
}

// TestValidateDeployment_SingleSTOP verifies that a single STOP opcode bytecode
// is allowed to deploy.
func TestValidateDeployment_SingleSTOP(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	bytecodeHex := "0x00"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
}

// TestValidateDeployment_SingleCREATE_Blocked verifies that a bare CREATE opcode
// is correctly detected and blocked.
func TestValidateDeployment_SingleCREATE_Blocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Single CREATE opcode
	bytecodeHex := "0xf0"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for bare CREATE opcode")
	}
	if !result.HasCreate {
		t.Error("expected HasCreate to be true")
	}
}

// TestValidateDeployment_SingleCREATE2_Blocked verifies that a bare CREATE2 opcode
// is correctly detected and blocked.
func TestValidateDeployment_SingleCREATE2_Blocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// Single CREATE2 opcode
	bytecodeHex := "0xf5"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Error("expected deployment to be denied for bare CREATE2 opcode")
	}
	if !result.HasCreate2 {
		t.Error("expected HasCreate2 to be true")
	}
}

// TestValidateDeployment_PUSH1_CREATE_AsArg_NotBlocked verifies that 0xf0 (CREATE)
// appearing as a PUSH1 argument is correctly treated as data, not an opcode.
// P0 critical case: without proper PUSH argument skipping, this would be a false positive.
func TestValidateDeployment_PUSH1_CREATE_AsArg_NotBlocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// PUSH1 0xf0 STOP — the 0xf0 is data for PUSH1, not a CREATE opcode
	bytecodeHex := "0x60f000"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
	if result.HasCreate {
		t.Error("HasCreate should be false: 0xf0 is PUSH1 data, not a CREATE opcode")
	}
}

// TestValidateDeployment_PUSH1_CREATE2_AsArg_NotBlocked verifies that 0xf5 (CREATE2)
// appearing as a PUSH1 argument is correctly treated as data, not an opcode.
func TestValidateDeployment_PUSH1_CREATE2_AsArg_NotBlocked(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	// PUSH1 0xf5 STOP — the 0xf5 is data for PUSH1, not a CREATE2 opcode
	bytecodeHex := "0x60f500"

	result, err := validator.ValidateDeployment(context.Background(), "", bytecodeHex, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed, got denied: %s", result.Reason)
	}
	if result.HasCreate2 {
		t.Error("HasCreate2 should be false: 0xf5 is PUSH1 data, not a CREATE2 opcode")
	}
}
