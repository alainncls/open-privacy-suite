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
	orgOwnedAddresses   map[string]map[string]bool // orgID -> address -> owned
	anyOrgRegistrations map[string]bool            // address -> registered to any org
	managedProxies      []*ManagedProxy            // Registered managed proxies
}

func newDeployValidatorTestStore() *deployValidatorTestStore {
	return &deployValidatorTestStore{
		MockStore:           NewMockStore(),
		orgOwnedAddresses:   make(map[string]map[string]bool),
		anyOrgRegistrations: make(map[string]bool),
		managedProxies:      make([]*ManagedProxy, 0),
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

func (s *deployValidatorTestStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	normalizedAddr := normalizeHexAddress(address)
	for addr, registered := range s.anyOrgRegistrations {
		if normalizeHexAddress(addr) == normalizedAddr {
			return registered, nil
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithCreate)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithCreate2)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithDynamicCall)
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

func TestDeploymentValidator_CallingOrgOwnedAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// Register the address as owned by org1
	store.setOrgOwnsAddress("org1", "0x1234567890123456789012345678901234567890", true)

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOrgOwned)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOtherOrg)
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

func TestDeploymentValidator_CallingTrulyPublicAddress(t *testing.T) {
	store := newDeployValidatorTestStore()
	// The address is NOT registered to any org (truly public)
	// Don't set any ownership

	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingPublic)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected deployment to be allowed when calling truly public address, got denied: %s", result.Reason)
	}
}

func TestDeploymentValidator_CallingPrecompile(t *testing.T) {
	store := newDeployValidatorTestStore()
	validator := NewDeploymentValidator(store)

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingPrecompile)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeDelegatecallOrgOwned)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeDelegatecallOtherOrg)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeInvalid)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", "0x")
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodePublicDelegatecall)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeCallingOrgOwned)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeMultipleCalls)
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

	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeMixedCalls)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeWithDynamicCall)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeHex)
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
	result, err := validator.ValidateDeployment(context.Background(), "org1", bytecodeNoExternalCalls)
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
