package bytecode

import (
	"encoding/hex"
	"testing"
)

func TestDetectProxyPattern_NilBytecode(t *testing.T) {
	info := DetectProxyPattern(nil)
	if info == nil {
		t.Fatal("expected non-nil result")
	}
	if info.IsProxy {
		t.Error("expected IsProxy to be false for nil bytecode")
	}
	if info.ProxyType != ProxyTypeNone {
		t.Errorf("expected ProxyType to be empty, got %s", info.ProxyType)
	}
}

func TestDetectProxyPattern_EmptyBytecode(t *testing.T) {
	bc, _ := Parse([]byte{})
	info := DetectProxyPattern(bc)
	if info.IsProxy {
		t.Error("expected IsProxy to be false for empty bytecode")
	}
}

func TestDetectProxyPattern_NoDelegateCall(t *testing.T) {
	// Simple bytecode without DELEGATECALL - not a proxy
	bytecode := []byte{PUSH1, 0x80, PUSH1, 0x40, MSTORE, STOP}
	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if info.IsProxy {
		t.Error("expected IsProxy to be false without DELEGATECALL")
	}
}

func TestDetectProxyPattern_ERC1967Implementation(t *testing.T) {
	// Create bytecode with ERC-1967 implementation slot pattern:
	// PUSH32 <implementation slot> -> SLOAD -> ... -> DELEGATECALL

	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

	bytecode := []byte{}
	// PUSH32 implementation slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, implementationSlot...)
	// SLOAD to read implementation address
	bytecode = append(bytecode, SLOAD)
	// Some stack operations
	bytecode = append(bytecode, DUP1, PUSH1, 0x00)
	// DELEGATECALL
	bytecode = append(bytecode, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for ERC-1967 pattern")
	}
	if info.ProxyType != ProxyTypeERC1967 {
		t.Errorf("expected ProxyType ERC1967, got %s", info.ProxyType)
	}
	if info.ImplementationSlot != "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" {
		t.Errorf("unexpected implementation slot: %s", info.ImplementationSlot)
	}
}

func TestDetectProxyPattern_TransparentProxy(t *testing.T) {
	// Transparent proxy has both implementation and admin slots
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	adminSlot, _ := hex.DecodeString("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")

	bytecode := []byte{}
	// Implementation slot pattern
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, implementationSlot...)
	bytecode = append(bytecode, SLOAD, DUP1)

	// Admin slot pattern
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, adminSlot...)
	bytecode = append(bytecode, SLOAD)

	// DELEGATECALL
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for Transparent proxy")
	}
	if info.ProxyType != ProxyTypeTransparent {
		t.Errorf("expected ProxyType Transparent, got %s", info.ProxyType)
	}
	if info.ImplementationSlot == "" {
		t.Error("expected implementation slot to be set")
	}
	if info.AdminSlot == "" {
		t.Error("expected admin slot to be set")
	}
}

func TestDetectProxyPattern_BeaconProxy(t *testing.T) {
	// Beacon proxy has beacon slot
	beaconSlot, _ := hex.DecodeString("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")

	bytecode := []byte{}
	// Beacon slot pattern
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, beaconSlot...)
	bytecode = append(bytecode, SLOAD, DUP1)
	// DELEGATECALL
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for Beacon proxy")
	}
	if info.ProxyType != ProxyTypeBeacon {
		t.Errorf("expected ProxyType Beacon, got %s", info.ProxyType)
	}
	if info.BeaconSlot == "" {
		t.Error("expected beacon slot to be set")
	}
}

func TestDetectProxyPattern_UUPSProxy(t *testing.T) {
	// UUPS proxy has implementation slot AND upgrade selectors in bytecode
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	upgradeToSelector, _ := hex.DecodeString("3659cfe6") // upgradeTo(address)

	bytecode := []byte{}
	// Implementation slot pattern
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, implementationSlot...)
	bytecode = append(bytecode, SLOAD, DUP1)

	// Upgrade selector check (common in UUPS)
	bytecode = append(bytecode, PUSH4)
	bytecode = append(bytecode, upgradeToSelector...)
	bytecode = append(bytecode, EQ)

	// DELEGATECALL
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for UUPS proxy")
	}
	if info.ProxyType != ProxyTypeUUPS {
		t.Errorf("expected ProxyType UUPS, got %s", info.ProxyType)
	}
	if len(info.UpgradeSelectors) == 0 {
		t.Error("expected upgrade selectors to be found")
	}
}

func TestDetectProxyPattern_DiamondProxy(t *testing.T) {
	// Diamond proxy has diamond-specific selectors
	diamondCutSelector, _ := hex.DecodeString("1f931c1c")  // diamondCut
	facetsSelector, _ := hex.DecodeString("7a0ed627")     // facets()

	bytecode := []byte{}
	// Diamond cut selector
	bytecode = append(bytecode, PUSH4)
	bytecode = append(bytecode, diamondCutSelector...)
	bytecode = append(bytecode, EQ, JUMPI)

	// Facets selector
	bytecode = append(bytecode, PUSH4)
	bytecode = append(bytecode, facetsSelector...)
	bytecode = append(bytecode, EQ, JUMPI)

	// DELEGATECALL (required for proxy detection)
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for Diamond proxy")
	}
	if info.ProxyType != ProxyTypeDiamond {
		t.Errorf("expected ProxyType Diamond, got %s", info.ProxyType)
	}
}

func TestDetectProxyPattern_DiamondStorageSlot(t *testing.T) {
	// Diamond proxy with storage slot
	diamondSlot, _ := hex.DecodeString("c8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c")

	bytecode := []byte{}
	// Diamond storage slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, diamondSlot...)
	bytecode = append(bytecode, SLOAD)

	// DELEGATECALL
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for Diamond proxy with storage slot")
	}
	if info.ProxyType != ProxyTypeDiamond {
		t.Errorf("expected ProxyType Diamond, got %s", info.ProxyType)
	}
}

func TestDetectProxyPattern_UnknownProxyPattern(t *testing.T) {
	// Proxy with DELEGATECALL but using custom storage slot (not ERC-1967)
	customSlot := make([]byte, 32)
	for i := range customSlot {
		customSlot[i] = byte(i)
	}

	bytecode := []byte{}
	// Custom storage slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, customSlot...)
	bytecode = append(bytecode, SLOAD, DUP1)
	// DELEGATECALL
	bytecode = append(bytecode, PUSH1, 0x00, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true for unknown proxy pattern")
	}
	if info.ProxyType != ProxyTypeUnknown {
		t.Errorf("expected ProxyType Unknown, got %s", info.ProxyType)
	}
}

func TestDetectProxyPattern_NonProxy_RegularContract(t *testing.T) {
	// A regular contract that uses DELEGATECALL but not as a proxy pattern
	// (e.g., for library calls with hardcoded addresses)

	address := make([]byte, 20)
	for i := range address {
		address[i] = 0xAB
	}

	bytecode := []byte{}
	// PUSH20 address (not from storage)
	bytecode = append(bytecode, PUSH20)
	bytecode = append(bytecode, address...)
	// DELEGATECALL to the hardcoded address
	bytecode = append(bytecode, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	// This should NOT be detected as a proxy because the delegation target
	// is hardcoded, not loaded from storage
	if info.IsProxy {
		t.Error("expected IsProxy to be false for hardcoded DELEGATECALL")
	}
}

func TestDetectProxyPattern_UpgradeSelectors(t *testing.T) {
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	upgradeToSelector, _ := hex.DecodeString("3659cfe6")        // upgradeTo(address)
	upgradeToAndCallSelector, _ := hex.DecodeString("4f1ef286") // upgradeToAndCall(address,bytes)

	bytecode := []byte{}
	// Implementation slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, implementationSlot...)
	bytecode = append(bytecode, SLOAD)

	// Multiple upgrade selectors
	bytecode = append(bytecode, PUSH4)
	bytecode = append(bytecode, upgradeToSelector...)
	bytecode = append(bytecode, PUSH4)
	bytecode = append(bytecode, upgradeToAndCallSelector...)

	// DELEGATECALL
	bytecode = append(bytecode, DELEGATECALL)
	bytecode = append(bytecode, STOP)

	bc, err := Parse(bytecode)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	info := DetectProxyPattern(bc)
	if !info.IsProxy {
		t.Error("expected IsProxy to be true")
	}
	if len(info.UpgradeSelectors) != 2 {
		t.Errorf("expected 2 upgrade selectors, got %d", len(info.UpgradeSelectors))
	}
}

func TestIsUpgradeableProxy(t *testing.T) {
	tests := []struct {
		name     string
		bytecode []byte
		want     bool
	}{
		{
			name:     "nil bytecode",
			bytecode: nil,
			want:     false,
		},
		{
			name:     "empty bytecode",
			bytecode: []byte{},
			want:     false,
		},
		{
			name:     "simple contract",
			bytecode: []byte{PUSH1, 0x80, STOP},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bc *Bytecode
			if tt.bytecode != nil {
				bc, _ = Parse(tt.bytecode)
			}
			got := IsUpgradeableProxy(bc)
			if got != tt.want {
				t.Errorf("IsUpgradeableProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetProxyImplementationSlot(t *testing.T) {
	// Test with ERC-1967 proxy
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

	bytecode := []byte{PUSH32}
	bytecode = append(bytecode, implementationSlot...)
	bytecode = append(bytecode, SLOAD, DELEGATECALL, STOP)

	bc, _ := Parse(bytecode)
	slot := GetProxyImplementationSlot(bc)

	if slot != "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" {
		t.Errorf("unexpected implementation slot: %s", slot)
	}
}

func TestGetProxyImplementationSlot_NonProxy(t *testing.T) {
	bytecode := []byte{PUSH1, 0x00, STOP}
	bc, _ := Parse(bytecode)
	slot := GetProxyImplementationSlot(bc)

	if slot != "" {
		t.Errorf("expected empty slot for non-proxy, got %s", slot)
	}
}

func TestERC1967Slots_Constants(t *testing.T) {
	// Verify the slot constants are correct
	expectedSlots := map[string]string{
		"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc": "implementation",
		"0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103": "admin",
		"0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50": "beacon",
	}

	for slot, name := range expectedSlots {
		if ERC1967Slots[slot] != name {
			t.Errorf("ERC1967Slots[%s] = %s, want %s", slot, ERC1967Slots[slot], name)
		}
	}

	if len(ERC1967Slots) != len(expectedSlots) {
		t.Errorf("ERC1967Slots has %d entries, want %d", len(ERC1967Slots), len(expectedSlots))
	}
}

func TestUpgradeSelectors_Constants(t *testing.T) {
	expectedSelectors := map[string]string{
		"0x3659cfe6": "upgradeTo(address)",
		"0x4f1ef286": "upgradeToAndCall(address,bytes)",
		"0x5c60da1b": "implementation()",
		"0xf851a440": "admin()",
	}

	for selector, sig := range expectedSelectors {
		if UpgradeSelectors[selector] != sig {
			t.Errorf("UpgradeSelectors[%s] = %s, want %s", selector, UpgradeSelectors[selector], sig)
		}
	}

	if len(UpgradeSelectors) != len(expectedSelectors) {
		t.Errorf("UpgradeSelectors has %d entries, want %d", len(UpgradeSelectors), len(expectedSelectors))
	}
}

func TestProxyType_String(t *testing.T) {
	tests := []struct {
		proxyType ProxyType
		want      string
	}{
		{ProxyTypeNone, ""},
		{ProxyTypeERC1967, "ERC1967"},
		{ProxyTypeTransparent, "Transparent"},
		{ProxyTypeUUPS, "UUPS"},
		{ProxyTypeBeacon, "Beacon"},
		{ProxyTypeDiamond, "Diamond"},
		{ProxyTypeUnknown, "Unknown"},
	}

	for _, tt := range tests {
		if string(tt.proxyType) != tt.want {
			t.Errorf("ProxyType %v string = %s, want %s", tt.proxyType, string(tt.proxyType), tt.want)
		}
	}
}

func TestDetectProxyPattern_PUSH32WithoutSLOAD(t *testing.T) {
	// PUSH32 with ERC-1967 slot but no SLOAD following
	// This should not be detected as a proxy
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")

	bytecode := []byte{PUSH32}
	bytecode = append(bytecode, implementationSlot...)
	// No SLOAD, just some other operations and DELEGATECALL
	bytecode = append(bytecode, POP, PUSH1, 0x00, DELEGATECALL, STOP)

	bc, _ := Parse(bytecode)
	info := DetectProxyPattern(bc)

	// Implementation slot should not be detected without SLOAD
	if info.ImplementationSlot != "" {
		t.Error("expected no implementation slot without SLOAD pattern")
	}
}

func TestDetectProxyPattern_MultipleSlots(t *testing.T) {
	// Test bytecode with all three ERC-1967 slots
	implementationSlot, _ := hex.DecodeString("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")
	adminSlot, _ := hex.DecodeString("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")
	beaconSlot, _ := hex.DecodeString("a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50")

	bytecode := []byte{}
	// Implementation slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, implementationSlot...)
	bytecode = append(bytecode, SLOAD, POP)

	// Admin slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, adminSlot...)
	bytecode = append(bytecode, SLOAD, POP)

	// Beacon slot
	bytecode = append(bytecode, PUSH32)
	bytecode = append(bytecode, beaconSlot...)
	bytecode = append(bytecode, SLOAD)

	// DELEGATECALL
	bytecode = append(bytecode, DELEGATECALL, STOP)

	bc, _ := Parse(bytecode)
	info := DetectProxyPattern(bc)

	if !info.IsProxy {
		t.Error("expected IsProxy to be true")
	}

	// With beacon slot, it should be detected as Beacon proxy
	if info.ProxyType != ProxyTypeBeacon {
		t.Errorf("expected ProxyType Beacon (beacon takes precedence), got %s", info.ProxyType)
	}

	if info.ImplementationSlot == "" {
		t.Error("expected implementation slot to be set")
	}
	if info.AdminSlot == "" {
		t.Error("expected admin slot to be set")
	}
	if info.BeaconSlot == "" {
		t.Error("expected beacon slot to be set")
	}
}
