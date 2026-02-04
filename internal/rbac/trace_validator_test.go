package rbac

import (
	"context"
	"strings"
	"testing"

	"privacy-proxy/internal/tracer"
)

// MockTraceStore implements the Store interface for trace validator tests.
type MockTraceStore struct {
	*MockStore
	sharedInfrastructure map[string]bool            // address -> is shared
	ownedAddresses       map[string]map[string]bool // orgID -> address -> owned
}

func NewMockTraceStore() *MockTraceStore {
	return &MockTraceStore{
		MockStore:            NewMockStore(),
		sharedInfrastructure: make(map[string]bool),
		ownedAddresses:       make(map[string]map[string]bool),
	}
}

func (m *MockTraceStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	addr := strings.ToLower(address)
	return m.sharedInfrastructure[addr], nil
}

func (m *MockTraceStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error {
	addr := strings.ToLower(infra.Address)
	m.sharedInfrastructure[addr] = true
	return nil
}

func (m *MockTraceStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) {
	return nil, nil
}

func (m *MockTraceStore) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	addr := strings.ToLower(address)
	delete(m.sharedInfrastructure, addr)
	return nil
}

func (m *MockTraceStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	addr := strings.ToLower(address)
	if orgAddrs, ok := m.ownedAddresses[orgID]; ok {
		return orgAddrs[addr], nil
	}
	return false, nil
}

func (m *MockTraceStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	addr := strings.ToLower(address)
	for orgID, addrs := range m.ownedAddresses {
		if addrs[addr] {
			return orgID, nil
		}
	}
	return "", nil
}

func (m *MockTraceStore) AddSharedInfrastructure(address string) {
	addr := strings.ToLower(address)
	m.sharedInfrastructure[addr] = true
}

func (m *MockTraceStore) AddOwnedAddress(orgID, address string) {
	addr := strings.ToLower(address)
	if m.ownedAddresses[orgID] == nil {
		m.ownedAddresses[orgID] = make(map[string]bool)
	}
	m.ownedAddresses[orgID][addr] = true
}

func TestValidateTrace_NilTrace(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected nil trace to be allowed")
	}
}

func TestValidateTrace_EmptyTrace(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected empty trace to be allowed")
	}
}

func TestValidateTrace_CreateDenied(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE", From: "0xsender", To: "0xnewcontract"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE to be denied")
	}
	if !strings.Contains(result.Reason, "CREATE") {
		t.Errorf("expected reason to mention CREATE, got: %s", result.Reason)
	}
}

func TestValidateTrace_Create2Denied(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		HasCreate2: true,
		CallTargets: []tracer.CallTarget{
			{Type: "CREATE2", From: "0xsender", To: "0xnewcontract"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected CREATE2 to be denied")
	}
	if !strings.Contains(result.Reason, "CREATE2") {
		t.Errorf("expected reason to mention CREATE2, got: %s", result.Reason)
	}
}

func TestValidateTrace_PrecompileAllowed(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	// Trace calling precompile address 0x01 (ecrecover)
	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x0000000000000000000000000000000000000001"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected precompile call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_SharedInfrastructureAllowed(t *testing.T) {
	store := NewMockTraceStore()
	// Register Uniswap router as shared infrastructure
	store.AddSharedInfrastructure("0xe592427a0aece92de3edee1f18e0157c05861564")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xe592427a0aece92de3edee1f18e0157c05861564"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected shared infrastructure call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_OrgOwnedContractAllowed(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1234567890123456789012345678901234567890")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1234567890123456789012345678901234567890"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected org-owned contract call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_OtherOrgContractDenied(t *testing.T) {
	store := NewMockTraceStore()
	// Register contract as owned by org2 (not the user's org)
	store.AddOwnedAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
	}

	// User is member of org1, not org2
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected call to other org's contract to be denied")
	}
	if !strings.Contains(result.Reason, "another organization") {
		t.Errorf("expected reason to mention another organization, got: %s", result.Reason)
	}
	if result.DeniedTarget != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("expected DeniedTarget to be the denied address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_PublicContractAllowed(t *testing.T) {
	store := NewMockTraceStore()
	// Contract not registered to any org - it's public

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected public contract call to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_MultiOrgUserAllowed(t *testing.T) {
	store := NewMockTraceStore()
	// User is member of both org1 and org2
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddOwnedAddress("org2", "0x2222222222222222222222222222222222222222")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			{Type: "CALL", From: "0x1111", To: "0x2222222222222222222222222222222222222222"},
		},
	}

	// User is member of both orgs
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true, "org2": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected multi-org user to access both orgs' contracts, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_MixedTargets(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddSharedInfrastructure("0xcccccccccccccccccccccccccccccccccccccccc")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// Org-owned contract
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			// Precompile
			{Type: "STATICCALL", From: "0x1111", To: "0x0000000000000000000000000000000000000002"},
			// Shared infrastructure
			{Type: "CALL", From: "0x1111", To: "0xcccccccccccccccccccccccccccccccccccccccc"},
			// Public contract
			{Type: "DELEGATECALL", From: "0x1111", To: "0xdddddddddddddddddddddddddddddddddddddddd"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected mixed valid targets to be allowed, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_DenyOnFirstViolation(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")
	store.AddOwnedAddress("org2", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") // Other org

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// First call is allowed
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
			// Second call is to another org - should deny
			{Type: "CALL", From: "0x1111", To: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			// Third call would be allowed but we should never reach it
			{Type: "CALL", From: "0xaaaa", To: "0x0000000000000000000000000000000000000001"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected trace to be denied on first violation")
	}
	if result.DeniedTarget != "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("expected DeniedTarget to be the violating address, got: %s", result.DeniedTarget)
	}
}

func TestValidateTrace_AddressNormalization(t *testing.T) {
	store := NewMockTraceStore()
	// Register with lowercase
	store.AddOwnedAddress("org1", "0xabcdef1234567890abcdef1234567890abcdef12")

	validator := NewTraceValidator(store)

	// Trace uses uppercase
	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected address normalization to work, got denied: %s", result.Reason)
	}
}

func TestValidateTrace_EmptyUserOrgs(t *testing.T) {
	store := NewMockTraceStore()
	store.AddOwnedAddress("org1", "0x1111111111111111111111111111111111111111")

	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			{Type: "CALL", From: "0xsender", To: "0x1111111111111111111111111111111111111111"},
		},
	}

	// User has no org memberships
	result, err := validator.ValidateTrace(context.Background(), map[string]bool{}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allowed {
		t.Errorf("expected user with no orgs to be denied access to org-owned contract")
	}
}

func TestValidateTrace_SkipsZeroAddress(t *testing.T) {
	store := NewMockTraceStore()
	validator := NewTraceValidator(store)

	trace := &tracer.TraceResult{
		CallTargets: []tracer.CallTarget{
			// Zero address (e.g., from ETH transfer)
			{Type: "CALL", From: "0xsender", To: "0x0000000000000000000000000000000000000000"},
			// Empty address
			{Type: "CALL", From: "0xsender", To: ""},
		},
	}

	result, err := validator.ValidateTrace(context.Background(), map[string]bool{"org1": true}, trace)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allowed {
		t.Errorf("expected zero/empty addresses to be skipped, got denied: %s", result.Reason)
	}
}

// TestValidateTrace_TableDriven provides comprehensive table-driven tests.
func TestValidateTrace_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		setupStore     func(*MockTraceStore)
		userOrgIDs     map[string]bool
		trace          *tracer.TraceResult
		expectAllowed  bool
		expectReason   string
		expectDenied   string
	}{
		{
			name:          "nil trace allowed",
			setupStore:    func(s *MockTraceStore) {},
			userOrgIDs:    map[string]bool{"org1": true},
			trace:         nil,
			expectAllowed: true,
		},
		{
			name:       "CREATE blocked",
			setupStore: func(s *MockTraceStore) {},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				HasCreate: true,
			},
			expectAllowed: false,
			expectReason:  "CREATE",
		},
		{
			name:       "all precompiles allowed",
			setupStore: func(s *MockTraceStore) {},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0x0000000000000000000000000000000000000001"},
					{Type: "STATICCALL", To: "0x0000000000000000000000000000000000000002"},
					{Type: "CALL", To: "0x0000000000000000000000000000000000000009"},
				},
			},
			expectAllowed: true,
		},
		{
			name: "shared infra allowed",
			setupStore: func(s *MockTraceStore) {
				s.AddSharedInfrastructure("0xsharedrouter")
			},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0xsharedrouter"},
				},
			},
			expectAllowed: true,
		},
		{
			name: "cross-org isolation enforced",
			setupStore: func(s *MockTraceStore) {
				s.AddOwnedAddress("org2", "0xorg2contract")
			},
			userOrgIDs: map[string]bool{"org1": true},
			trace: &tracer.TraceResult{
				CallTargets: []tracer.CallTarget{
					{Type: "CALL", To: "0xorg2contract"},
				},
			},
			expectAllowed: false,
			expectReason:  "another organization",
			expectDenied:  "0xorg2contract",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockTraceStore()
			tt.setupStore(store)

			validator := NewTraceValidator(store)
			result, err := validator.ValidateTrace(context.Background(), tt.userOrgIDs, tt.trace)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allowed != tt.expectAllowed {
				t.Errorf("Allowed = %v, want %v (reason: %s)", result.Allowed, tt.expectAllowed, result.Reason)
			}

			if tt.expectReason != "" && !strings.Contains(result.Reason, tt.expectReason) {
				t.Errorf("Reason = %q, want to contain %q", result.Reason, tt.expectReason)
			}

			if tt.expectDenied != "" && result.DeniedTarget != tt.expectDenied {
				t.Errorf("DeniedTarget = %q, want %q", result.DeniedTarget, tt.expectDenied)
			}
		})
	}
}
