package rbac

import (
	"context"
	"testing"
	"time"
)

// MockCrossOrgStore is a comprehensive mock store for testing cross-org isolation.
// It implements the full Store interface with configurable behaviors.
type MockCrossOrgStore struct {
	users                 map[string]*User                  // externalID -> User
	organizations         map[string]*Organization          // orgID -> Organization
	memberships           map[string][]*MembershipWithDetails // userID -> memberships
	contractOwners        map[string]string                  // lowercase address -> orgID
	registeredToAnyOrg    map[string]bool                    // lowercase address -> bool
	addressOwnedByOrg     map[string]map[string]bool         // address -> orgID -> bool
	groupAccess           map[string]*GroupAccess            // groupID -> GroupAccess
	cachedPermissions     map[string]*EffectivePermissions   // userID:orgID -> perms
	contractGrants        map[string][]*ContractGrant        // groupID -> grants
}

func NewMockCrossOrgStore() *MockCrossOrgStore {
	return &MockCrossOrgStore{
		users:                 make(map[string]*User),
		organizations:         make(map[string]*Organization),
		memberships:           make(map[string][]*MembershipWithDetails),
		contractOwners:        make(map[string]string),
		registeredToAnyOrg:    make(map[string]bool),
		addressOwnedByOrg:     make(map[string]map[string]bool),
		groupAccess:           make(map[string]*GroupAccess),
		cachedPermissions:     make(map[string]*EffectivePermissions),
		contractGrants:        make(map[string][]*ContractGrant),
	}
}

// User operations
func (m *MockCrossOrgStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	return m.users[externalID], nil
}

func (m *MockCrossOrgStore) CreateUser(ctx context.Context, user *User) error {
	m.users[user.ExternalID] = user
	return nil
}

func (m *MockCrossOrgStore) GetUser(ctx context.Context, id string) (*User, error) {
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (m *MockCrossOrgStore) UpdateUser(ctx context.Context, user *User) error { return nil }
func (m *MockCrossOrgStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteUser(ctx context.Context, id string) error { return nil }

// Organization operations
func (m *MockCrossOrgStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return m.organizations[id], nil
}

func (m *MockCrossOrgStore) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	for _, org := range m.organizations {
		if org.Slug == slug {
			return org, nil
		}
	}
	return nil, nil
}

func (m *MockCrossOrgStore) CreateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockCrossOrgStore) UpdateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockCrossOrgStore) ListOrganizations(ctx context.Context) ([]*Organization, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteOrganization(ctx context.Context, id string) error { return nil }

// Membership operations
func (m *MockCrossOrgStore) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	return m.memberships[userID], nil
}

func (m *MockCrossOrgStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	var result []*MembershipWithDetails
	for _, ms := range m.memberships[userID] {
		if ms.Group != nil && ms.Group.OrgID == orgID {
			result = append(result, ms)
		}
	}
	return result, nil
}

func (m *MockCrossOrgStore) CreateMembership(ctx context.Context, membership *UserMembership) error { return nil }
func (m *MockCrossOrgStore) GetMembership(ctx context.Context, id string) (*UserMembership, error) { return nil, nil }
func (m *MockCrossOrgStore) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error) { return nil, nil }
func (m *MockCrossOrgStore) UpdateMembership(ctx context.Context, membership *UserMembership) error { return nil }
func (m *MockCrossOrgStore) ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockCrossOrgStore) ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteMembership(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) DeleteExpiredMemberships(ctx context.Context) (int64, error) { return 0, nil }

// Contract ownership operations - CRITICAL for cross-org isolation
func (m *MockCrossOrgStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	return m.contractOwners[normalizeAddress(address)], nil
}

func (m *MockCrossOrgStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	return m.registeredToAnyOrg[normalizeAddress(address)], nil
}

func (m *MockCrossOrgStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if orgMap, ok := m.addressOwnedByOrg[normalizeAddress(address)]; ok {
		return orgMap[orgID], nil
	}
	return false, nil
}

// Contract operations
func (m *MockCrossOrgStore) CreateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockCrossOrgStore) GetContract(ctx context.Context, id string) (*Contract, error) { return nil, nil }
func (m *MockCrossOrgStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) { return nil, nil }
func (m *MockCrossOrgStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) { return nil, nil }
func (m *MockCrossOrgStore) UpdateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockCrossOrgStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) { return nil, nil }
func (m *MockCrossOrgStore) ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Contract, int, error) { return nil, 0, nil }
func (m *MockCrossOrgStore) DeleteContract(ctx context.Context, id string) error { return nil }

// Group operations
func (m *MockCrossOrgStore) CreateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockCrossOrgStore) GetGroup(ctx context.Context, id string) (*Group, error) { return nil, nil }
func (m *MockCrossOrgStore) GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error) { return nil, nil }
func (m *MockCrossOrgStore) UpdateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockCrossOrgStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error) { return nil, nil }
func (m *MockCrossOrgStore) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Group, int, error) { return nil, 0, nil }
func (m *MockCrossOrgStore) ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteGroup(ctx context.Context, id string) error { return nil }
func (m *MockCrossOrgStore) GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) {
	return []*Group{}, nil
}

// GroupAccess operations
func (m *MockCrossOrgStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) {
	return m.groupAccess[groupID], nil
}
func (m *MockCrossOrgStore) CreateGroupAccess(ctx context.Context, access *GroupAccess) error { return nil }
func (m *MockCrossOrgStore) UpdateGroupAccess(ctx context.Context, access *GroupAccess) error { return nil }
func (m *MockCrossOrgStore) DeleteGroupAccess(ctx context.Context, groupID string) error { return nil }

// Contract grant operations
func (m *MockCrossOrgStore) CreateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockCrossOrgStore) GetContractGrant(ctx context.Context, id string) (*ContractGrant, error) { return nil, nil }
func (m *MockCrossOrgStore) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error) { return nil, nil }
func (m *MockCrossOrgStore) UpdateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockCrossOrgStore) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error) { return nil, nil }
func (m *MockCrossOrgStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) {
	return m.contractGrants[groupID], nil
}
func (m *MockCrossOrgStore) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteContractGrant(ctx context.Context, id string) error { return nil }

// Cache operations
func (m *MockCrossOrgStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	return m.cachedPermissions[userID+":"+orgID], nil
}
func (m *MockCrossOrgStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	m.cachedPermissions[perms.UserID+":"+perms.OrgID] = perms
	return nil
}
func (m *MockCrossOrgStore) InvalidateCacheForUser(ctx context.Context, userID string) error { return nil }
func (m *MockCrossOrgStore) InvalidateCacheForOrg(ctx context.Context, orgID string) error { return nil }
func (m *MockCrossOrgStore) InvalidateCacheForGroup(ctx context.Context, groupID string) error { return nil }
func (m *MockCrossOrgStore) CleanupExpiredCache(ctx context.Context) (int64, error) { return 0, nil }

// Audit log operations
func (m *MockCrossOrgStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error { return nil }
func (m *MockCrossOrgStore) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }
func (m *MockCrossOrgStore) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }

// Preregistered address operations
func (m *MockCrossOrgStore) CreatePreregisteredAddresses(ctx context.Context, addresses []*PreregisteredAddress) error { return nil }
func (m *MockCrossOrgStore) ListPreregisteredAddresses(ctx context.Context, orgID string) ([]*PreregisteredAddress, error) { return nil, nil }
func (m *MockCrossOrgStore) GetPreregisteredAddressByAddress(ctx context.Context, orgID, address string) (*PreregisteredAddress, error) { return nil, nil }
func (m *MockCrossOrgStore) DeletePreregisteredAddress(ctx context.Context, orgID, address string) error { return nil }
func (m *MockCrossOrgStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) { return false, nil }
func (m *MockCrossOrgStore) MarkAddressUsed(ctx context.Context, address string) error { return nil }

// Managed proxy operations
func (m *MockCrossOrgStore) CreateManagedProxy(ctx context.Context, proxy *ManagedProxy) error { return nil }
func (m *MockCrossOrgStore) GetManagedProxy(ctx context.Context, address string) (*ManagedProxy, error) { return nil, nil }
func (m *MockCrossOrgStore) UpdateManagedProxyImpl(ctx context.Context, address, newImpl string) error { return nil }
func (m *MockCrossOrgStore) IsManagedProxy(ctx context.Context, address string) (bool, error) { return false, nil }

// Constructor ABI operations
func (m *MockCrossOrgStore) GetConstructorABI(ctx context.Context, orgID, address string) (string, error) { return "", nil }
func (m *MockCrossOrgStore) UpdateConstructorABI(ctx context.Context, orgID, address, abi string) error { return nil }

// Shared infrastructure stubs
func (m *MockCrossOrgStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) { return false, nil }
func (m *MockCrossOrgStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error { return nil }
func (m *MockCrossOrgStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) { return nil, nil }
func (m *MockCrossOrgStore) DeleteSharedInfrastructure(ctx context.Context, address string) error { return nil }

// Helper to normalize address
func normalizeAddress(addr string) string {
	if len(addr) >= 2 && addr[:2] == "0x" {
		return "0x" + addr[2:]
	}
	return addr
}

// setupCrossOrgTestScenario creates a test scenario with two orgs and their contracts.
// OrgA has ContractA, OrgB has ContractB.
// UserA is member of OrgA only, UserB is member of OrgB only.
func setupCrossOrgTestScenario(store *MockCrossOrgStore) {
	// Create organizations
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
	store.organizations["org-a"] = orgA
	store.organizations["org-b"] = orgB

	// Create users
	userA := &User{ID: "user-a", ExternalID: "did:test:user-a", KYC: true, Banned: false}
	userB := &User{ID: "user-b", ExternalID: "did:test:user-b", KYC: true, Banned: false}
	store.users["did:test:user-a"] = userA
	store.users["did:test:user-b"] = userB

	// Create groups
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	groupB := &Group{ID: "group-b", OrgID: "org-b", Slug: "group-b", Name: "Group B"}

	// Create memberships - UserA only in OrgA, UserB only in OrgB
	store.memberships["user-a"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-a", UserID: "user-a", GroupID: "group-a"}, Group: groupA},
	}
	store.memberships["user-b"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-b", UserID: "user-b", GroupID: "group-b"}, Group: groupB},
	}

	// Set up group access - both have default read claims
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		DefaultClaims:  []Claim{ClaimRead},
	}
	store.groupAccess["group-b"] = &GroupAccess{
		ID:             "access-b",
		GroupID:        "group-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		DefaultClaims:  []Claim{ClaimRead},
	}

	// Define contract addresses
	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"

	// Set up contract ownership - CRITICAL for cross-org isolation
	store.contractOwners[contractA] = "org-a"
	store.contractOwners[contractB] = "org-b"

	// Mark contracts as registered to orgs
	store.registeredToAnyOrg[contractA] = true
	store.registeredToAnyOrg[contractB] = true

	// Set up address ownership maps
	store.addressOwnedByOrg[contractA] = map[string]bool{"org-a": true}
	store.addressOwnedByOrg[contractB] = map[string]bool{"org-b": true}

	// Pre-cache permissions (optional, for faster tests)
	// These represent the computed permissions for users in their respective orgs
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{},
		DefaultClaims:  []Claim{ClaimRead},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["user-b:org-b"] = &EffectivePermissions{
		ID:             "perms-b",
		UserID:         "user-b",
		OrgID:          "org-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{},
		DefaultClaims:  []Claim{ClaimRead},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
}

// TestCheckAccessCrossOrgIsolation tests the full CheckAccess flow for cross-org isolation.
// This is the critical test that validates the security fix.
func TestCheckAccessCrossOrgIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	// Create the access controller with a short cache TTL
	controller := NewAccessController(store, 5*time.Minute)

	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"
	publicContract := "0xcccc000000000000000000000000000000000003"

	t.Run("SECURITY-001: User A cannot access Contract B via eth_call", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-a",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:    contractB,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for cross-org contract")
		}
		if result.Reason == "" {
			t.Error("expected a reason for denial")
		}
		if !containsString(result.Reason, "belongs to an organization you are not a member of") {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-002: User B cannot access Contract A via eth_call", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-b",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:    contractA,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for cross-org contract")
		}
		if !containsString(result.Reason, "belongs to an organization you are not a member of") {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-003: User A CAN access their own Contract A", func(t *testing.T) {
		// For this test, we need to configure the user to have access to contractA
		// Since contractA is registered to org-a, user-a should be able to access it
		// via either explicit contract access OR default_claims (since it's in their org)

		// Mark contractA as owned by org-a in addressOwnedByOrg (already done in setup)

		req := &AccessCheckRequest{
			UserExternalID:   "did:test:user-a",
			Method:           "eth_call",
			Params:           []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:    contractA,
			FunctionSelector: "",
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// This should be allowed because user is in the org that owns the contract
		if !result.Allowed {
			t.Errorf("expected access to be allowed for user's own org contract, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-004: eth_getLogs on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": contractB, "fromBlock": "0x0", "toBlock": "latest"}},
			TargetAddress:  contractB, // Target address for single-contract getLogs
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getLogs on cross-org contract")
		}
	})

	t.Run("SECURITY-005: eth_getLogs with mixed-org addresses is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": []any{contractA, contractB}, "fromBlock": "0x0", "toBlock": "latest"}},
			TargetAddress:  "", // Multiple addresses, no single target
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getLogs with mixed-org addresses")
		}
	})

	t.Run("SECURITY-006: eth_getBalance on cross-org address is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getBalance",
			Params:         []any{contractB, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getBalance on cross-org address")
		}
	})

	t.Run("SECURITY-007: Public contract (not registered to any org) is accessible", func(t *testing.T) {
		// publicContract is NOT registered to any org
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": publicContract, "data": "0x"}, "latest"},
			TargetAddress:  publicContract,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should be allowed via default_claims since it's a public contract
		if !result.Allowed {
			t.Errorf("expected access to be allowed for public contract, got: %s", result.Reason)
		}
	})

	t.Run("SECURITY-008: eth_getCode on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getCode",
			Params:         []any{contractB, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getCode on cross-org contract")
		}
	})

	t.Run("SECURITY-009: eth_getStorageAt on cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_getStorageAt",
			Params:         []any{contractB, "0x0", "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_getStorageAt on cross-org contract")
		}
	})

	t.Run("SECURITY-010: eth_sendTransaction to cross-org contract is denied", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": contractB, "from": "0x9999999999999999999999999999999999999999", "data": "0x"}},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied for eth_sendTransaction to cross-org contract")
		}
	})
}

// TestCheckAccessCrossOrgWithDefaultClaims tests that default_claims cannot be used
// to bypass cross-org isolation for registered contracts.
func TestCheckAccessCrossOrgWithDefaultClaims(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)

	// Give user-a very permissive default_claims (all claims)
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getLogs", "eth_getCode", "eth_getStorageAt", "eth_sendTransaction"},
		ContractAccess: map[string]ContractAccess{},
		DefaultClaims:  []Claim{ClaimRead, ClaimWrite, ClaimAdmin}, // Very permissive
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)
	contractB := "0xbbbb000000000000000000000000000000000002"

	t.Run("permissive default_claims cannot access cross-org contract", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Errorf("expected access to be denied despite permissive default_claims")
		}
		if !containsString(result.Reason, "belongs to an organization you are not a member of") {
			t.Errorf("expected cross-org denial message, got: %s", result.Reason)
		}
	})
}

// TestCheckAccessMultiOrgUser tests that a user who is member of multiple orgs
// can access contracts from any of their orgs.
func TestCheckAccessMultiOrgUser(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()

	// Create two organizations
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
	store.organizations["org-a"] = orgA
	store.organizations["org-b"] = orgB

	// Create a multi-org user who is member of BOTH orgs
	multiUser := &User{ID: "multi-user", ExternalID: "did:test:multi-user", KYC: true, Banned: false}
	store.users["did:test:multi-user"] = multiUser

	// Create groups
	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	groupB := &Group{ID: "group-b", OrgID: "org-b", Slug: "group-b", Name: "Group B"}

	// User is member of BOTH orgs
	store.memberships["multi-user"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-a", UserID: "multi-user", GroupID: "group-a"}, Group: groupA},
		{Membership: &UserMembership{ID: "mem-b", UserID: "multi-user", GroupID: "group-b"}, Group: groupB},
	}

	// Set up group access
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		DefaultClaims:  []Claim{ClaimRead},
	}
	store.groupAccess["group-b"] = &GroupAccess{
		ID:             "access-b",
		GroupID:        "group-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		DefaultClaims:  []Claim{ClaimRead},
	}

	// Define contracts
	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"

	// Set up ownership
	store.contractOwners[contractA] = "org-a"
	store.contractOwners[contractB] = "org-b"
	store.registeredToAnyOrg[contractA] = true
	store.registeredToAnyOrg[contractB] = true
	store.addressOwnedByOrg[contractA] = map[string]bool{"org-a": true}
	store.addressOwnedByOrg[contractB] = map[string]bool{"org-b": true}

	// Cache permissions for multi-user in both orgs
	store.cachedPermissions["multi-user:org-a"] = &EffectivePermissions{
		ID:             "perms-multi-a",
		UserID:         "multi-user",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{},
		DefaultClaims:  []Claim{ClaimRead},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}
	store.cachedPermissions["multi-user:org-b"] = &EffectivePermissions{
		ID:             "perms-multi-b",
		UserID:         "multi-user",
		OrgID:          "org-b",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{},
		DefaultClaims:  []Claim{ClaimRead},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	controller := NewAccessController(store, 5*time.Minute)

	t.Run("multi-org user can access Contract A (from org-a)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:multi-user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected multi-org user to access contract from org-a, got: %s", result.Reason)
		}
	})

	t.Run("multi-org user can access Contract B (from org-b)", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:multi-user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
			TargetAddress:  contractB,
		}

		result, err := controller.CheckAccess(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected multi-org user to access contract from org-b, got: %s", result.Reason)
		}
	})
}

// containsString checks if a string contains a substring.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
