package rbac

import (
	"context"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/evm/create3"
)

// Test bytecode for factory deployment tests
// These are realistic bytecode patterns for testing

// mockAccessControllerStore implements the Store interface for testing
type mockAccessControllerStore struct {
	*MockStore
	organizations        map[string]*Organization
	users                map[string]*User
	groups               map[string]*Group
	memberships          map[string][]*UserMembership
	groupAccess          map[string]*GroupAccess
	contracts            map[string]map[string]*Contract // orgID -> address -> contract
	preregisteredAddrs   map[string]map[string]*PreregisteredAddress
	orgOwnedAddresses    map[string]map[string]bool // orgID -> address -> owned
	contractRegistration map[string]bool            // address -> registered to any org
}

func newMockAccessControllerStore() *mockAccessControllerStore {
	return &mockAccessControllerStore{
		MockStore:            NewMockStore(),
		organizations:        make(map[string]*Organization),
		users:                make(map[string]*User),
		groups:               make(map[string]*Group),
		memberships:          make(map[string][]*UserMembership),
		groupAccess:          make(map[string]*GroupAccess),
		contracts:            make(map[string]map[string]*Contract),
		preregisteredAddrs:   make(map[string]map[string]*PreregisteredAddress),
		orgOwnedAddresses:    make(map[string]map[string]bool),
		contractRegistration: make(map[string]bool),
	}
}

func (s *mockAccessControllerStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return s.organizations[id], nil
}

func (s *mockAccessControllerStore) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	for _, org := range s.organizations {
		if org.Slug == slug {
			return org, nil
		}
	}
	return nil, nil
}

func (s *mockAccessControllerStore) GetUser(ctx context.Context, id string) (*User, error) {
	return s.users[id], nil
}

func (s *mockAccessControllerStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	for _, user := range s.users {
		if user.ExternalID == externalID {
			return user, nil
		}
	}
	return nil, nil
}

func (s *mockAccessControllerStore) GetUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) {
	return s.memberships[userID], nil
}

func (s *mockAccessControllerStore) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	memberships := s.memberships[userID]
	result := make([]*MembershipWithDetails, 0, len(memberships))
	for _, m := range memberships {
		group := s.groups[m.GroupID]
		result = append(result, &MembershipWithDetails{
			Membership: m,
			Group:      group,
		})
	}
	return result, nil
}

func (s *mockAccessControllerStore) GetGroup(ctx context.Context, id string) (*Group, error) {
	return s.groups[id], nil
}

func (s *mockAccessControllerStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) {
	return s.groupAccess[groupID], nil
}

func (s *mockAccessControllerStore) GetContract(ctx context.Context, id string) (*Contract, error) {
	// Check all orgs for a contract with this ID
	for _, contracts := range s.contracts {
		for _, c := range contracts {
			if c.ID == id {
				return c, nil
			}
		}
	}
	return nil, nil
}

func (s *mockAccessControllerStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) {
	if contracts, ok := s.contracts[orgID]; ok {
		return contracts[strings.ToLower(address)], nil
	}
	return nil, nil
}

func (s *mockAccessControllerStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) {
	if contracts, ok := s.contracts[orgID]; ok {
		result := make([]*Contract, 0, len(contracts))
		for _, c := range contracts {
			result = append(result, c)
		}
		return result, nil
	}
	return nil, nil
}

func (s *mockAccessControllerStore) GetPreregisteredAddressByAddress(ctx context.Context, orgID, address string) (*PreregisteredAddress, error) {
	if addrs, ok := s.preregisteredAddrs[orgID]; ok {
		return addrs[strings.ToLower(address)], nil
	}
	return nil, nil
}

func (s *mockAccessControllerStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	if addrs, ok := s.orgOwnedAddresses[orgID]; ok {
		return addrs[strings.ToLower(address)], nil
	}
	return false, nil
}

func (s *mockAccessControllerStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	addr := strings.ToLower(address)
	for orgID, addrs := range s.orgOwnedAddresses {
		if addrs[addr] {
			return orgID, nil
		}
	}
	return "", nil
}

func (s *mockAccessControllerStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	return s.contractRegistration[strings.ToLower(address)], nil
}

// Helper methods to set up test data
func (s *mockAccessControllerStore) addOrg(org *Organization) {
	s.organizations[org.ID] = org
}

func (s *mockAccessControllerStore) addUser(user *User) {
	s.users[user.ID] = user
}

func (s *mockAccessControllerStore) addGroup(group *Group) {
	s.groups[group.ID] = group
}

func (s *mockAccessControllerStore) addMembership(userID string, membership *UserMembership) {
	s.memberships[userID] = append(s.memberships[userID], membership)
}

func (s *mockAccessControllerStore) setGroupAccess(groupID string, access *GroupAccess) {
	s.groupAccess[groupID] = access
}

func (s *mockAccessControllerStore) addContract(orgID string, contract *Contract) {
	if s.contracts[orgID] == nil {
		s.contracts[orgID] = make(map[string]*Contract)
	}
	s.contracts[orgID][strings.ToLower(contract.Address)] = contract
	s.contractRegistration[strings.ToLower(contract.Address)] = true
}

func (s *mockAccessControllerStore) setOrgOwnsAddress(orgID, address string) {
	if s.orgOwnedAddresses[orgID] == nil {
		s.orgOwnedAddresses[orgID] = make(map[string]bool)
	}
	s.orgOwnedAddresses[orgID][strings.ToLower(address)] = true
}

// TestFactoryDeploymentRequiresAdmin tests that CREATE3 factory deployment requires admin claim
func TestFactoryDeploymentRequiresAdmin(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup: Create org, user, group
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	adminUser := &User{ID: "admin1", ExternalID: "did:test:admin1", KYC: true}
	store.addUser(adminUser)

	// Group with deploy claim only (no admin)
	deployerGroup := &Group{ID: "deployers", OrgID: "org1", Slug: "deployers", Name: "Deployers"}
	store.addGroup(deployerGroup)
	store.setGroupAccess("deployers", &GroupAccess{
		GroupID:        "deployers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
	})

	// Group with admin claim
	adminGroup := &Group{ID: "admins", OrgID: "org1", Slug: "admins", Name: "Admins"}
	store.addGroup(adminGroup)
	store.setGroupAccess("admins", &GroupAccess{
		GroupID:        "admins",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy, ClaimAdmin},
	})

	// Add memberships
	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "deployers"})
	store.addMembership("admin1", &UserMembership{ID: "mem2", UserID: "admin1", GroupID: "admins"})

	// Get the trusted factory bytecode hash for testing
	// We need actual bytecode that matches a trusted factory
	trustedFactoryBytecode := getTrustedFactoryBytecode()

	t.Run("user with deploy claim cannot deploy factory", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					// No "to" field = deployment
					"data": trustedFactoryBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected factory deployment to be denied for user without admin claim")
		}
		if !strings.Contains(result.Reason, "admin") {
			t.Errorf("expected reason to mention admin, got: %s", result.Reason)
		}
	})

	t.Run("admin can deploy factory", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:admin1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": trustedFactoryBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected factory deployment to be allowed for admin, got reason: %s", result.Reason)
		}
	})
}

// TestRegularContractDeploymentWithDeployClaim tests that regular contracts can be deployed with deploy claim
func TestRegularContractDeploymentWithDeployClaim(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	group := &Group{ID: "deployers", OrgID: "org1", Slug: "deployers", Name: "Deployers"}
	store.addGroup(group)
	store.setGroupAccess("deployers", &GroupAccess{
		GroupID:        "deployers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
	})

	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "deployers"})

	// Simple contract bytecode (no CREATE/CREATE2, no external calls)
	// PUSH1 0x00 STOP
	simpleBytecode := "0x600000"

	t.Run("user with deploy claim can deploy regular contract", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": simpleBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected regular contract deployment to be allowed, got reason: %s", result.Reason)
		}
	})
}

// TestNonTrustedFactoryBlocked tests that non-whitelisted factory contracts are blocked
func TestNonTrustedFactoryBlocked(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "admin1", ExternalID: "did:test:admin1", KYC: true}
	store.addUser(user)

	group := &Group{ID: "admins", OrgID: "org1", Slug: "admins", Name: "Admins"}
	store.addGroup(group)
	store.setGroupAccess("admins", &GroupAccess{
		GroupID:        "admins",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy, ClaimAdmin},
	})

	store.addMembership("admin1", &UserMembership{ID: "mem1", UserID: "admin1", GroupID: "admins"})

	// Contract with CREATE opcode but NOT matching any trusted factory
	// This should be blocked because it has CREATE but isn't whitelisted
	bytecodeWithCreate := "0x6000600060006000f000" // PUSH1 0 x4, CREATE, STOP

	t.Run("non-trusted factory blocked even for admin", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:admin1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": bytecodeWithCreate,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected non-trusted factory to be blocked")
		}
		if !strings.Contains(result.Reason, "CREATE") {
			t.Errorf("expected reason to mention CREATE opcodes, got: %s", result.Reason)
		}
	})
}

// TestDeploymentWithoutDeployClaim tests that deployment is denied without deploy claim
func TestDeploymentWithoutDeployClaim(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	// Group with only read/write claims (no deploy)
	group := &Group{ID: "readers", OrgID: "org1", Slug: "readers", Name: "Readers"}
	store.addGroup(group)
	store.setGroupAccess("readers", &GroupAccess{
		GroupID:        "readers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite}, // No deploy!
	})

	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "readers"})

	simpleBytecode := "0x600000"

	t.Run("deployment denied without deploy claim", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": simpleBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Allowed {
			t.Error("expected deployment to be denied without deploy claim")
		}
		if result.Reason != "access denied" {
			t.Errorf("expected generic denial, got: %s", result.Reason)
		}
	})
}

// TestProxyContractDeployment tests proxy contract deployment flow
func TestProxyContractDeployment(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	group := &Group{ID: "deployers", OrgID: "org1", Slug: "deployers", Name: "Deployers"}
	store.addGroup(group)
	store.setGroupAccess("deployers", &GroupAccess{
		GroupID:        "deployers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
	})

	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "deployers"})

	// ERC1967 proxy pattern bytecode (simplified)
	// This has DELEGATECALL with dynamic target (from storage) but is recognized as a proxy
	// For simplicity, we use a minimal proxy-like bytecode
	// Real proxies would be detected by the proxy detection logic
	proxyBytecode := "0x600000" // Simplified - real proxy detection is in bytecode package

	t.Run("proxy contract deployment allowed with deploy claim", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": proxyBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected proxy deployment to be allowed, got reason: %s", result.Reason)
		}
	})
}

// TestFactoryClaimInheritance tests that admin claim can be inherited from parent groups
func TestFactoryClaimInheritance(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup
	org := &Organization{ID: "org1", Slug: "test-org", Name: "Test Org"}
	store.addOrg(org)

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	// Parent group with admin claim and the required methods
	// (child inherits intersection of methods, so parent must have eth_sendTransaction)
	parentGroup := &Group{ID: "parent", OrgID: "org1", Slug: "parent", Name: "Parent"}
	store.addGroup(parentGroup)
	store.setGroupAccess("parent", &GroupAccess{
		GroupID:        "parent",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:  []Claim{ClaimAdmin, ClaimDeploy},
	})

	// Child group inherits from parent (intersection of methods and claims)
	childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Name: "Child", ParentID: stringPtr("parent")}
	store.addGroup(childGroup)
	store.setGroupAccess("child", &GroupAccess{
		GroupID:        "child",
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:  []Claim{ClaimDeploy, ClaimAdmin},
	})

	// User is member of child group
	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "child"})

	trustedFactoryBytecode := getTrustedFactoryBytecode()

	t.Run("admin claim inherited from parent allows factory deployment", func(t *testing.T) {
		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"data": trustedFactoryBytecode,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected factory deployment to be allowed with inherited admin, got reason: %s", result.Reason)
		}
	})
}

// Helper to get trusted factory bytecode for testing
func getTrustedFactoryBytecode() string {
	// Return the actual SimpleCreate3Factory bytecode which is whitelisted
	return create3.SimpleCreate3FactoryBytecode
}

func stringPtr(s string) *string {
	return &s
}

// TestE2EDeploymentViaCreate3 tests the end-to-end flow of deploying via CREATE3
func TestE2EDeploymentViaCreate3(t *testing.T) {
	store := newMockAccessControllerStore()
	controller := NewAccessController(store, 5*time.Minute)

	// Setup org with factory configured
	org := &Organization{
		ID:   "org1",
		Slug: "test-org",
		Name: "Test Org",
		Settings: map[string]any{
			"factory_address": "0x1234567890123456789012345678901234567890",
		},
	}
	store.addOrg(org)

	// Register the factory as org-owned
	factoryAddr := "0x1234567890123456789012345678901234567890"
	store.setOrgOwnsAddress("org1", factoryAddr)
	store.addContract("org1", &Contract{
		ID:      "factory-contract-1",
		OrgID:   "org1",
		Address: factoryAddr,
		Name:    "CREATE3 Factory",
	})

	user := &User{ID: "user1", ExternalID: "did:test:user1", KYC: true}
	store.addUser(user)

	group := &Group{ID: "deployers", OrgID: "org1", Slug: "deployers", Name: "Deployers"}
	store.addGroup(group)
	store.setGroupAccess("deployers", &GroupAccess{
		GroupID:        "deployers",
		AllowedMethods: []string{"eth_sendTransaction", "eth_call"},
		Claims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
	})

	store.addMembership("user1", &UserMembership{ID: "mem1", UserID: "user1", GroupID: "deployers"})

	t.Run("call to factory contract for deployment", func(t *testing.T) {
		// Simulate calling factory.deploy(salt, bytecode)
		// deploy(bytes32,bytes) selector: 0xcdcb760a
		deploySelector := "0xcdcb760a"
		salt := strings.Repeat("00", 32) // bytes32
		// Simplified - real call would have ABI-encoded bytecode
		calldata := deploySelector + salt

		req := &AccessCheckRequest{
			UserExternalID: "did:test:user1",
			OrgSlug:        "test-org",
			Method:         "eth_sendTransaction",
			Params: []any{
				map[string]any{
					"to":   factoryAddr,
					"data": calldata,
				},
			},
		}

		result, err := controller.CheckAccess(context.Background(), req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !result.Allowed {
			t.Errorf("expected call to factory to be allowed, got reason: %s", result.Reason)
		}
	})
}

// Additional store interface methods required for AccessController

func (s *mockAccessControllerStore) GetManagedProxy(ctx context.Context, address string) (*ManagedProxy, error) {
	return nil, nil
}

func (s *mockAccessControllerStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) {
	return nil, nil
}

func (s *mockAccessControllerStore) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error) {
	return nil, nil
}

func (s *mockAccessControllerStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error) {
	var groups []*Group
	for _, g := range s.groups {
		if g.OrgID == orgID {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func (s *mockAccessControllerStore) GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error) {
	for _, g := range s.groups {
		if g.OrgID == orgID && g.Slug == slug {
			return g, nil
		}
	}
	return nil, nil
}

func (s *mockAccessControllerStore) GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) {
	group := s.groups[groupID]
	if group == nil {
		return nil, nil
	}

	// Build hierarchy following parent chain
	var hierarchy []*Group
	current := group
	for current != nil {
		hierarchy = append([]*Group{current}, hierarchy...)
		if current.ParentID == nil {
			break
		}
		current = s.groups[*current.ParentID]
	}
	return hierarchy, nil
}

func (s *mockAccessControllerStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	memberships := s.memberships[userID]
	var result []*MembershipWithDetails
	for _, m := range memberships {
		group := s.groups[m.GroupID]
		if group != nil && group.OrgID == orgID {
			result = append(result, &MembershipWithDetails{
				Membership: m,
				Group:      group,
			})
		}
	}
	return result, nil
}

func (s *mockAccessControllerStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	return nil, nil
}

func (s *mockAccessControllerStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	return nil
}

func (s *mockAccessControllerStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	if addrs, ok := s.preregisteredAddrs[orgID]; ok {
		_, exists := addrs[strings.ToLower(address)]
		return exists, nil
	}
	return false, nil
}

func (s *mockAccessControllerStore) IsManagedProxy(ctx context.Context, address string) (bool, error) {
	return false, nil
}

func (s *mockAccessControllerStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) {
	result := make(map[string]*Contract)
	for _, id := range ids {
		for _, contracts := range s.contracts {
			for _, c := range contracts {
				if c.ID == id {
					result[id] = c
				}
			}
		}
	}
	return result, nil
}

func (s *mockAccessControllerStore) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error {
	return nil
}

func (s *mockAccessControllerStore) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error {
	return nil
}

// Add the SimpleCreate3FactoryHash to the trusted list for testing
func init() {
	// Add the test factory to the trusted list using the known hash
	// The factory bytecode hash is pre-computed and stored in create3.SimpleCreate3FactoryHash
	create3.AddTrustedFactory(create3.TrustedFactory{
		Name:         "Test SimpleCreate3Factory",
		BytecodeHash: create3.SimpleCreate3FactoryHash,
		Source:       "test",
	})
}
