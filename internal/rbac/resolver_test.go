package rbac

import (
	"context"
	"strings"
	"testing"
	"time"
)

// MockStore implements Store interface for testing
type MockStore struct {
	organizations     map[string]*Organization
	groups            map[string]*Group
	groupAccess       map[string]*GroupAccess
	contracts         map[string]*Contract
	contractGrants    map[string][]*ContractGrant
	users             map[string]*User
	memberships       map[string]*UserMembership
	cachedPermissions map[string]*EffectivePermissions
	groupsByOrg       map[string][]*MembershipWithDetails
}

func NewMockStore() *MockStore {
	return &MockStore{
		organizations:     make(map[string]*Organization),
		groups:            make(map[string]*Group),
		groupAccess:       make(map[string]*GroupAccess),
		contracts:         make(map[string]*Contract),
		contractGrants:    make(map[string][]*ContractGrant),
		users:             make(map[string]*User),
		memberships:       make(map[string]*UserMembership),
		cachedPermissions: make(map[string]*EffectivePermissions),
		groupsByOrg:       make(map[string][]*MembershipWithDetails),
	}
}

// Implement minimal Store interface for resolver tests

func (m *MockStore) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	return m.organizations[id], nil
}

func (m *MockStore) GetOrganizationBySlug(ctx context.Context, slug string) (*Organization, error) {
	for _, org := range m.organizations {
		if org.Slug == slug {
			return org, nil
		}
	}
	return nil, nil
}

func (m *MockStore) GetGroup(ctx context.Context, id string) (*Group, error) {
	return m.groups[id], nil
}

func (m *MockStore) GetGroupBySlug(ctx context.Context, orgID, slug string) (*Group, error) {
	for _, g := range m.groups {
		if g.OrgID == orgID && g.Slug == slug {
			return g, nil
		}
	}
	return nil, nil
}

func (m *MockStore) GetGroupHierarchy(ctx context.Context, groupID string) ([]*Group, error) {
	group := m.groups[groupID]
	if group == nil {
		return nil, nil
	}

	// Build hierarchy from path
	var hierarchy []*Group
	for _, g := range m.groups {
		if g.OrgID == group.OrgID && len(g.Path) <= len(group.Path) {
			// Check if g.Path is a prefix of group.Path
			if group.Path == g.Path || (len(group.Path) > len(g.Path) && group.Path[len(g.Path)] == '.') {
				hierarchy = append(hierarchy, g)
			}
		}
	}

	// Sort by depth
	for i := 0; i < len(hierarchy)-1; i++ {
		for j := i + 1; j < len(hierarchy); j++ {
			if hierarchy[i].Depth > hierarchy[j].Depth {
				hierarchy[i], hierarchy[j] = hierarchy[j], hierarchy[i]
			}
		}
	}

	return hierarchy, nil
}

func (m *MockStore) GetGroupAccess(ctx context.Context, groupID string) (*GroupAccess, error) {
	return m.groupAccess[groupID], nil
}

func (m *MockStore) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*MembershipWithDetails, error) {
	key := userID + ":" + orgID
	return m.groupsByOrg[key], nil
}

func (m *MockStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	key := userID + ":" + orgID
	return m.cachedPermissions[key], nil
}

func (m *MockStore) SetCachedPermissions(ctx context.Context, perms *EffectivePermissions) error {
	key := perms.UserID + ":" + perms.OrgID
	m.cachedPermissions[key] = perms
	return nil
}

func (m *MockStore) InvalidateCacheForUser(ctx context.Context, userID string) error {
	for key := range m.cachedPermissions {
		if len(key) > len(userID) && key[:len(userID)] == userID {
			delete(m.cachedPermissions, key)
		}
	}
	return nil
}

func (m *MockStore) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	for key := range m.cachedPermissions {
		if len(key) > len(orgID) && key[len(key)-len(orgID):] == orgID {
			delete(m.cachedPermissions, key)
		}
	}
	return nil
}

func (m *MockStore) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	// Clear all cache for simplicity in tests
	m.cachedPermissions = make(map[string]*EffectivePermissions)
	return nil
}

func (m *MockStore) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*ContractGrant, error) {
	return m.contractGrants[groupID], nil
}

func (m *MockStore) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*ContractGrantWithGroup, error) {
	return nil, nil
}

func (m *MockStore) GetContract(ctx context.Context, id string) (*Contract, error) {
	return m.contracts[id], nil
}

func (m *MockStore) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*Contract, error) {
	result := make(map[string]*Contract)
	for _, id := range ids {
		if c, ok := m.contracts[id]; ok {
			result[id] = c
		}
	}
	return result, nil
}

// Stub implementations for other Store methods
func (m *MockStore) CreateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockStore) UpdateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockStore) ListOrganizations(ctx context.Context) ([]*Organization, error)  { return nil, nil }
func (m *MockStore) DeleteOrganization(ctx context.Context, id string) error         { return nil }
func (m *MockStore) CreateGroup(ctx context.Context, group *Group) error             { return nil }
func (m *MockStore) UpdateGroup(ctx context.Context, group *Group) error             { return nil }
func (m *MockStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error)  { return nil, nil }
func (m *MockStore) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Group, int, error) {
	return nil, 0, nil
}
func (m *MockStore) ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error) {
	return nil, nil
}
func (m *MockStore) DeleteGroup(ctx context.Context, id string) error { return nil }
func (m *MockStore) CreateGroupAccess(ctx context.Context, access *GroupAccess) error {
	m.groupAccess[access.GroupID] = access
	return nil
}
func (m *MockStore) UpdateGroupAccess(ctx context.Context, access *GroupAccess) error {
	m.groupAccess[access.GroupID] = access
	return nil
}
func (m *MockStore) DeleteGroupAccess(ctx context.Context, groupID string) error { return nil }
func (m *MockStore) CreateUser(ctx context.Context, user *User) error            { return nil }
func (m *MockStore) GetUser(ctx context.Context, id string) (*User, error)       { return m.users[id], nil }
func (m *MockStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	for _, u := range m.users {
		if u.ExternalID == externalID {
			return u, nil
		}
	}
	return nil, nil
}
func (m *MockStore) UpdateUser(ctx context.Context, user *User) error { return nil }
func (m *MockStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) {
	return nil, nil
}
func (m *MockStore) DeleteUser(ctx context.Context, id string) error { return nil }
func (m *MockStore) CreateMembership(ctx context.Context, membership *UserMembership) error {
	return nil
}
func (m *MockStore) GetMembership(ctx context.Context, id string) (*UserMembership, error) {
	return nil, nil
}
func (m *MockStore) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error) {
	return nil, nil
}
func (m *MockStore) UpdateMembership(ctx context.Context, membership *UserMembership) error {
	return nil
}
func (m *MockStore) ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) {
	return nil, nil
}
func (m *MockStore) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	return nil, nil
}
func (m *MockStore) ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error) {
	return nil, nil
}
func (m *MockStore) DeleteMembership(ctx context.Context, id string) error        { return nil }
func (m *MockStore) DeleteExpiredMemberships(ctx context.Context) (int64, error)  { return 0, nil }
func (m *MockStore) CreateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockStore) GetContractByAddress(ctx context.Context, orgID, address string) (*Contract, error) {
	for _, c := range m.contracts {
		if c.OrgID == orgID && c.Address == address {
			return c, nil
		}
	}
	return nil, nil
}
func (m *MockStore) UpdateContract(ctx context.Context, contract *Contract) error { return nil }
func (m *MockStore) ListContracts(ctx context.Context, orgID string) ([]*Contract, error) {
	return nil, nil
}
func (m *MockStore) ListContractsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*Contract, int, error) {
	return nil, 0, nil
}
func (m *MockStore) DeleteContract(ctx context.Context, id string) error { return nil }
func (m *MockStore) IsContractRegisteredToAnyOrg(ctx context.Context, address string) (bool, error) {
	for _, c := range m.contracts {
		if strings.ToLower(c.Address) == strings.ToLower(address) {
			return true, nil
		}
	}
	return false, nil
}
func (m *MockStore) IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error) {
	for _, c := range m.contracts {
		if strings.ToLower(c.Address) == strings.ToLower(address) && c.OrgID == orgID {
			return true, nil
		}
	}
	return false, nil
}
func (m *MockStore) GetContractOwnerOrgID(ctx context.Context, address string) (string, error) {
	for _, c := range m.contracts {
		if strings.ToLower(c.Address) == strings.ToLower(address) {
			return c.OrgID, nil
		}
	}
	return "", nil
}
func (m *MockStore) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) {
	return nil, nil
}
func (m *MockStore) CreateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockStore) GetContractGrant(ctx context.Context, id string) (*ContractGrant, error) {
	return nil, nil
}
func (m *MockStore) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*ContractGrant, error) {
	return nil, nil
}
func (m *MockStore) UpdateContractGrant(ctx context.Context, grant *ContractGrant) error { return nil }
func (m *MockStore) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*ContractGrant, error) {
	return nil, nil
}
func (m *MockStore) DeleteContractGrant(ctx context.Context, id string) error { return nil }
func (m *MockStore) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	return nil, nil
}
func (m *MockStore) CleanupExpiredCache(ctx context.Context) (int64, error)         { return 0, nil }
func (m *MockStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error { return nil }
func (m *MockStore) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error) {
	return nil, nil
}
func (m *MockStore) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error) {
	return nil, nil
}

// Preregistered address stubs
func (m *MockStore) CreatePreregisteredAddresses(ctx context.Context, addresses []*PreregisteredAddress) error {
	return nil
}
func (m *MockStore) ListPreregisteredAddresses(ctx context.Context, orgID string) ([]*PreregisteredAddress, error) {
	return nil, nil
}
func (m *MockStore) GetPreregisteredAddressByAddress(ctx context.Context, orgID, address string) (*PreregisteredAddress, error) {
	return nil, nil
}
func (m *MockStore) DeletePreregisteredAddress(ctx context.Context, orgID, address string) error {
	return nil
}
func (m *MockStore) PreRegisterPlainCreate(ctx context.Context, orgID, address, note string) error {
	return nil
}
func (m *MockStore) DeletePreregisteredAddressByAddress(ctx context.Context, address string) error {
	return nil
}
func (m *MockStore) IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error) {
	return false, nil
}
func (m *MockStore) MarkAddressUsed(ctx context.Context, address string) error {
	return nil
}

// Constructor ABI stubs
func (m *MockStore) GetConstructorABI(ctx context.Context, orgID, address string) (string, error) {
	return "", nil
}
func (m *MockStore) UpdateConstructorABI(ctx context.Context, orgID, address, abi string) error {
	return nil
}

// Managed proxy stubs
func (m *MockStore) CreateManagedProxy(ctx context.Context, proxy *ManagedProxy) error {
	return nil
}
func (m *MockStore) GetManagedProxy(ctx context.Context, address string) (*ManagedProxy, error) {
	return nil, nil
}
func (m *MockStore) UpdateManagedProxyImpl(ctx context.Context, address, newImpl string) error {
	return nil
}
func (m *MockStore) IsManagedProxy(ctx context.Context, address string) (bool, error) {
	return false, nil
}

// Shared infrastructure stubs
func (m *MockStore) IsSharedInfrastructure(ctx context.Context, address string) (bool, error) {
	return false, nil
}
func (m *MockStore) CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error {
	return nil
}
func (m *MockStore) ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error) {
	return nil, nil
}
func (m *MockStore) DeleteSharedInfrastructure(ctx context.Context, address string) error {
	return nil
}

// Paginated list stubs
func (m *MockStore) ListOrganizationsPaginated(ctx context.Context, limit, offset int) ([]*Organization, int, error) {
	return nil, 0, nil
}
func (m *MockStore) ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*GroupWithAccess, int, error) {
	return nil, 0, nil
}
func (m *MockStore) ListUsersPaginated(ctx context.Context, limit, offset int) ([]*User, int, error) {
	return nil, 0, nil
}

// Tests

func TestResolverRestrictiveInheritance(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	// Setup: org -> root -> child
	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
	childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
	store.groups["root"] = rootGroup
	store.groups["child"] = childGroup

	// Root group access - wider permissions
	store.groupAccess["root"] = &GroupAccess{
		GroupID:        "root",
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_sendTransaction"},
		Claims:         []Claim{ClaimRead, ClaimWrite},
	}

	// Child group access - more restrictive (INTERSECTION with parent)
	store.groupAccess["child"] = &GroupAccess{
		GroupID:        "child",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []Claim{ClaimRead},
	}

	// User in child group
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "child"},
			Group:      childGroup,
		},
	}

	// Resolve permissions
	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should only have intersection: eth_call, eth_getBalance
	if len(perms.AllowedMethods) != 2 {
		t.Errorf("Expected 2 methods, got %d: %v", len(perms.AllowedMethods), perms.AllowedMethods)
	}

	if !perms.HasMethod("eth_call") {
		t.Error("Expected eth_call to be allowed")
	}
	if !perms.HasMethod("eth_getBalance") {
		t.Error("Expected eth_getBalance to be allowed")
	}
	if perms.HasMethod("eth_sendTransaction") {
		t.Error("eth_sendTransaction should be restricted by child group")
	}

	// Should only have intersection of claims: read
	if len(perms.Claims) != 1 || perms.Claims[0] != ClaimRead {
		t.Errorf("Expected only read claim, got %v", perms.Claims)
	}
}

func TestResolverEmptyClaimsNarrowsHierarchy(t *testing.T) {
	t.Run("empty claims narrows parent claims to zero", func(t *testing.T) {
		store := NewMockStore()
		resolver := NewResolver(store, 5*time.Minute)

		org := &Organization{ID: "org1", Slug: "test"}
		store.organizations["org1"] = org

		rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
		childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
		store.groups["root"] = rootGroup
		store.groups["child"] = childGroup

		store.groupAccess["root"] = &GroupAccess{
			GroupID:        "root",
			AllowedMethods: []string{"eth_call"},
			Claims:         []Claim{ClaimRead, ClaimWrite},
		}
		// Explicitly empty claims — should narrow parent to zero
		store.groupAccess["child"] = &GroupAccess{
			GroupID:        "child",
			AllowedMethods: []string{"eth_call"},
			Claims:         []Claim{},
		}

		store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
			{
				Membership: &UserMembership{UserID: "user1", GroupID: "child"},
				Group:      childGroup,
			},
		}

		perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
		if err != nil {
			t.Fatalf("ResolvePermissions failed: %v", err)
		}

		if len(perms.Claims) != 0 {
			t.Errorf("Expected 0 claims (empty narrows parent), got %d: %v", len(perms.Claims), perms.Claims)
		}
	})

	t.Run("nil claims inherits parent claims", func(t *testing.T) {
		store := NewMockStore()
		resolver := NewResolver(store, 5*time.Minute)

		org := &Organization{ID: "org1", Slug: "test"}
		store.organizations["org1"] = org

		rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
		childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
		store.groups["root"] = rootGroup
		store.groups["child"] = childGroup

		store.groupAccess["root"] = &GroupAccess{
			GroupID:        "root",
			AllowedMethods: []string{"eth_call"},
			Claims:         []Claim{ClaimRead, ClaimWrite},
		}
		// nil claims — should inherit parent's claims
		store.groupAccess["child"] = &GroupAccess{
			GroupID:        "child",
			AllowedMethods: []string{"eth_call"},
			Claims:         nil,
		}

		store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
			{
				Membership: &UserMembership{UserID: "user1", GroupID: "child"},
				Group:      childGroup,
			},
		}

		perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
		if err != nil {
			t.Fatalf("ResolvePermissions failed: %v", err)
		}

		if len(perms.Claims) != 2 {
			t.Errorf("Expected 2 claims (inherited from parent), got %d: %v", len(perms.Claims), perms.Claims)
		}
		if !HasClaim(perms.Claims, ClaimRead) {
			t.Error("Expected read claim to be inherited")
		}
		if !HasClaim(perms.Claims, ClaimWrite) {
			t.Error("Expected write claim to be inherited")
		}
	})

	t.Run("empty allowed methods narrows parent methods to zero", func(t *testing.T) {
		store := NewMockStore()
		resolver := NewResolver(store, 5*time.Minute)

		org := &Organization{ID: "org1", Slug: "test"}
		store.organizations["org1"] = org

		rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
		childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
		store.groups["root"] = rootGroup
		store.groups["child"] = childGroup

		store.groupAccess["root"] = &GroupAccess{
			GroupID:        "root",
			AllowedMethods: []string{"eth_call", "eth_getBalance"},
			Claims:         []Claim{ClaimRead},
		}
		// Explicitly empty methods — should narrow parent to zero
		store.groupAccess["child"] = &GroupAccess{
			GroupID:        "child",
			AllowedMethods: []string{},
			Claims:         []Claim{ClaimRead},
		}

		store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
			{
				Membership: &UserMembership{UserID: "user1", GroupID: "child"},
				Group:      childGroup,
			},
		}

		perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
		if err != nil {
			t.Fatalf("ResolvePermissions failed: %v", err)
		}

		if len(perms.AllowedMethods) != 0 {
			t.Errorf("Expected 0 methods (empty narrows parent), got %d: %v", len(perms.AllowedMethods), perms.AllowedMethods)
		}
	})

	t.Run("nil allowed methods inherits parent methods", func(t *testing.T) {
		store := NewMockStore()
		resolver := NewResolver(store, 5*time.Minute)

		org := &Organization{ID: "org1", Slug: "test"}
		store.organizations["org1"] = org

		rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
		childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
		store.groups["root"] = rootGroup
		store.groups["child"] = childGroup

		store.groupAccess["root"] = &GroupAccess{
			GroupID:        "root",
			AllowedMethods: []string{"eth_call", "eth_getBalance"},
			Claims:         []Claim{ClaimRead},
		}
		// nil methods — should inherit parent's methods
		store.groupAccess["child"] = &GroupAccess{
			GroupID:        "child",
			AllowedMethods: nil,
			Claims:         []Claim{ClaimRead},
		}

		store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
			{
				Membership: &UserMembership{UserID: "user1", GroupID: "child"},
				Group:      childGroup,
			},
		}

		perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
		if err != nil {
			t.Fatalf("ResolvePermissions failed: %v", err)
		}

		if len(perms.AllowedMethods) != 2 {
			t.Errorf("Expected 2 methods (inherited from parent), got %d: %v", len(perms.AllowedMethods), perms.AllowedMethods)
		}
		if !perms.HasMethod("eth_call") {
			t.Error("Expected eth_call to be inherited")
		}
		if !perms.HasMethod("eth_getBalance") {
			t.Error("Expected eth_getBalance to be inherited")
		}
	})
}

func TestResolverMultipleMemberships(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	// Two separate group hierarchies
	groupA := &Group{ID: "groupA", OrgID: "org1", Slug: "groupA", Path: "groupA", Depth: 0}
	groupB := &Group{ID: "groupB", OrgID: "org1", Slug: "groupB", Path: "groupB", Depth: 0}
	store.groups["groupA"] = groupA
	store.groups["groupB"] = groupB

	// Group A access
	store.groupAccess["groupA"] = &GroupAccess{
		GroupID:        "groupA",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []Claim{ClaimRead},
	}
	// Group B access
	store.groupAccess["groupB"] = &GroupAccess{
		GroupID:        "groupB",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []Claim{ClaimWrite},
	}

	// User is member of both groups
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupA"},
			Group:      groupA,
		},
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupB"},
			Group:      groupB,
		},
	}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should have UNION of methods: eth_call, eth_getBalance, eth_sendTransaction
	if len(perms.AllowedMethods) != 3 {
		t.Errorf("Expected 3 methods, got %d: %v", len(perms.AllowedMethods), perms.AllowedMethods)
	}

	// Should have UNION of default claims: read, write
	if len(perms.Claims) != 2 {
		t.Errorf("Expected 2 default claims, got %d: %v", len(perms.Claims), perms.Claims)
	}
}

func TestResolverContractGrantsInheritance(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
	childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
	store.groups["root"] = rootGroup
	store.groups["child"] = childGroup

	// Contract A
	contractA := &Contract{ID: "contractA", OrgID: "org1", Address: "0xaddressA"}
	store.contracts["contractA"] = contractA

	// Note: Grant-level claims are deprecated. Claims are now inherited from GroupAccess.
	// Grants just link groups to contracts and optionally restrict functions.
	// For this test, we set up GroupAccess.Claims on root and child to test inheritance.
	store.contractGrants["root"] = []*ContractGrant{
		{ContractID: "contractA", GroupID: "root"},
	}

	store.contractGrants["child"] = []*ContractGrant{
		{ContractID: "contractA", GroupID: "child"},
	}

	// Group access - claims here are now the source of truth for contract access
	store.groupAccess["root"] = &GroupAccess{
		GroupID:        "root",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []Claim{ClaimRead, ClaimWrite, ClaimAdmin},
	}
	store.groupAccess["child"] = &GroupAccess{
		GroupID:        "child",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []Claim{ClaimRead, ClaimWrite}, // More restrictive than parent
	}

	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "child"},
			Group:      childGroup,
		},
	}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should have INTERSECTION of claims on contract A: read, write (not admin)
	// Note: addresses are lowercased in the resolver
	access, ok := perms.ContractAccess["0xaddressa"]
	if !ok {
		t.Fatal("Expected access to 0xaddressa")
	}
	if len(access.Claims) != 2 {
		t.Errorf("Expected 2 claims on contract A, got %d: %v", len(access.Claims), access.Claims)
	}
	if access.HasClaim(ClaimAdmin) {
		t.Error("Should not have admin claim (restricted by child group)")
	}
}

func TestResolverRateLimitsRestrictive(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
	childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
	store.groups["root"] = rootGroup
	store.groups["child"] = childGroup

	rootRPS := 100
	childRPS := 50 // More restrictive

	store.groupAccess["root"] = &GroupAccess{
		GroupID:        "root",
		AllowedMethods: []string{"eth_call"},
		RateLimitRPS:   &rootRPS,
	}

	store.groupAccess["child"] = &GroupAccess{
		GroupID:        "child",
		AllowedMethods: []string{"eth_call"},
		RateLimitRPS:   &childRPS,
	}

	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "child"},
			Group:      childGroup,
		},
	}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should have MINIMUM rate limit (50, the more restrictive one)
	if perms.RateLimitRPS == nil || *perms.RateLimitRPS != 50 {
		t.Errorf("Expected rate limit 50, got %v", perms.RateLimitRPS)
	}
}

func TestResolverNoMemberships(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	// User with no memberships
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should return empty permissions
	if len(perms.AllowedMethods) != 0 {
		t.Errorf("Expected 0 methods for user with no memberships, got %d", len(perms.AllowedMethods))
	}
	if len(perms.Claims) != 0 {
		t.Errorf("Expected 0 default claims for user with no memberships, got %d", len(perms.Claims))
	}
	if len(perms.ContractAccess) != 0 {
		t.Errorf("Expected 0 contract access for user with no memberships, got %d", len(perms.ContractAccess))
	}
}

func TestResolverMultipleMembershipsRateLimitsMax(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	groupA := &Group{ID: "groupA", OrgID: "org1", Slug: "groupA", Path: "groupA", Depth: 0}
	groupB := &Group{ID: "groupB", OrgID: "org1", Slug: "groupB", Path: "groupB", Depth: 0}
	store.groups["groupA"] = groupA
	store.groups["groupB"] = groupB

	rpsA := 50
	rpsB := 100 // Higher

	store.groupAccess["groupA"] = &GroupAccess{
		GroupID:        "groupA",
		AllowedMethods: []string{"eth_call"},
		RateLimitRPS:   &rpsA,
	}
	store.groupAccess["groupB"] = &GroupAccess{
		GroupID:        "groupB",
		AllowedMethods: []string{"eth_call"},
		RateLimitRPS:   &rpsB,
	}

	// User is member of both groups
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupA"},
			Group:      groupA,
		},
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupB"},
			Group:      groupB,
		},
	}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Across memberships, should have MAXIMUM rate limit (100)
	if perms.RateLimitRPS == nil || *perms.RateLimitRPS != 100 {
		t.Errorf("Expected rate limit 100, got %v", perms.RateLimitRPS)
	}
}

func TestIntersectFunctions(t *testing.T) {
	tests := []struct {
		name   string
		parent []FunctionRule
		child  []FunctionRule
		want   []FunctionRule
	}{
		{
			name:   "both nil returns nil",
			parent: nil,
			child:  nil,
			want:   nil,
		},
		{
			name:   "parent nil child has rules returns child",
			parent: nil,
			child: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
			want: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
		},
		{
			name: "parent has rules child nil returns parent",
			parent: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
			child: nil,
			want: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
		},
		{
			name: "intersection of selectors",
			parent: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
			child: []FunctionRule{
				{Selector: "0x2222"},
				{Selector: "0x3333"},
			},
			want: []FunctionRule{
				{Selector: "0x2222"},
			},
		},
		{
			name: "child param rules override parent param rules",
			parent: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			child: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 1, MustBe: "self"}}},
			},
			want: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 1, MustBe: "self"}}},
			},
		},
		{
			name:   "both empty slices returns empty",
			parent: []FunctionRule{},
			child:  []FunctionRule{},
			want:   []FunctionRule{},
		},
		{
			name: "parent has rules child is empty returns empty (child deny-all narrows)",
			parent: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
			child: []FunctionRule{},
			want:  []FunctionRule{},
		},
		{
			name:   "parent is empty child has rules returns empty (parent deny-all narrows)",
			parent: []FunctionRule{},
			child: []FunctionRule{
				{Selector: "0x1111"},
			},
			want: []FunctionRule{},
		},
		{
			name: "parent has param rules child has none keeps parent rules",
			parent: []FunctionRule{
				{Selector: "0xbbbb", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			child: []FunctionRule{
				{Selector: "0xbbbb"},
			},
			want: []FunctionRule{
				{Selector: "0xbbbb", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := intersectFunctions(tt.parent, tt.child)

			// Both nil
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d rules, got %d: %+v", len(tt.want), len(got), got)
			}

			// Build lookup from result for order-independent comparison
			gotMap := make(map[string]FunctionRule, len(got))
			for _, r := range got {
				gotMap[strings.ToLower(r.Selector)] = r
			}

			for _, wantRule := range tt.want {
				gotRule, ok := gotMap[strings.ToLower(wantRule.Selector)]
				if !ok {
					t.Errorf("expected selector %s in result, not found", wantRule.Selector)
					continue
				}
				if len(gotRule.ParamRules) != len(wantRule.ParamRules) {
					t.Errorf("selector %s: expected %d param rules, got %d: %+v",
						wantRule.Selector, len(wantRule.ParamRules), len(gotRule.ParamRules), gotRule.ParamRules)
					continue
				}
				for i, wantParam := range wantRule.ParamRules {
					if gotRule.ParamRules[i] != wantParam {
						t.Errorf("selector %s param_rule[%d]: expected %+v, got %+v",
							wantRule.Selector, i, wantParam, gotRule.ParamRules[i])
					}
				}
			}
		})
	}
}

func TestUnionFunctions(t *testing.T) {
	tests := []struct {
		name string
		a    []FunctionRule
		b    []FunctionRule
		want []FunctionRule
	}{
		{
			name: "both nil returns nil",
			a:    nil,
			b:    nil,
			want: nil,
		},
		{
			name: "a nil b has rules returns nil",
			a:    nil,
			b: []FunctionRule{
				{Selector: "0x1111"},
			},
			want: nil,
		},
		{
			name: "a has rules b nil returns nil",
			a: []FunctionRule{
				{Selector: "0x1111"},
			},
			b:    nil,
			want: nil,
		},
		{
			name: "union of disjoint selectors",
			a: []FunctionRule{
				{Selector: "0x1111"},
			},
			b: []FunctionRule{
				{Selector: "0x2222"},
			},
			want: []FunctionRule{
				{Selector: "0x1111"},
				{Selector: "0x2222"},
			},
		},
		{
			name: "one has param rules other has none drops param rules",
			a: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			b: []FunctionRule{
				{Selector: "0xaaaa"},
			},
			want: []FunctionRule{
				{Selector: "0xaaaa"},
			},
		},
		{
			name: "same param rules on both keeps them",
			a: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			b: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			want: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
		},
		{
			name: "both empty slices returns empty",
			a:    []FunctionRule{},
			b:    []FunctionRule{},
			want: []FunctionRule{},
		},
		{
			name: "different param rules on both keeps a side",
			a: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
			b: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 1, MustBe: "self"}}},
			},
			want: []FunctionRule{
				{Selector: "0xaaaa", ParamRules: []ParamRule{{Index: 0, MustBe: "self"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unionFunctions(tt.a, tt.b)

			// Both nil
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}

			if len(got) != len(tt.want) {
				t.Fatalf("expected %d rules, got %d: %+v", len(tt.want), len(got), got)
			}

			// Build lookup from result for order-independent comparison
			gotMap := make(map[string]FunctionRule, len(got))
			for _, r := range got {
				gotMap[strings.ToLower(r.Selector)] = r
			}

			for _, wantRule := range tt.want {
				gotRule, ok := gotMap[strings.ToLower(wantRule.Selector)]
				if !ok {
					t.Errorf("expected selector %s in result, not found", wantRule.Selector)
					continue
				}
				if len(gotRule.ParamRules) != len(wantRule.ParamRules) {
					t.Errorf("selector %s: expected %d param rules, got %d: %+v",
						wantRule.Selector, len(wantRule.ParamRules), len(gotRule.ParamRules), gotRule.ParamRules)
					continue
				}
				for i, wantParam := range wantRule.ParamRules {
					if gotRule.ParamRules[i] != wantParam {
						t.Errorf("selector %s param_rule[%d]: expected %+v, got %+v",
							wantRule.Selector, i, wantParam, gotRule.ParamRules[i])
					}
				}
			}
		})
	}
}
