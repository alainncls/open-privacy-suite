package rbac

import (
	"context"
	"testing"
	"time"
)

// MockStore implements Store interface for testing
type MockStore struct {
	organizations      map[string]*Organization
	groups             map[string]*Group
	groupPermissions   map[string]*GroupPermissions
	roles              map[string]*Role
	users              map[string]*User
	memberships        map[string]*UserMembership
	cachedPermissions  map[string]*EffectivePermissions
	groupsByOrg        map[string][]*MembershipWithDetails
}

func NewMockStore() *MockStore {
	return &MockStore{
		organizations:     make(map[string]*Organization),
		groups:            make(map[string]*Group),
		groupPermissions:  make(map[string]*GroupPermissions),
		roles:             make(map[string]*Role),
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

func (m *MockStore) GetGroupPermissions(ctx context.Context, groupID string) (*GroupPermissions, error) {
	return m.groupPermissions[groupID], nil
}

func (m *MockStore) GetRole(ctx context.Context, id string) (*Role, error) {
	return m.roles[id], nil
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

// Stub implementations for other Store methods
func (m *MockStore) CreateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockStore) UpdateOrganization(ctx context.Context, org *Organization) error { return nil }
func (m *MockStore) ListOrganizations(ctx context.Context) ([]*Organization, error) { return nil, nil }
func (m *MockStore) DeleteOrganization(ctx context.Context, id string) error { return nil }
func (m *MockStore) CreateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockStore) UpdateGroup(ctx context.Context, group *Group) error { return nil }
func (m *MockStore) ListGroups(ctx context.Context, orgID string) ([]*Group, error) { return nil, nil }
func (m *MockStore) ListGroupsByParent(ctx context.Context, parentID string) ([]*Group, error) { return nil, nil }
func (m *MockStore) DeleteGroup(ctx context.Context, id string) error { return nil }
func (m *MockStore) SetGroupPermissions(ctx context.Context, perms *GroupPermissions) error { return nil }
func (m *MockStore) DeleteGroupPermissions(ctx context.Context, groupID string) error { return nil }
func (m *MockStore) CreateRole(ctx context.Context, role *Role) error { return nil }
func (m *MockStore) GetRoleByName(ctx context.Context, orgID, name string) (*Role, error) { return nil, nil }
func (m *MockStore) UpdateRole(ctx context.Context, role *Role) error { return nil }
func (m *MockStore) ListRoles(ctx context.Context, orgID string) ([]*Role, error) { return nil, nil }
func (m *MockStore) DeleteRole(ctx context.Context, id string) error { return nil }
func (m *MockStore) CreateUser(ctx context.Context, user *User) error { return nil }
func (m *MockStore) GetUser(ctx context.Context, id string) (*User, error) { return m.users[id], nil }
func (m *MockStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	for _, u := range m.users {
		if u.ExternalID == externalID {
			return u, nil
		}
	}
	return nil, nil
}
func (m *MockStore) UpdateUser(ctx context.Context, user *User) error { return nil }
func (m *MockStore) ListUsers(ctx context.Context, limit, offset int) ([]*User, error) { return nil, nil }
func (m *MockStore) DeleteUser(ctx context.Context, id string) error { return nil }
func (m *MockStore) CreateMembership(ctx context.Context, membership *UserMembership) error { return nil }
func (m *MockStore) GetMembership(ctx context.Context, id string) (*UserMembership, error) { return nil, nil }
func (m *MockStore) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*UserMembership, error) { return nil, nil }
func (m *MockStore) UpdateMembership(ctx context.Context, membership *UserMembership) error { return nil }
func (m *MockStore) ListUserMemberships(ctx context.Context, userID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockStore) ListGroupMembers(ctx context.Context, groupID string) ([]*UserMembership, error) { return nil, nil }
func (m *MockStore) DeleteMembership(ctx context.Context, id string) error { return nil }
func (m *MockStore) DeleteExpiredMemberships(ctx context.Context) (int64, error) { return 0, nil }
func (m *MockStore) CreateContractOwnership(ctx context.Context, ownership *ContractOwnership) error { return nil }
func (m *MockStore) GetContractOwnership(ctx context.Context, id string) (*ContractOwnership, error) { return nil, nil }
func (m *MockStore) GetContractOwnershipByAddress(ctx context.Context, orgID, address string) (*ContractOwnership, error) { return nil, nil }
func (m *MockStore) UpdateContractOwnership(ctx context.Context, ownership *ContractOwnership) error { return nil }
func (m *MockStore) ListContractOwnerships(ctx context.Context, orgID string) ([]*ContractOwnership, error) { return nil, nil }
func (m *MockStore) ListContractOwnershipsByGroup(ctx context.Context, groupID string) ([]*ContractOwnership, error) { return nil, nil }
func (m *MockStore) DeleteContractOwnership(ctx context.Context, id string) error { return nil }
func (m *MockStore) CleanupExpiredCache(ctx context.Context) (int64, error) { return 0, nil }
func (m *MockStore) CreateAuditLog(ctx context.Context, entry *AuditLogEntry) error { return nil }
func (m *MockStore) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }
func (m *MockStore) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*AuditLogEntry, error) { return nil, nil }

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

	// Root group permissions (contracts only - methods now come from Role)
	store.groupPermissions["root"] = &GroupPermissions{
		GroupID: "root",
	}

	// Child group permissions (contracts only - methods now come from Role)
	store.groupPermissions["child"] = &GroupPermissions{
		GroupID: "child",
	}

	// User in child group with a role that has methods
	// In the new model, methods are on the Role, not GroupPermissions
	role := &Role{
		ID:           "role1",
		OrgID:        "org1",
		Claims:       []Claim{ClaimReader},
		AllowMethods: []string{"eth_call", "eth_getBalance"}, // Methods on Role
	}
	store.roles["role1"] = role

	roleID := "role1"
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "child", RoleID: &roleID},
			Group:      childGroup,
			Role:       role,
		},
	}

	// Resolve permissions
	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should only have intersection: eth_call, eth_getBalance
	if len(perms.AllowMethods) != 2 {
		t.Errorf("Expected 2 methods, got %d: %v", len(perms.AllowMethods), perms.AllowMethods)
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

	// Group permissions (contracts only - methods now come from Role)
	store.groupPermissions["groupA"] = &GroupPermissions{
		GroupID: "groupA",
	}
	store.groupPermissions["groupB"] = &GroupPermissions{
		GroupID: "groupB",
	}

	// User is member of both groups with different roles
	// In the new model, methods are on the Role, not GroupPermissions
	roleReader := &Role{
		ID:           "reader",
		OrgID:        "org1",
		Claims:       []Claim{ClaimReader},
		AllowMethods: []string{"eth_call", "eth_getBalance"}, // Group A's methods
	}
	roleWriter := &Role{
		ID:           "writer",
		OrgID:        "org1",
		Claims:       []Claim{ClaimWriter},
		AllowMethods: []string{"eth_call", "eth_sendTransaction"}, // Group B's methods
	}
	store.roles["reader"] = roleReader
	store.roles["writer"] = roleWriter

	readerID := "reader"
	writerID := "writer"
	store.groupsByOrg["user1:org1"] = []*MembershipWithDetails{
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupA", RoleID: &readerID},
			Group:      groupA,
			Role:       roleReader,
		},
		{
			Membership: &UserMembership{UserID: "user1", GroupID: "groupB", RoleID: &writerID},
			Group:      groupB,
			Role:       roleWriter,
		},
	}

	perms, err := resolver.ResolvePermissions(context.Background(), "user1", "org1")
	if err != nil {
		t.Fatalf("ResolvePermissions failed: %v", err)
	}

	// Should have UNION of methods: eth_call, eth_getBalance, eth_sendTransaction
	if len(perms.AllowMethods) != 3 {
		t.Errorf("Expected 3 methods, got %d: %v", len(perms.AllowMethods), perms.AllowMethods)
	}

	// Should have UNION of claims: reader, writer
	if !perms.HasClaim(ClaimReader) {
		t.Error("Expected reader claim")
	}
	if !perms.HasClaim(ClaimWriter) {
		t.Error("Expected writer claim")
	}
}

func TestResolverOwnedAddressesPropagate(t *testing.T) {
	store := NewMockStore()
	resolver := NewResolver(store, 5*time.Minute)

	org := &Organization{ID: "org1", Slug: "test"}
	store.organizations["org1"] = org

	rootGroup := &Group{ID: "root", OrgID: "org1", Slug: "root", Path: "root", Depth: 0}
	childGroup := &Group{ID: "child", OrgID: "org1", Slug: "child", Path: "root.child", Depth: 1, ParentID: &rootGroup.ID}
	store.groups["root"] = rootGroup
	store.groups["child"] = childGroup

	// Root owns address A
	store.groupPermissions["root"] = &GroupPermissions{
		GroupID:        "root",
		AllowMethods:   []string{"eth_call"},
		OwnedAddresses: []string{"0xaddressA"},
	}

	// Child owns address B
	store.groupPermissions["child"] = &GroupPermissions{
		GroupID:        "child",
		AllowMethods:   []string{"eth_call"},
		OwnedAddresses: []string{"0xaddressB"},
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

	// Should have UNION of owned addresses (ownership propagates down)
	if len(perms.OwnedAddresses) != 2 {
		t.Errorf("Expected 2 owned addresses, got %d: %v", len(perms.OwnedAddresses), perms.OwnedAddresses)
	}

	if !perms.OwnsAddress("0xaddressA") {
		t.Error("Expected to own 0xaddressA (inherited from parent)")
	}
	if !perms.OwnsAddress("0xaddressB") {
		t.Error("Expected to own 0xaddressB (from child)")
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

	store.groupPermissions["root"] = &GroupPermissions{
		GroupID:      "root",
		AllowMethods: []string{"eth_call"},
		RateLimitRPS: &rootRPS,
	}

	store.groupPermissions["child"] = &GroupPermissions{
		GroupID:      "child",
		AllowMethods: []string{"eth_call"},
		RateLimitRPS: &childRPS,
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
	if len(perms.AllowMethods) != 0 {
		t.Errorf("Expected 0 methods for user with no memberships, got %d", len(perms.AllowMethods))
	}
	if len(perms.Claims) != 0 {
		t.Errorf("Expected 0 claims for user with no memberships, got %d", len(perms.Claims))
	}
}
