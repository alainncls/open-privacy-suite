package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RBAC enforcement tests — verify access control, blocked methods, permissions.
// These need a real DB for RBAC resolution.

func TestResilience_UnauthenticatedRPC_NoWriteMethods(t *testing.T) {
	srv, _ := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	result, err := srv.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: "",
		Method:         "eth_sendTransaction",
	})
	require.NoError(t, err)
	assert.False(t, result.Allowed,
		"unauthenticated user must not be allowed to call eth_sendTransaction")
}

func TestResilience_UnauthenticatedRPC_BlockedMethods(t *testing.T) {
	srv, _ := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	// These are globally blocked — not exempted like debug_traceTransaction/debug_traceCall
	blockedMethods := []string{
		"admin_addPeer",
		"personal_sign",
		"eth_sign",
		"miner_start",
		"txpool_content",
		"debug_storageRangeAt",
	}

	for _, method := range blockedMethods {
		t.Run(method, func(t *testing.T) {
			result, err := srv.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
				UserExternalID: "",
				Method:         method,
			})
			require.NoError(t, err)
			assert.False(t, result.Allowed,
				"blocked method %s must be denied for unauthenticated user", method)
		})
	}
}

func TestResilience_GetEffectivePermissions_Success(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "perms-org-" + uuid.New().String()[:8],
		Name: "Perms Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "perms-group",
		Name:  "Perms Group",
		Path:  "perms-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []rbac.Claim{rbac.ClaimRead},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:perms-user",
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/users/"+user.ID+"/effective-permissions?org="+org.Slug, nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())

	var perms map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &perms))
	assert.NotEmpty(t, perms)
}

func TestResilience_GetEffectivePermissions_NonexistentUser(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/users/"+uuid.New().String()+"/effective-permissions", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestResilience_CheckAccessAPI_ValidRequest(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "access-check-org",
		Name: "Access Check Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "access-group",
		Name:  "Access Group",
		Path:  "access-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimRead},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:access-check-user",
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	body, _ := json.Marshal(map[string]interface{}{
		"user_external_id": user.ExternalID,
		"org_slug":         org.Slug,
		"method":           "eth_call",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/access/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, true, result["allowed"])
}

func TestResilience_CheckAccessAPI_DeniedMethod(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "deny-check-org",
		Name: "Deny Check Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "deny-group",
		Name:  "Deny Group",
		Path:  "deny-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimRead},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:deny-check-user",
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	body, _ := json.Marshal(map[string]interface{}{
		"user_external_id": user.ExternalID,
		"org_slug":         org.Slug,
		"method":           "eth_sendTransaction",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/access/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, false, result["allowed"])
}

func TestResilience_ConcurrentAccessChecks(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "concurrent-access-org",
		Name: "Concurrent Access Org",
	}
	require.NoError(t, srv.db.CreateOrganization(ctx, org))

	group := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "concurrent-group",
		Name:  "Concurrent Group",
		Path:  "concurrent-group",
	}
	require.NoError(t, srv.db.CreateGroup(ctx, group))

	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:         []rbac.Claim{rbac.ClaimRead},
	}
	require.NoError(t, srv.db.CreateGroupAccess(ctx, access))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:concurrent-user",
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	done := make(chan bool, 50)
	for i := 0; i < 50; i++ {
		go func() {
			body, _ := json.Marshal(map[string]interface{}{
				"user_external_id": user.ExternalID,
				"org_slug":         org.Slug,
				"method":           "eth_call",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/access/check", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Admin-Token", "test-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			var result map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &result)
			done <- result["allowed"] == true
		}()
	}

	var allowed int
	for i := 0; i < 50; i++ {
		if <-done {
			allowed++
		}
	}

	assert.Equal(t, 50, allowed,
		"all 50 concurrent access checks should return allowed (got %d)", allowed)
}
