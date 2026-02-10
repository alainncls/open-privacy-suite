package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServerRBAC wraps Server with a router for testing
type testServerRBAC struct {
	*Server
	router *gin.Engine
}

func setupTestServerForRBAC(t *testing.T) *testServerRBAC {
	// Check if TEST_DATABASE_URL is set
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Run migrations
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Clean up RBAC tables (new schema)
	ctx := context.Background()
	conn := database.Conn()
	conn.ExecContext(ctx, "DELETE FROM rbac_audit_log")
	conn.ExecContext(ctx, "DELETE FROM effective_permissions_cache")
	conn.ExecContext(ctx, "DELETE FROM contract_grants")
	conn.ExecContext(ctx, "DELETE FROM contracts")
	conn.ExecContext(ctx, "DELETE FROM preregistered_addresses")
	conn.ExecContext(ctx, "DELETE FROM user_memberships")
	conn.ExecContext(ctx, "DELETE FROM group_access")
	conn.ExecContext(ctx, "DELETE FROM groups")
	conn.ExecContext(ctx, "DELETE FROM users")
	conn.ExecContext(ctx, "DELETE FROM organizations")

	t.Cleanup(func() {
		database.Close()
	})

	cfg := &config.Config{
		NodeURL:     "http://localhost:8545",
		JWTSecret:   "test-secret-key-for-jwt-signing-123",
		BaseURL:     "http://localhost:8080",
		Environment: "development",
	}

	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	// Create RBAC access controller
	rbacAccessCtrl := rbac.NewAccessController(database, 5*time.Minute)

	// Create server with minimal setup
	gin.SetMode(gin.TestMode)
	router := gin.New()

	server := &Server{
		db:             database,
		config:         cfg,
		jwtService:     jwtService,
		rbacAccessCtrl: rbacAccessCtrl,
	}

	// Register only RBAC routes
	api := router.Group("/api")
	server.registerRBACRoutes(api)

	return &testServerRBAC{
		Server: server,
		router: router,
	}
}

func TestOrganizationAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	var createdOrgID string

	t.Run("CreateOrganization", func(t *testing.T) {
		body := map[string]any{
			"slug":     "test-org",
			"name":     "Test Organization",
			"settings": map[string]any{"feature": true},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response["id"])
		assert.Equal(t, "test-org", response["slug"])
		createdOrgID = response["id"].(string)
	})

	t.Run("ListOrganizations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/orgs", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 1)
		assert.NotNil(t, response["total"])
		assert.NotNil(t, response["limit"])
		assert.NotNil(t, response["offset"])
	})

	t.Run("GetOrganization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/orgs/"+createdOrgID, nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, createdOrgID, response["id"])
	})

	t.Run("GetOrganizationNotFound", func(t *testing.T) {
		// Use a valid UUID format that doesn't exist
		req := httptest.NewRequest(http.MethodGet, "/api/orgs/"+uuid.New().String(), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("UpdateOrganization", func(t *testing.T) {
		body := map[string]any{
			"name": "Updated Organization",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/orgs/"+createdOrgID, bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "Updated Organization", response["name"])
	})

	t.Run("CreateOrganizationMissingFields", func(t *testing.T) {
		body := map[string]any{
			"slug": "incomplete",
			// Missing "name"
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("ListOrganizationsPaginated", func(t *testing.T) {
		// Create a second org for pagination testing
		body := map[string]any{
			"slug":     "test-org-2",
			"name":     "Test Organization 2",
			"settings": map[string]any{},
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		// Test with limit=1
		req = httptest.NewRequest(http.MethodGet, "/api/orgs?limit=1&offset=0", nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.Equal(t, 1, len(data))
		assert.GreaterOrEqual(t, int(response["total"].(float64)), 2)
		assert.Equal(t, float64(1), response["limit"])
		assert.Equal(t, float64(0), response["offset"])

		// Test with offset=1
		req = httptest.NewRequest(http.MethodGet, "/api/orgs?limit=1&offset=1", nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data = response["data"].([]any)
		assert.Equal(t, 1, len(data))
		assert.Equal(t, float64(1), response["offset"])
	})
}

func TestGroupAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Create organization first
	org := createTestOrganization(t, server, "group-test-org")
	var createdGroupID string

	t.Run("CreateGroup", func(t *testing.T) {
		body := map[string]any{
			"slug":        "root",
			"name":        "Root Group",
			"description": "The root group",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		createdGroupID = response["id"].(string)
		assert.Equal(t, "root", response["slug"])
	})

	t.Run("CreateChildGroup", func(t *testing.T) {
		body := map[string]any{
			"slug":      "child",
			"name":      "Child Group",
			"parent_id": createdGroupID,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "root.child", response["path"])
		assert.Equal(t, float64(1), response["depth"])
	})

	t.Run("ListGroups", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		data := response["data"].([]any)
		assert.GreaterOrEqual(t, len(data), 2)
		assert.NotNil(t, response["total"])
		assert.NotNil(t, response["limit"])
		assert.NotNil(t, response["offset"])
	})

	t.Run("GetGroup", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, createdGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UpdateGroup", func(t *testing.T) {
		body := map[string]any{
			"name": "Updated Root Group",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, createdGroupID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("SetGroupAccess", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":  []string{"read"},
			"rate_limit_rps":  100,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, createdGroupID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetGroupAccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, createdGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)
		assert.Len(t, methods, 2)
	})

	t.Run("DeleteGroup", func(t *testing.T) {
		// Create a group to delete
		body := map[string]any{
			"slug": "delete-me",
			"name": "Delete Me",
		}
		jsonBody, _ := json.Marshal(body)

		createReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", org.ID), bytes.NewReader(jsonBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		server.router.ServeHTTP(createW, createReq)

		var createResp map[string]any
		json.Unmarshal(createW.Body.Bytes(), &createResp)
		deleteGroupID := createResp["id"].(string)

		// Delete it
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/orgs/%s/groups/%s", org.ID, deleteGroupID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestGroupAccessAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "group-access-test-org")
	group := createTestGroup(t, server, org.ID, "test-group")

	t.Run("SetGroupAccess", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":  []string{"read"},
			"rate_limit_rps":  100,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetGroupAccess", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		methods := response["allowed_methods"].([]any)
		assert.Equal(t, 2, len(methods))
	})
}

func TestGroupAccessValidation(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "access-validation-org")
	group := createTestGroup(t, server, org.ID, "validation-group")

	t.Run("RejectsWriteMethodsWithoutWriteClaim", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
			"claims":  []string{"read"}, // Missing "write" claim!
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Contains(t, response["error"], "eth_sendTransaction")
		assert.Contains(t, response["error"], "write claim")
	})

	t.Run("RejectsReadMethodsWithoutReadClaim", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_getBalance"},
			"claims":  []string{"write"}, // Missing "read" claim!
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Contains(t, response["error"], "read claim")
	})

	t.Run("AcceptsMatchingMethodsAndClaims", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"eth_call", "eth_sendTransaction"},
			"claims":  []string{"read", "write"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsEmptyMethodsList", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{},
			"claims":  []string{},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsUnknownMethodsWithoutClaims", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{"some_unknown_method", "another_custom_method"},
			"claims":  []string{}, // No claims needed for unknown methods
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("AcceptsAllClaimsWithAnyMethods", func(t *testing.T) {
		body := map[string]any{
			"allowed_methods": []string{
				"eth_call", "eth_getBalance", "eth_chainId",
				"eth_sendTransaction", "eth_sendRawTransaction",
			},
			"claims": []string{"read", "write", "admin", "upgrade", "deploy"},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestUserAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Create a user directly in the database
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:user123",
		KYC:        true,
		Banned:     false,
		Note:       "Test user",
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	t.Run("ListUsers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GetUser", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/users/"+user.ID, nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, user.ExternalID, response["external_id"])
	})

	t.Run("UpdateUser", func(t *testing.T) {
		body := map[string]any{
			"banned": true,
			"note":   "Banned for testing",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, "/api/users/"+user.ID, bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["banned"])
	})
}

func TestMembershipAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Setup: org, group, user
	org := createTestOrganization(t, server, "membership-test-org")
	group := createTestGroup(t, server, org.ID, "membership-group")

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:member",
		KYC:        true,
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	var createdMembershipID string

	t.Run("CreateMembership", func(t *testing.T) {
		body := map[string]any{
			"group_id": group.ID,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/memberships", user.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		createdMembershipID = response["id"].(string)
	})

	t.Run("ListUserMemberships", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/users/%s/memberships", user.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response []any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, len(response), 1)
	})

	t.Run("GetEffectivePermissions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/users/%s/effective-permissions?org=%s", user.ID, org.Slug), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeleteMembership", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/users/%s/memberships/%s", user.ID, createdMembershipID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestContractAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "contract-test-org")
	_ = createTestGroup(t, server, org.ID, "contract-group")

	testAddress := "0x1234567890123456789012345678901234567890"

	t.Run("CreateContract", func(t *testing.T) {
		body := map[string]any{
			"address": testAddress,
			"name":    "Test Contract",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("ListContracts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UpdateContract", func(t *testing.T) {
		body := map[string]any{
			"name":     "Updated Contract",
			"metadata": map[string]any{"updated": true},
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("DeleteContract", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestAccessCheckAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Setup: org, group, user with membership
	org := createTestOrganization(t, server, "access-test-org")
	// Create group
	group := createTestGroup(t, server, org.ID, "access-group")

	// Set group access with allowed methods
	accessBody := map[string]any{
		"allowed_methods": []string{"eth_call", "eth_getBalance"},
		"claims":  []string{"read"},
	}
	accessJson, _ := json.Marshal(accessBody)
	accessReq := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/groups/%s/access", org.ID, group.ID), bytes.NewReader(accessJson))
	accessReq.Header.Set("Content-Type", "application/json")
	accessW := httptest.NewRecorder()
	server.router.ServeHTTP(accessW, accessReq)
	require.Equal(t, http.StatusOK, accessW.Code)

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:access-user",
		KYC:        true,
		Metadata:   map[string]any{},
	}
	err := server.Server.db.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Create membership
	memBody := map[string]any{
		"group_id": group.ID,
	}
	memJson, _ := json.Marshal(memBody)
	memReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/users/%s/memberships", user.ID), bytes.NewReader(memJson))
	memReq.Header.Set("Content-Type", "application/json")
	memW := httptest.NewRecorder()
	server.router.ServeHTTP(memW, memReq)

	t.Run("CheckAccessAllowed", func(t *testing.T) {
		body := map[string]any{
			"user_external_id": user.ExternalID,
			"org_slug":         org.Slug,
			"method":           "eth_call",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, true, response["allowed"])
	})

	t.Run("CheckAccessDenied", func(t *testing.T) {
		body := map[string]any{
			"user_external_id": user.ExternalID,
			"org_slug":         org.Slug,
			"method":           "eth_sendTransaction", // Not in allowed methods
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, "/api/access/check", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, false, response["allowed"])
	})
}

func TestCacheStatsAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	t.Run("GetCacheStats", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/cache/stats", nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Contains(t, response, "entries")
		assert.Contains(t, response, "expired_pending")
		assert.Contains(t, response, "max_entries")
	})
}

func TestContractABIUpload(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "abi-test-org")
	testAddress := "0xabcdef1234567890abcdef1234567890abcdef12"

	// Create contract first
	createBody := map[string]any{
		"address": testAddress,
		"name":    "ABI Test Contract",
	}
	createJson, _ := json.Marshal(createBody)
	createReq := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), bytes.NewReader(createJson))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	server.router.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	// Valid ERC20-like ABI for testing
	validABI := `[{"type":"function","name":"balanceOf","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"},{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable"}]`

	t.Run("UploadValidABI", func(t *testing.T) {
		body := map[string]any{
			"abi": validABI,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Contract should have ABI set
		assert.Equal(t, testAddress, response["address"])
		assert.NotEmpty(t, response["abi"])
	})

	t.Run("VerifyABIInContract", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts/%s", org.ID, testAddress), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		// Verify ABI is persisted
		assert.NotEmpty(t, response["abi"])
		assert.Contains(t, response["abi"], "balanceOf")
		assert.Contains(t, response["abi"], "transfer")
	})

	t.Run("UploadInvalidJSONABI", func(t *testing.T) {
		body := map[string]any{
			"abi": "not valid json",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UploadNonArrayABI", func(t *testing.T) {
		body := map[string]any{
			"abi": `{"type": "function"}`, // Object instead of array
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UploadEmptyABI", func(t *testing.T) {
		body := map[string]any{
			"abi": "[]",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Empty array is valid ABI (contract with no public functions)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("UploadABIToNonexistentContract", func(t *testing.T) {
		nonexistentAddr := "0x0000000000000000000000000000000000000001"
		body := map[string]any{
			"abi": validABI,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/contracts/%s/abi", org.ID, nonexistentAddr), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Helper functions

func createTestOrganization(t *testing.T, server *testServerRBAC, slug string) *rbac.Organization {
	body := map[string]any{
		"slug":     slug,
		"name":     slug + " Org",
		"settings": map[string]any{},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)

	return &rbac.Organization{
		ID:   response["id"].(string),
		Slug: response["slug"].(string),
		Name: response["name"].(string),
	}
}

func createTestGroup(t *testing.T, server *testServerRBAC, orgID, slug string) *rbac.Group {
	body := map[string]any{
		"slug": slug,
		"name": slug + " Group",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups", orgID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var response map[string]any
	json.Unmarshal(w.Body.Bytes(), &response)

	return &rbac.Group{
		ID:    response["id"].(string),
		OrgID: orgID,
		Slug:  response["slug"].(string),
		Name:  response["name"].(string),
	}
}
