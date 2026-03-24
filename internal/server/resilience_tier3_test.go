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

// ============================================================================
// Tier 3, Item 18: Compliance admin endpoints — auth + input validation
// ============================================================================

func TestResilience_Compliance_AllEndpointsRequireAuth(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/admin/orgs/" + orgID + "/compliance/config", ""},
		{"PUT", "/api/v1/admin/orgs/" + orgID + "/compliance/config", `{"enabled":true,"threshold_fiat":1000}`},
		{"GET", "/api/v1/admin/orgs/" + orgID + "/compliance/tokens", ""},
		{"PUT", "/api/v1/admin/orgs/" + orgID + "/compliance/tokens/0x1234567890abcdef1234567890abcdef12345678", `{"symbol":"TEST","decimals":18}`},
		{"DELETE", "/api/v1/admin/orgs/" + orgID + "/compliance/tokens/0x1234567890abcdef1234567890abcdef12345678", ""},
		{"GET", "/api/v1/admin/orgs/" + orgID + "/compliance/travel-rule-records", ""},
		{"GET", "/api/v1/admin/orgs/" + orgID + "/compliance/logs", ""},
		{"GET", "/api/v1/admin/orgs/" + orgID + "/compliance/address-thresholds", ""},
		{"GET", "/api/v1/admin/compliance/system-token-prices", ""},
		{"GET", "/api/v1/admin/compliance/sanctions", ""},
		{"POST", "/api/v1/admin/compliance/sanctions", `{"address":"0x1234567890abcdef1234567890abcdef12345678","reason":"test"}`},
		{"GET", "/api/v1/admin/compliance/currency", ""},
		{"PUT", "/api/v1/admin/compliance/currency", `{"currency":"usd"}`},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body *bytes.Reader
			if route.body != "" {
				body = bytes.NewReader([]byte(route.body))
			} else {
				body = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(route.method, route.path, body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"%s %s must require admin auth, got %d", route.method, route.path, w.Code)
		})
	}
}

func TestResilience_Compliance_UpdateConfig(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	t.Run("valid config", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"enabled":        true,
			"threshold_fiat": 1000.0,
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/compliance/config", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())
	})

	t.Run("negative threshold rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"enabled":        true,
			"threshold_fiat": -100.0,
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/compliance/config", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestResilience_Compliance_SanctionedAddresses(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	t.Run("add sanctioned address", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
			"reason":  "OFAC listed",
		})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/admin/compliance/sanctions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code, "response: %s", w.Body.String())
	})

	t.Run("invalid address rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"address": "not-an-address",
			"reason":  "test",
		})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/admin/compliance/sanctions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("list sanctions", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/admin/compliance/sanctions", nil)
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestResilience_Compliance_SetBaseCurrency(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	t.Run("valid currency", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"currency": "eur"})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/compliance/currency", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())
	})

	t.Run("invalid currency rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"currency": "btc"})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/compliance/currency", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestResilience_Compliance_AddressThresholdOverride(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)
	addr := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"

	t.Run("upsert threshold", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"threshold_fiat": 5000.0,
			"note":           "high-value customer",
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/compliance/address-thresholds/"+addr,
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())
	})

	t.Run("list thresholds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/admin/orgs/"+orgID+"/compliance/address-thresholds", nil)
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("negative threshold rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]interface{}{
			"threshold_fiat": -1.0,
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/compliance/address-thresholds/"+addr,
			bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// ============================================================================
// Tier 3, Item 19: deletePreregisteredAddress — auth + validation
// ============================================================================

func TestResilience_DeletePreregisteredAddress_RequiresAuth(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/orgs/"+orgID+"/addresses/preregistered/0x1234567890abcdef1234567890abcdef12345678", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResilience_DeletePreregisteredAddress_InvalidAddress(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/orgs/"+orgID+"/addresses/preregistered/not-valid", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should reject with 400 for invalid address format
	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound,
		"invalid address should be rejected, got %d: %s", w.Code, w.Body.String())
}

// ============================================================================
// Tier 3, Item 20: CREATE3 config — auth + validation
// ============================================================================

func TestResilience_Create3Config_GetAndSet(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	t.Run("get unconfigured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/admin/orgs/"+orgID+"/config/create3", nil)
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, false, resp["configured"])
	})

	t.Run("set factory address", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"factory": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/config/create3", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "response: %s", w.Body.String())
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["configured"])
	})

	t.Run("get configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/admin/orgs/"+orgID+"/config/create3", nil)
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]interface{}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["configured"])
		assert.Contains(t, resp["factory"], "abcdefabcdef")
	})

	t.Run("invalid factory address rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{
			"factory": "not-an-address",
		})
		req := httptest.NewRequest(http.MethodPut,
			"/api/v1/admin/orgs/"+orgID+"/config/create3", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Admin-Token", "test-token")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("requires auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/admin/orgs/"+orgID+"/config/create3", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// ============================================================================
// Tier 3, Item 25: Concurrent admin CRUD
// ============================================================================

func TestResilience_ConcurrentOrgCreation(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	done := make(chan int, 20)
	for i := 0; i < 20; i++ {
		go func(n int) {
			body, _ := json.Marshal(map[string]string{
				"slug": "concurrent-org-" + uuid.New().String()[:8],
				"name": "Concurrent Org",
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Admin-Token", "test-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			done <- w.Code
		}(i)
	}

	var created, failed int
	for i := 0; i < 20; i++ {
		code := <-done
		if code == http.StatusCreated || code == http.StatusOK {
			created++
		} else {
			failed++
		}
	}

	assert.Equal(t, 20, created, "all concurrent org creations should succeed (got %d created, %d failed)", created, failed)
}

func TestResilience_ConcurrentAccessChecks(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	// Setup org, group, user
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

// ============================================================================
// Tier 3: Compliance error leakage check
// ============================================================================

func TestResilience_Compliance_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"get config nonexistent org", "GET",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/config", ""},
		{"list tokens nonexistent org", "GET",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/tokens", ""},
		{"delete nonexistent sanction", "DELETE",
			"/api/v1/admin/compliance/sanctions/" + uuid.New().String(), ""},
		{"delete nonexistent travel record", "DELETE",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/travel-rule-records/" + uuid.New().String(), ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *bytes.Reader
			if tc.body != "" {
				body = bytes.NewReader([]byte(tc.body))
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Admin-Token", "test-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assertNoInternalErrorLeakage(t, w.Body.String())
		})
	}
}
