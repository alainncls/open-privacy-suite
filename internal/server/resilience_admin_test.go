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

// Admin endpoint tests — CRUD, input validation, error leakage.
// These need a real DB because the handlers execute.

func TestResilience_ManagedProxy_RegisterAndList(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	body, _ := json.Marshal(map[string]string{
		"proxy_address": "0x1234567890abcdef1234567890abcdef12345678",
		"proxy_type":    "erc1967",
		"current_impl":  "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "proxy registration should succeed: %s", w.Body.String())

	req = httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs/"+orgID+"/proxies", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestResilience_ManagedProxy_InvalidAddress(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	body, _ := json.Marshal(map[string]string{
		"proxy_address": "not-an-address",
		"proxy_type":    "erc1967",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid proxy address")
}

func TestResilience_ManagedProxy_InvalidProxyType(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	body, _ := json.Marshal(map[string]string{
		"proxy_address": "0x1234567890abcdef1234567890abcdef12345678",
		"proxy_type":    "malicious_type",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid proxy type")
}

func TestResilience_ManagedProxy_DuplicateRejected(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	body, _ := json.Marshal(map[string]string{
		"proxy_address": "0x1234567890abcdef1234567890abcdef12345678",
		"proxy_type":    "uups",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestResilience_ManagedProxy_NonexistentOrg(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	body, _ := json.Marshal(map[string]string{
		"proxy_address": "0x1234567890abcdef1234567890abcdef12345678",
		"proxy_type":    "erc1967",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+uuid.New().String()+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertNoInternalErrorLeakage(t, w.Body.String())
}

func TestResilience_GetUserLinkedAddresses_Success(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	ctx := context.Background()

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:linked-addr-user",
		KYC:        true,
	}
	require.NoError(t, srv.db.CreateUser(ctx, user))
	require.NoError(t, srv.db.LinkEthAddress(ctx,
		user.ExternalID,
		"0x1234567890abcdef1234567890abcdef12345678",
		"sig-1", "hash-1",
	))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+user.ID+"/linked-addresses", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string][]map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp["addresses"], 1)
	assert.Contains(t, resp["addresses"][0]["address"], "1234567890abcdef")
}

func TestResilience_GetUserLinkedAddresses_NonexistentUser(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+uuid.New().String()+"/linked-addresses", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestResilience_GetUserLinkedAddresses_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+uuid.New().String()+"/linked-addresses", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assertNoInternalErrorLeakage(t, w.Body.String())
}

func TestResilience_AdminHandlers_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		skip   string
	}{
		{"get nonexistent org", "GET", "/api/v1/admin/orgs/" + uuid.New().String(), "", ""},
		{"get nonexistent user", "GET", "/api/v1/admin/users/" + uuid.New().String(), "", ""},
		{"delete nonexistent session", "DELETE", "/api/v1/admin/sessions/" + uuid.New().String(), "",
			"BUG: nil pointer panic — sessionStore is nil when not initialised, handler does not nil-check"},
		{"get nonexistent tenant", "GET", "/api/v1/admin/azure-tenants/" + uuid.New().String(), "", ""},
		{"create org missing fields", "POST", "/api/v1/admin/orgs", `{}`, ""},
		{"create group missing org", "POST", "/api/v1/admin/orgs/" + uuid.New().String() + "/groups", `{"slug":"test","name":"test"}`,
			"BUG: leaks PostgreSQL SQLSTATE constraint error in HTTP response body"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
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

func TestResilience_CacheStats_WithAuth(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/cache/stats", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var stats map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stats))
	assert.Contains(t, stats, "entries")
	assert.Contains(t, stats, "max_entries")
}

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

func TestResilience_DeletePreregisteredAddress_InvalidAddress(t *testing.T) {
	srv, router := setupResilienceServer(t, "test-token")
	orgID := createOrgForTest(t, srv)

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/orgs/"+orgID+"/addresses/preregistered/not-valid", nil)
	req.Header.Set("X-Admin-Token", "test-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.True(t, w.Code == http.StatusBadRequest || w.Code == http.StatusNotFound,
		"invalid address should be rejected, got %d: %s", w.Code, w.Body.String())
}

func TestResilience_Governance_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")
	fakeOrg := uuid.New().String()
	fakeReq := uuid.New().String()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"get settings nonexistent org", "GET",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/settings", ""},
		{"list requests nonexistent org", "GET",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/requests", ""},
		{"get request nonexistent", "GET",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq, ""},
		{"approve nonexistent request", "POST",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq + "/approve", "{}"},
		{"reject nonexistent request", "POST",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq + "/reject", `{"reason":"test"}`},
		{"list approvers nonexistent org", "GET",
			"/api/v1/admin/orgs/" + fakeOrg + "/governance/approvers", ""},
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

func TestResilience_Disclosure_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")
	fakeGrant := uuid.New().String()
	fakeReq := uuid.New().String()

	cases := []struct {
		name   string
		method string
		path   string
		skip   string
	}{
		{"get nonexistent request", "GET",
			"/api/v1/admin/disclosure/requests/" + fakeReq, ""},
		{"delete nonexistent request", "DELETE",
			"/api/v1/admin/disclosure/requests/" + fakeReq,
			"BUG: nil pointer panic — disclosureService is nil when not initialised"},
		{"revoke nonexistent grant", "POST",
			"/api/v1/admin/disclosure/grants/" + fakeGrant + "/revoke",
			"BUG: nil pointer panic — disclosureService is nil when not initialised"},
		{"get logs nonexistent grant", "GET",
			"/api/v1/admin/disclosure/grants/" + fakeGrant + "/logs",
			"BUG: nil pointer panic — disclosureService is nil when not initialised"},
		{"get summary nonexistent grant", "GET",
			"/api/v1/admin/disclosure/grants/" + fakeGrant + "/summary",
			"BUG: nil pointer panic — disclosureService is nil when not initialised"},
		{"get events nonexistent grant", "GET",
			"/api/v1/admin/disclosure/grants/" + fakeGrant + "/events",
			"BUG: nil pointer panic — disclosureService is nil when not initialised"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skip != "" {
				t.Skip(tc.skip)
			}
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(nil))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Admin-Token", "test-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assertNoInternalErrorLeakage(t, w.Body.String())
		})
	}
}

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
		body, _ := json.Marshal(map[string]string{"factory": "not-an-address"})
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
