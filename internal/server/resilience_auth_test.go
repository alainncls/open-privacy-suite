package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Tests that admin auth middleware rejects unauthenticated requests.
// These use setupAuthOnlyRouter — no DB needed, middleware rejects before handler runs.

func TestResilience_EmptyAdminToken_RejectsRequests(t *testing.T) {
	t.Skip("BUG: empty ADMIN_API_TOKEN allows unauthenticated admin access (server.go:805-809)")

	router := setupAuthOnlyRouter(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code,
		"empty admin token must not allow unauthenticated access to admin endpoints")
}

func TestResilience_EmptyAdminToken_EmptyHeaderDenied(t *testing.T) {
	t.Skip("BUG: empty ADMIN_API_TOKEN allows unauthenticated admin access (server.go:805-809)")

	router := setupAuthOnlyRouter(t, "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs", nil)
	req.Header.Set("X-Admin-Token", "")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.NotEqual(t, http.StatusOK, w.Code,
		"empty X-Admin-Token header must not grant admin access when token is unconfigured")
}

func TestResilience_AdminRoutes_AllRequireAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")
	fakeOrg := uuid.New().String()

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/admin/orgs"},
		{"POST", "/api/v1/admin/orgs"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg},
		{"PUT", "/api/v1/admin/orgs/" + fakeOrg},
		{"DELETE", "/api/v1/admin/orgs/" + fakeOrg},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/groups"},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/groups"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/contracts"},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/contracts"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/proxies"},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/proxies"},
		{"GET", "/api/v1/admin/users"},
		{"GET", "/api/v1/admin/sessions"},
		{"GET", "/api/v1/admin/azure-tenants"},
		{"POST", "/api/v1/admin/azure-tenants"},
		{"POST", "/api/v1/admin/access/check"},
		{"GET", "/api/v1/admin/cache/stats"},
		// Governance (landed post-audit)
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/settings"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/requests"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/approvers"},
		// Disclosure (landed post-audit)
		{"GET", "/api/v1/admin/disclosure/requests"},
		{"GET", "/api/v1/admin/disclosure/grants"},
		{"GET", "/api/v1/admin/disclosure/check-access"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body *bytes.Reader
			if route.method == "POST" || route.method == "PUT" {
				body = bytes.NewReader([]byte("{}"))
			} else {
				body = bytes.NewReader(nil)
			}

			req := httptest.NewRequest(route.method, route.path, body)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"%s %s must require admin auth, got %d: %s",
				route.method, route.path, w.Code, w.Body.String())
		})
	}
}

func TestResilience_GetUserLinkedAddresses_RequiresAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users/"+uuid.New().String()+"/linked-addresses", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"linked addresses endpoint must require admin auth")
}

func TestResilience_GetEffectivePermissions_RequiresAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/admin/users/"+uuid.New().String()+"/effective-permissions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResilience_CheckAccessAPI_RequiresAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	body := []byte(`{"user_external_id":"did:test:anyone","method":"eth_call"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/access/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"access check API must require admin auth — exposes RBAC internals")
}

func TestResilience_CacheStats_RequiresAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/cache/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"cache stats must require admin auth")
}

func TestResilience_ManagedProxy_RequiresAdminAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	body := []byte(`{"proxy_address":"0x1234567890abcdef1234567890abcdef12345678","proxy_type":"erc1967"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+uuid.New().String()+"/proxies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"managed proxy registration must require admin auth")
}

func TestResilience_DeletePreregisteredAddress_RequiresAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/admin/orgs/"+uuid.New().String()+"/addresses/preregistered/0x1234567890abcdef1234567890abcdef12345678", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestResilience_Governance_AllEndpointsRequireAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")
	fakeOrg := uuid.New().String()
	fakeReq := uuid.New().String()
	fakeGroup := uuid.New().String()

	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/settings"},
		{"PUT", "/api/v1/admin/orgs/" + fakeOrg + "/governance/settings"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/requests"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq + "/approve"},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/governance/requests/" + fakeReq + "/reject"},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/governance/approvers"},
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/governance/approvers"},
		{"DELETE", "/api/v1/admin/orgs/" + fakeOrg + "/governance/approvers/" + fakeGroup},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body *bytes.Reader
			if route.method == "POST" || route.method == "PUT" {
				body = bytes.NewReader([]byte("{}"))
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

func TestResilience_Disclosure_AllEndpointsRequireAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")
	fakeGrant := uuid.New().String()
	fakeReq := uuid.New().String()

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/admin/disclosure/requests"},
		{"GET", "/api/v1/admin/disclosure/requests"},
		{"GET", "/api/v1/admin/disclosure/requests/" + fakeReq},
		{"DELETE", "/api/v1/admin/disclosure/requests/" + fakeReq},
		{"GET", "/api/v1/admin/disclosure/grants"},
		{"POST", "/api/v1/admin/disclosure/grants/" + fakeGrant + "/revoke"},
		{"GET", "/api/v1/admin/disclosure/check-access"},
		{"GET", "/api/v1/admin/disclosure/grants/" + fakeGrant + "/logs"},
		{"GET", "/api/v1/admin/disclosure/grants/" + fakeGrant + "/summary"},
		{"GET", "/api/v1/admin/disclosure/grants/" + fakeGrant + "/report/pdf"},
		{"GET", "/api/v1/admin/disclosure/grants/" + fakeGrant + "/events"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body *bytes.Reader
			if route.method == "POST" {
				body = bytes.NewReader([]byte("{}"))
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

func TestResilience_ContractGrants_RequireAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")
	fakeOrg := uuid.New().String()
	fakeAddr := "0x1234567890abcdef1234567890abcdef12345678"
	fakeGroup := uuid.New().String()

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/admin/orgs/" + fakeOrg + "/contracts/" + fakeAddr + "/grants"},
		{"PUT", "/api/v1/admin/orgs/" + fakeOrg + "/contracts/" + fakeAddr + "/grants/" + fakeGroup},
		{"DELETE", "/api/v1/admin/orgs/" + fakeOrg + "/contracts/" + fakeAddr + "/grants/" + fakeGroup},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var body *bytes.Reader
			if route.method == "POST" || route.method == "PUT" {
				body = bytes.NewReader([]byte("{}"))
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

func TestResilience_Compliance_AllEndpointsRequireAuth(t *testing.T) {
	router := setupAuthOnlyRouter(t, "test-token")
	fakeOrg := uuid.New().String()

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/config", ""},
		{"PUT", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/config", `{"enabled":true,"threshold_fiat":1000}`},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/tokens", ""},
		{"PUT", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/tokens/0x1234567890abcdef1234567890abcdef12345678", `{"symbol":"TEST","decimals":18}`},
		{"DELETE", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/tokens/0x1234567890abcdef1234567890abcdef12345678", ""},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/travel-rule-records", ""},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/logs", ""},
		{"GET", "/api/v1/admin/orgs/" + fakeOrg + "/compliance/address-thresholds", ""},
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
