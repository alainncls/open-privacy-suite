package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// Compliance endpoint tests — CRUD, validation, error leakage.
// These need a real DB.

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

func TestResilience_Compliance_NoErrorLeakage(t *testing.T) {
	_, router := setupResilienceServer(t, "test-token")

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"get config nonexistent org", "GET",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/config"},
		{"list tokens nonexistent org", "GET",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/tokens"},
		{"delete nonexistent sanction", "DELETE",
			"/api/v1/admin/compliance/sanctions/" + uuid.New().String()},
		{"delete nonexistent travel record", "DELETE",
			"/api/v1/admin/orgs/" + uuid.New().String() + "/compliance/travel-rule-records/" + uuid.New().String()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(nil))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Admin-Token", "test-token")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assertNoInternalErrorLeakage(t, w.Body.String())
		})
	}
}
