package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreregisteredAddressAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	org := createTestOrganization(t, server, "preregister-test-org")
	testFactory := "0x1111111111111111111111111111111111111111"

	t.Run("PreregisterAddresses", func(t *testing.T) {
		body := map[string]any{
			"factory":     testFactory,
			"salt_prefix": "0xdeadbeef",
			"count":       3,
			"note":        "Test preregistration",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)

		addresses, ok := response["addresses"].([]any)
		require.True(t, ok, "response should contain addresses array")
		assert.Len(t, addresses, 3)

		// Verify each address has required fields
		for _, addr := range addresses {
			addrMap := addr.(map[string]any)
			assert.NotEmpty(t, addrMap["id"])
			assert.NotEmpty(t, addrMap["address"])
			assert.Equal(t, strings.ToLower(testFactory), addrMap["factory"])
			assert.NotEmpty(t, addrMap["salt"])
			assert.Equal(t, "Test preregistration", addrMap["note"])
		}
	})

	t.Run("ListPreregisteredAddresses", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/addresses/preregistered", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var addresses []map[string]any
		json.Unmarshal(w.Body.Bytes(), &addresses)
		assert.GreaterOrEqual(t, len(addresses), 3)
	})

	t.Run("DeletePreregisteredAddress", func(t *testing.T) {
		// First get the list to find an address to delete
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/addresses/preregistered", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		var addresses []map[string]any
		json.Unmarshal(w.Body.Bytes(), &addresses)
		require.NotEmpty(t, addresses)

		addressToDelete := addresses[0]["address"].(string)

		// Delete the address
		req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/%s", org.ID, addressToDelete), nil)
		w = httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify it's gone
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/addresses/preregistered", org.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		json.Unmarshal(w.Body.Bytes(), &addresses)
		for _, addr := range addresses {
			assert.NotEqual(t, addressToDelete, addr["address"])
		}
	})
}

func TestCreate3ConfigAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	org := createTestOrganization(t, server, "create3-config-org")
	testFactory := "0x2222222222222222222222222222222222222222"

	t.Run("GetCreate3Config_NotConfigured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, false, response["configured"])
		assert.Equal(t, "", response["factory"])
	})

	t.Run("SetCreate3Config", func(t *testing.T) {
		body := map[string]any{
			"factory": testFactory,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, true, response["configured"])
		assert.Equal(t, strings.ToLower(testFactory), response["factory"])
	})

	t.Run("GetCreate3Config_Configured", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, true, response["configured"])
		assert.Equal(t, strings.ToLower(testFactory), response["factory"])
	})

	t.Run("SetCreate3Config_InvalidAddress", func(t *testing.T) {
		body := map[string]any{
			"factory": "not-an-address",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestPerOrgFactoryIsolation(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	// Create two organizations
	org1 := createTestOrganization(t, server, "factory-isolation-org1")
	org2 := createTestOrganization(t, server, "factory-isolation-org2")

	factory1 := "0x1111111111111111111111111111111111111111"
	factory2 := "0x2222222222222222222222222222222222222222"

	t.Run("EachOrgHasIndependentFactory", func(t *testing.T) {
		// Set factory for org1
		body := map[string]any{"factory": factory1}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/config/create3", org1.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Set different factory for org2
		body = map[string]any{"factory": factory2}
		jsonBody, _ = json.Marshal(body)
		req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/config/create3", org2.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Verify org1 has factory1
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org1.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		var resp1 map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp1)
		assert.Equal(t, strings.ToLower(factory1), resp1["factory"])

		// Verify org2 has factory2
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org2.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		var resp2 map[string]any
		json.Unmarshal(w.Body.Bytes(), &resp2)
		assert.Equal(t, strings.ToLower(factory2), resp2["factory"])

		// Factories should be different
		assert.NotEqual(t, resp1["factory"], resp2["factory"])
	})

	t.Run("PreregisterAutoSetsFactory", func(t *testing.T) {
		// Create a new org with no factory
		org3 := createTestOrganization(t, server, "auto-factory-org")
		factory3 := "0x3333333333333333333333333333333333333333"

		// Verify no factory configured
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org3.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		var configBefore map[string]any
		json.Unmarshal(w.Body.Bytes(), &configBefore)
		assert.Equal(t, false, configBefore["configured"])

		// Preregister with a factory
		body := map[string]any{
			"factory":     factory3,
			"salt_prefix": "0xauto",
			"count":       1,
		}
		jsonBody, _ := json.Marshal(body)
		req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org3.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		// Factory should now be configured
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org3.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		var configAfter map[string]any
		json.Unmarshal(w.Body.Bytes(), &configAfter)
		assert.Equal(t, true, configAfter["configured"])
		assert.Equal(t, strings.ToLower(factory3), configAfter["factory"])
	})

	t.Run("PreregisterRejectsMismatchedFactory", func(t *testing.T) {
		// Org1 already has factory1 configured
		// Try to preregister with a different factory
		differentFactory := "0x9999999999999999999999999999999999999999"

		body := map[string]any{
			"factory":     differentFactory,
			"salt_prefix": "0xbad",
			"count":       1,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org1.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Should be rejected
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Contains(t, response["error"], "factory")
	})

	t.Run("PreregisterAcceptsMatchingFactory", func(t *testing.T) {
		// Org1 has factory1 configured - preregister with same factory should work
		body := map[string]any{
			"factory":     factory1,
			"salt_prefix": "0xgood",
			"count":       2,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org1.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("OrgsCannotSeeEachOthersAddresses", func(t *testing.T) {
		// Preregister addresses in org1
		body := map[string]any{
			"factory":     factory1,
			"salt_prefix": "0xorg1only",
			"count":       2,
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org1.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		var preregResp map[string]any
		json.Unmarshal(w.Body.Bytes(), &preregResp)
		org1Addresses := preregResp["addresses"].([]any)

		// List org2's addresses
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/addresses/preregistered", org2.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		var org2List []map[string]any
		json.Unmarshal(w.Body.Bytes(), &org2List)

		// Org1's addresses should NOT appear in org2's list
		for _, org1Addr := range org1Addresses {
			org1AddrMap := org1Addr.(map[string]any)
			for _, org2Addr := range org2List {
				assert.NotEqual(t, org1AddrMap["address"], org2Addr["address"],
					"org1's addresses should not be visible to org2")
			}
		}
	})
}

func TestFactoryAddressNormalization(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	org := createTestOrganization(t, server, "normalization-org")

	t.Run("FactoryIsStoredLowercase", func(t *testing.T) {
		// Set factory with mixed case
		mixedCaseFactory := "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12"

		body := map[string]any{"factory": mixedCaseFactory}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Verify it's stored lowercase
		req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/config/create3", org.ID), nil)
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, strings.ToLower(mixedCaseFactory), response["factory"])
	})
}

func TestConstructorABIAPI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	org := createTestOrganization(t, server, "constructor-abi-test-org")
	testFactory := "0x4444444444444444444444444444444444444444"

	// First preregister an address
	preregBody := map[string]any{
		"factory":     testFactory,
		"salt_prefix": "0xabitest",
		"count":       1,
	}
	jsonBody, _ := json.Marshal(preregBody)
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	var preregResponse map[string]any
	json.Unmarshal(w.Body.Bytes(), &preregResponse)
	addresses := preregResponse["addresses"].([]any)
	require.Len(t, addresses, 1)
	testAddress := addresses[0].(map[string]any)["address"].(string)

	t.Run("UpdateConstructorABI", func(t *testing.T) {
		abiJSON := `[{"type":"constructor","inputs":[{"name":"oracle","type":"address"}]}]`

		body := map[string]any{
			"constructor_abi": abiJSON,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)
		assert.Equal(t, "constructor ABI updated", response["message"])
	})

	t.Run("ListShowsConstructorABI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/addresses/preregistered", org.ID), nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var addresses []map[string]any
		json.Unmarshal(w.Body.Bytes(), &addresses)

		// Find our test address
		var found bool
		for _, addr := range addresses {
			if addr["address"] == testAddress {
				found = true
				assert.NotEmpty(t, addr["constructor_abi"], "constructor_abi should be set")
				assert.Contains(t, addr["constructor_abi"], "oracle")
				break
			}
		}
		assert.True(t, found, "test address should be in the list")
	})

	t.Run("UpdateConstructorABI_InvalidJSON", func(t *testing.T) {
		body := map[string]any{
			"constructor_abi": "not valid json",
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UpdateConstructorABI_NonExistentAddress", func(t *testing.T) {
		body := map[string]any{
			"constructor_abi": `[{"type":"constructor","inputs":[]}]`,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/0x9999999999999999999999999999999999999999/abi", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("UpdateConstructorABI_ClearABI", func(t *testing.T) {
		// First set an ABI
		body := map[string]any{
			"constructor_abi": `[{"type":"constructor","inputs":[{"name":"test","type":"uint256"}]}]`,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Now we can't really "clear" it since constructor_abi is required
		// But we can set it to an empty constructor
		body = map[string]any{
			"constructor_abi": `[{"type":"constructor","inputs":[]}]`,
		}
		jsonBody, _ = json.Marshal(body)

		req = httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/orgs/%s/addresses/preregistered/%s/abi", org.ID, testAddress), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestPreregisterWithConstructorABI(t *testing.T) {
	server := setupTestServerForRBAC(t)

	// Clean up preregistered_addresses table
	server.db.Conn().ExecContext(t.Context(), "DELETE FROM preregistered_addresses")

	org := createTestOrganization(t, server, "prereg-with-abi-org")
	testFactory := "0x5555555555555555555555555555555555555555"

	t.Run("PreregisterWithABI", func(t *testing.T) {
		abiJSON := `[{"type":"constructor","inputs":[{"name":"admin","type":"address"},{"name":"fee","type":"uint256"}]}]`

		body := map[string]any{
			"factory":         testFactory,
			"salt_prefix":     "0xwithabi",
			"count":           2,
			"note":            "Contract with constructor",
			"constructor_abi": abiJSON,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)

		addresses, ok := response["addresses"].([]any)
		require.True(t, ok, "response should contain addresses array")
		assert.Len(t, addresses, 2)

		// Verify each address has the ABI
		for _, addr := range addresses {
			addrMap := addr.(map[string]any)
			assert.NotEmpty(t, addrMap["constructor_abi"])
			assert.Contains(t, addrMap["constructor_abi"], "admin")
		}
	})

	t.Run("PreregisterWithoutABI", func(t *testing.T) {
		// Addresses can be preregistered without ABI (ABI added later)
		body := map[string]any{
			"factory":     testFactory,
			"salt_prefix": "0xnoabi",
			"count":       1,
		}
		jsonBody, _ := json.Marshal(body)

		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/addresses/preregister", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var response map[string]any
		json.Unmarshal(w.Body.Bytes(), &response)

		addresses, ok := response["addresses"].([]any)
		require.True(t, ok)
		assert.Len(t, addresses, 1)

		// ABI should be empty
		addrMap := addresses[0].(map[string]any)
		assert.Empty(t, addrMap["constructor_abi"])
	})
}
