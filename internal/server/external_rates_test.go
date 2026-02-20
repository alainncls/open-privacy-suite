package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

var testHexAddressRe = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

// mockExternalRatesStore implements the subset of db methods needed for testing.
type mockExternalRatesStore struct {
	systemPricesByAddr map[string]*compliance.SystemTokenPrice
	createdPrices      []*compliance.SystemTokenPrice
	systemSettings     map[string]string
}

// processMockRate handles the core rate update/create logic for both single and batch handlers.
// Returns (httpStatus, responseBody).
func processMockRate(store *mockExternalRatesStore, tokenAddress string, price float64, symbol string, decimals *int) (int, gin.H) {
	existing := store.systemPricesByAddr[tokenAddress]

	if existing != nil {
		// Reject overriding CoinGecko-sourced tokens
		if existing.Source == "coingecko" {
			return http.StatusConflict, gin.H{"error": "cannot override CoinGecko-sourced token via external API; use the admin dashboard to manage CoinGecko tokens"}
		}

		// Bounds check
		oldPrice := existing.PriceFiat
		if oldPrice > 0 {
			deviationPct := math.Abs(price-oldPrice) / oldPrice * 100
			maxDeviation := 50.0
			if v, ok := store.systemSettings["max_price_deviation_pct"]; ok && v != "" {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 {
					maxDeviation = parsed
				}
			}
			if deviationPct > maxDeviation {
				return http.StatusUnprocessableEntity, gin.H{
					"error": fmt.Sprintf(
						"price change of %.1f%% exceeds maximum allowed deviation of %.1f%% (current: %.2f, proposed: %.2f). Use the admin dashboard for larger adjustments.",
						deviationPct, maxDeviation, oldPrice, price,
					),
				}
			}
		}

		// Cooldown check
		cooldownMinutes := 1440
		if v, ok := store.systemSettings["price_update_cooldown_minutes"]; ok && v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				cooldownMinutes = parsed
			}
		}
		if cooldownMinutes > 0 {
			elapsed := time.Since(existing.UpdatedAt)
			cooldown := time.Duration(cooldownMinutes) * time.Minute
			if elapsed < cooldown {
				remaining := cooldown - elapsed
				return http.StatusTooManyRequests, gin.H{
					"error": fmt.Sprintf(
						"price for %s was updated %dm ago; next update allowed in %dm. Cooldown: %d minutes (configurable via admin settings).",
						existing.Symbol, int(elapsed.Minutes()), int(remaining.Minutes()), cooldownMinutes,
					),
				}
			}
		}

		existing.PriceFiat = price
		existing.Source = "external"
		existing.UpdatedAt = time.Now()

		return http.StatusOK, gin.H{
			"id":            existing.ID,
			"token_address": existing.TokenAddress,
			"symbol":        existing.Symbol,
			"price_fiat":    existing.PriceFiat,
			"source":        existing.Source,
		}
	}

	// New token
	if symbol == "" {
		return http.StatusBadRequest, gin.H{"error": "symbol is required for new tokens"}
	}
	if decimals == nil {
		return http.StatusBadRequest, gin.H{"error": "decimals is required for new tokens"}
	}

	newPrice := &compliance.SystemTokenPrice{
		ID:           len(store.createdPrices) + 100,
		Symbol:       symbol,
		Decimals:     *decimals,
		PriceFiat:    price,
		Source:       "external",
		TokenAddress: &tokenAddress,
		UpdatedAt:    time.Now(),
	}
	store.createdPrices = append(store.createdPrices, newPrice)

	return http.StatusCreated, gin.H{
		"id":            newPrice.ID,
		"token_address": newPrice.TokenAddress,
		"symbol":        newPrice.Symbol,
		"decimals":      newPrice.Decimals,
		"price_fiat":    newPrice.PriceFiat,
		"source":        newPrice.Source,
	}
}

// validateAndNormalizeAddress validates and normalizes a token address.
// Returns (normalizedAddress, errorMessage). If errorMessage is non-empty, validation failed.
func validateAndNormalizeAddress(addr string) (string, string) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if addr != "native" {
		if len(addr) != 42 || !testHexAddressRe.MatchString(addr) {
			return addr, "token_address must be 'native' or a valid 42-character hex address starting with 0x"
		}
	}
	return addr, ""
}

func setupExternalRatesRouter(store *mockExternalRatesStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	if store.systemSettings == nil {
		store.systemSettings = make(map[string]string)
	}

	// Inline handler that mirrors the real putExternalRate logic for testing
	r.PUT("/api/v1/external/rates", func(c *gin.Context) {
		var input struct {
			TokenAddress string  `json:"token_address" binding:"required"`
			Price        float64 `json:"price" binding:"required"`
			Symbol       string  `json:"symbol"`
			Decimals     *int    `json:"decimals"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if input.Price <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "price must be greater than 0"})
			return
		}

		addr, errMsg := validateAndNormalizeAddress(input.TokenAddress)
		if errMsg != "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
			return
		}
		input.TokenAddress = addr

		status, resp := processMockRate(store, input.TokenAddress, input.Price, input.Symbol, input.Decimals)
		c.JSON(status, resp)
	})

	// Batch handler that mirrors the real putExternalRateBatch logic
	r.PUT("/api/v1/external/rates/batch", func(c *gin.Context) {
		var input struct {
			Prices []struct {
				TokenAddress string  `json:"token_address" binding:"required"`
				Price        float64 `json:"price" binding:"required"`
				Symbol       string  `json:"symbol"`
				Decimals     *int    `json:"decimals"`
			} `json:"prices" binding:"required"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if len(input.Prices) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "prices array must not be empty"})
			return
		}
		if len(input.Prices) > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "maximum 100 tokens per batch"})
			return
		}

		type batchResult struct {
			TokenAddress string  `json:"token_address"`
			Status       string  `json:"status"`
			Error        string  `json:"error,omitempty"`
			PriceFiat    float64 `json:"price_fiat,omitempty"`
			Symbol       string  `json:"symbol,omitempty"`
			Source       string  `json:"source,omitempty"`
		}

		results := make([]batchResult, len(input.Prices))
		for i, item := range input.Prices {
			addr, addrErr := validateAndNormalizeAddress(item.TokenAddress)
			results[i].TokenAddress = addr

			if item.Price <= 0 {
				results[i].Status = "error"
				results[i].Error = "price must be greater than 0"
				continue
			}
			if addrErr != "" {
				results[i].Status = "error"
				results[i].Error = "invalid token address format"
				continue
			}

			status, resp := processMockRate(store, addr, item.Price, item.Symbol, item.Decimals)
			if status >= 400 {
				results[i].Status = "error"
				if errVal, ok := resp["error"]; ok {
					results[i].Error = errVal.(string)
				}
				continue
			}
			results[i].Status = "ok"
			if pf, ok := resp["price_fiat"]; ok {
				results[i].PriceFiat = pf.(float64)
			}
			if sym, ok := resp["symbol"]; ok {
				results[i].Symbol = sym.(string)
			}
			if src, ok := resp["source"]; ok {
				results[i].Source = src.(string)
			}
		}

		c.JSON(http.StatusOK, gin.H{"results": results})
	})

	return r
}

func TestExternalRates_UpdateExisting(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				CoingeckoID:  strPtr("ethereum"),
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "external",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-25 * time.Hour),
			},
		},
	}

	r := setupExternalRatesRouter(store)
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 2500.50})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["price_fiat"].(float64) != 2500.50 {
		t.Errorf("expected price_fiat 2500.50, got %v", resp["price_fiat"])
	}
	if resp["source"] != "external" {
		t.Errorf("expected source 'external', got %v", resp["source"])
	}
}

func TestExternalRates_CreateNewToken(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)
	decimals := 18
	body, _ := json.Marshal(map[string]any{
		"token_address": "0x1234567890abcdef1234567890abcdef12345678",
		"price":         42.50,
		"symbol":        "BANK",
		"decimals":      decimals,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["symbol"] != "BANK" {
		t.Errorf("expected symbol 'BANK', got %v", resp["symbol"])
	}
	if resp["price_fiat"].(float64) != 42.50 {
		t.Errorf("expected price_fiat 42.50, got %v", resp["price_fiat"])
	}
	if resp["source"] != "external" {
		t.Errorf("expected source 'external', got %v", resp["source"])
	}
	if len(store.createdPrices) != 1 {
		t.Errorf("expected 1 created price, got %d", len(store.createdPrices))
	}
}

func TestExternalRates_NewTokenMissingSymbol(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)
	body, _ := json.Marshal(map[string]any{
		"token_address": "0x1234567890abcdef1234567890abcdef12345678",
		"price":         42.50,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExternalRates_BadPrice(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)

	tests := []struct {
		name string
		body string
		code int
	}{
		{"zero price", `{"token_address": "native", "price": 0}`, http.StatusBadRequest},
		{"negative price", `{"token_address": "native", "price": -100}`, http.StatusBadRequest},
		{"missing price", `{"token_address": "native"}`, http.StatusBadRequest},
		{"missing token_address", `{"price": 100}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != tt.code {
				t.Errorf("expected %d, got %d: %s", tt.code, w.Code, w.Body.String())
			}
		})
	}
}

func TestExternalRates_RejectCoinGeckoOverride(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				CoingeckoID:  strPtr("ethereum"),
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "coingecko",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-25 * time.Hour),
			},
		},
	}

	r := setupExternalRatesRouter(store)
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 9999.99})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"].(string), "CoinGecko") {
		t.Errorf("expected error mentioning CoinGecko, got %v", resp["error"])
	}

	// Verify price was NOT changed
	if store.systemPricesByAddr["native"].PriceFiat != 2000 {
		t.Errorf("expected price to remain 2000, got %v", store.systemPricesByAddr["native"].PriceFiat)
	}
}

func TestExternalRates_InvalidTokenAddress(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)

	tests := []struct {
		name    string
		address string
	}{
		{"too short", "0x1234"},
		{"no 0x prefix", "1234567890abcdef1234567890abcdef12345678"},
		{"non-hex characters", "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{"too long", "0x1234567890abcdef1234567890abcdef1234567890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"token_address": tt.address,
				"price":         100.0,
				"symbol":        "TEST",
				"decimals":      18,
			})
			req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

// --- Bounds checking tests ---

func TestExternalRates_BoundsExceeded(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "external",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-25 * time.Hour), // past cooldown
			},
		},
		// Use default 50% max deviation
	}

	r := setupExternalRatesRouter(store)

	// 2000 -> 4000 is a 100% change, well above the 50% default
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 4000.0})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errMsg, ok := resp["error"].(string)
	if !ok {
		t.Fatalf("expected error string in response, got %v", resp)
	}
	if !strings.Contains(errMsg, "exceeds maximum allowed deviation") {
		t.Errorf("expected error containing 'exceeds maximum allowed deviation', got: %s", errMsg)
	}

	// Verify price was NOT changed
	if store.systemPricesByAddr["native"].PriceFiat != 2000 {
		t.Errorf("expected price to remain 2000, got %v", store.systemPricesByAddr["native"].PriceFiat)
	}
}

func TestExternalRates_BoundsWithinLimit(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "external",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-25 * time.Hour), // past cooldown
			},
		},
		// Use default 50% max deviation
	}

	r := setupExternalRatesRouter(store)

	// 2000 -> 2800 is a 40% change, within the 50% default
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 2800.0})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["price_fiat"].(float64) != 2800.0 {
		t.Errorf("expected price_fiat 2800.0, got %v", resp["price_fiat"])
	}
}

// --- Cooldown tests ---

func TestExternalRates_CooldownBlocked(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "external",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now(), // just updated
			},
		},
		// Default cooldown is 1440 minutes (24h)
	}

	r := setupExternalRatesRouter(store)

	// Price change within bounds (10%) but cooldown not expired
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 2200.0})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errMsg, ok := resp["error"].(string)
	if !ok {
		t.Fatalf("expected error string in response, got %v", resp)
	}
	if !strings.Contains(errMsg, "Cooldown") {
		t.Errorf("expected error containing 'Cooldown', got: %s", errMsg)
	}

	// Verify price was NOT changed
	if store.systemPricesByAddr["native"].PriceFiat != 2000 {
		t.Errorf("expected price to remain 2000, got %v", store.systemPricesByAddr["native"].PriceFiat)
	}
}

func TestExternalRates_CooldownExpired(t *testing.T) {
	nativeAddr := "native"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			"native": {
				ID:           1,
				Symbol:       "ETH",
				Decimals:     18,
				PriceFiat:    2000,
				Source:       "external",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-25 * time.Hour), // > 24h ago
			},
		},
		// Default cooldown is 1440 minutes (24h)
	}

	r := setupExternalRatesRouter(store)

	// Price change within bounds (10%) and cooldown expired
	body, _ := json.Marshal(map[string]any{"token_address": "native", "price": 2200.0})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["price_fiat"].(float64) != 2200.0 {
		t.Errorf("expected price_fiat 2200.0, got %v", resp["price_fiat"])
	}
}

// --- New token skips bounds and cooldown ---

func TestExternalRates_NewTokenSkipsBoundsAndCooldown(t *testing.T) {
	// Empty store — no existing tokens, so bounds and cooldown should not apply
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
		systemSettings: map[string]string{
			"max_price_deviation_pct":       "1",  // extremely strict bounds
			"price_update_cooldown_minutes": "999", // very long cooldown
		},
	}

	r := setupExternalRatesRouter(store)

	decimals := 18
	body, _ := json.Marshal(map[string]any{
		"token_address": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		"price":         99999.99,
		"symbol":        "NEW",
		"decimals":      decimals,
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["symbol"] != "NEW" {
		t.Errorf("expected symbol 'NEW', got %v", resp["symbol"])
	}
	if resp["price_fiat"].(float64) != 99999.99 {
		t.Errorf("expected price_fiat 99999.99, got %v", resp["price_fiat"])
	}
}

// --- Batch endpoint tests ---

func TestExternalRates_Batch_Success(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			addr1: {
				ID:           1,
				Symbol:       "AAA",
				Decimals:     18,
				PriceFiat:    100,
				Source:       "external",
				TokenAddress: &addr1,
				UpdatedAt:    time.Now().Add(-25 * time.Hour),
			},
			addr2: {
				ID:           2,
				Symbol:       "BBB",
				Decimals:     18,
				PriceFiat:    200,
				Source:       "external",
				TokenAddress: &addr2,
				UpdatedAt:    time.Now().Add(-25 * time.Hour),
			},
		},
	}

	r := setupExternalRatesRouter(store)

	body, _ := json.Marshal(map[string]any{
		"prices": []map[string]any{
			{"token_address": addr1, "price": 110.0},
			{"token_address": addr2, "price": 210.0},
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Results []struct {
			TokenAddress string  `json:"token_address"`
			Status       string  `json:"status"`
			Error        string  `json:"error"`
			PriceFiat    float64 `json:"price_fiat"`
			Symbol       string  `json:"symbol"`
			Source       string  `json:"source"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}

	for i, r := range resp.Results {
		if r.Status != "ok" {
			t.Errorf("result[%d]: expected status 'ok', got '%s' (error: %s)", i, r.Status, r.Error)
		}
		if r.Source != "external" {
			t.Errorf("result[%d]: expected source 'external', got '%s'", i, r.Source)
		}
	}

	if resp.Results[0].PriceFiat != 110.0 {
		t.Errorf("result[0]: expected price_fiat 110.0, got %v", resp.Results[0].PriceFiat)
	}
	if resp.Results[1].PriceFiat != 210.0 {
		t.Errorf("result[1]: expected price_fiat 210.0, got %v", resp.Results[1].PriceFiat)
	}
}

func TestExternalRates_Batch_PartialFailure(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{
			addr1: {
				ID:           1,
				Symbol:       "AAA",
				Decimals:     18,
				PriceFiat:    100,
				Source:       "external",
				TokenAddress: &addr1,
				UpdatedAt:    time.Now().Add(-25 * time.Hour),
			},
		},
	}

	r := setupExternalRatesRouter(store)

	body, _ := json.Marshal(map[string]any{
		"prices": []map[string]any{
			{"token_address": addr1, "price": 110.0},         // valid, within bounds
			{"token_address": "native", "price": -5.0},       // invalid: negative price
		},
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Results []struct {
			TokenAddress string `json:"token_address"`
			Status       string `json:"status"`
			Error        string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(resp.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(resp.Results))
	}

	if resp.Results[0].Status != "ok" {
		t.Errorf("result[0]: expected status 'ok', got '%s' (error: %s)", resp.Results[0].Status, resp.Results[0].Error)
	}
	if resp.Results[1].Status != "error" {
		t.Errorf("result[1]: expected status 'error', got '%s'", resp.Results[1].Status)
	}
	if resp.Results[1].Error == "" {
		t.Error("result[1]: expected non-empty error message")
	}
}

func TestExternalRates_Batch_TooMany(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)

	// Build a batch with 101 items
	prices := make([]map[string]any, 101)
	for i := range prices {
		prices[i] = map[string]any{
			"token_address": fmt.Sprintf("0x%040x", i),
			"price":         100.0,
			"symbol":        "TOK",
			"decimals":      18,
		}
	}

	body, _ := json.Marshal(map[string]any{"prices": prices})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"].(string), "maximum 100") {
		t.Errorf("expected error mentioning maximum 100, got: %v", resp["error"])
	}
}

func TestExternalRates_Batch_Empty(t *testing.T) {
	store := &mockExternalRatesStore{
		systemPricesByAddr: map[string]*compliance.SystemTokenPrice{},
	}

	r := setupExternalRatesRouter(store)

	body, _ := json.Marshal(map[string]any{"prices": []map[string]any{}})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/external/rates/batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errMsg, ok := resp["error"].(string)
	if !ok || !strings.Contains(errMsg, "empty") {
		t.Errorf("expected error mentioning empty, got: %v", resp["error"])
	}
}

func strPtr(s string) *string {
	return &s
}
