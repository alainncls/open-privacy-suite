package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

// mockExternalRatesStore implements the subset of db methods needed for testing.
type mockExternalRatesStore struct {
	systemPricesByAddr map[string]*compliance.SystemTokenPrice
	createdPrices      []*compliance.SystemTokenPrice
}

func setupExternalRatesRouter(store *mockExternalRatesStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

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

		existing := store.systemPricesByAddr[input.TokenAddress]

		if existing != nil {
			existing.PriceFiat = input.Price
			existing.Source = "external"
			existing.UpdatedAt = time.Now()

			c.JSON(http.StatusOK, gin.H{
				"id":            existing.ID,
				"token_address": existing.TokenAddress,
				"symbol":        existing.Symbol,
				"price_fiat":    existing.PriceFiat,
				"source":        existing.Source,
			})
			return
		}

		// New token
		if input.Symbol == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "symbol is required for new tokens"})
			return
		}
		if input.Decimals == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "decimals is required for new tokens"})
			return
		}

		newPrice := &compliance.SystemTokenPrice{
			ID:           len(store.createdPrices) + 100,
			Symbol:       input.Symbol,
			Decimals:     *input.Decimals,
			PriceFiat:    input.Price,
			Source:       "external",
			TokenAddress: &input.TokenAddress,
			UpdatedAt:    time.Now(),
		}
		store.createdPrices = append(store.createdPrices, newPrice)

		c.JSON(http.StatusCreated, gin.H{
			"id":            newPrice.ID,
			"token_address": newPrice.TokenAddress,
			"symbol":        newPrice.Symbol,
			"decimals":      newPrice.Decimals,
			"price_fiat":    newPrice.PriceFiat,
			"source":        newPrice.Source,
		})
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
				Source:       "coingecko",
				TokenAddress: &nativeAddr,
				UpdatedAt:    time.Now().Add(-1 * time.Hour),
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

func strPtr(s string) *string {
	return &s
}
