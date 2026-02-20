package server

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

// registerExternalRatesRoutes registers the external rates API routes.
// These are authenticated via API keys, completely separate from JWT/localhost auth.
func (s *Server) registerExternalRatesRoutes(router *gin.Engine) {
	external := router.Group("/api/v1/external")
	external.Use(apiKeyMiddleware(s.db, "rates:write"))
	{
		external.PUT("/rates", s.putExternalRate)
	}
}

func (s *Server) putExternalRate(c *gin.Context) {
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

	ctx := c.Request.Context()

	// Try to find by token_address first
	existing, err := s.db.GetSystemTokenPriceByAddress(ctx, input.TokenAddress)
	if err != nil {
		internalError(c, "failed to look up system token price", err)
		return
	}

	if existing != nil {
		// Update existing token — flip source to external so CoinGecko stops overwriting
		existing.PriceFiat = input.Price
		existing.Source = "external"
		existing.UpdatedAt = time.Now()
		if err := s.db.UpsertSystemTokenPrice(ctx, existing); err != nil {
			internalError(c, "failed to update system token price", err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"id":            existing.ID,
			"token_address": existing.TokenAddress,
			"symbol":        existing.Symbol,
			"price_fiat":    existing.PriceFiat,
			"source":        existing.Source,
			"updated_at":    existing.UpdatedAt.Format(time.RFC3339),
		})
		return
	}

	// New token — require symbol and decimals
	if input.Symbol == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "symbol is required for new tokens"})
		return
	}
	if input.Decimals == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decimals is required for new tokens"})
		return
	}
	if *input.Decimals < 0 || *input.Decimals > 77 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decimals must be between 0 and 77"})
		return
	}
	if len(input.Symbol) > 20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "symbol must be 20 characters or fewer"})
		return
	}

	newPrice := &compliance.SystemTokenPrice{
		Symbol:       input.Symbol,
		Decimals:     *input.Decimals,
		PriceFiat:    input.Price,
		Source:       "external",
		TokenAddress: &input.TokenAddress,
		UpdatedAt:    time.Now(),
	}

	if err := s.db.CreateSystemTokenPrice(ctx, newPrice); err != nil {
		internalError(c, "failed to create system token price", err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":            newPrice.ID,
		"token_address": newPrice.TokenAddress,
		"symbol":        newPrice.Symbol,
		"decimals":      newPrice.Decimals,
		"price_fiat":    newPrice.PriceFiat,
		"source":        newPrice.Source,
		"updated_at":    newPrice.UpdatedAt.Format(time.RFC3339),
	})
}

// Admin API key management endpoints

func (s *Server) listAPIKeys(c *gin.Context) {
	keys, err := s.db.ListAPIKeys(c.Request.Context())
	if err != nil {
		internalError(c, "failed to list API keys", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": keys})
}

func (s *Server) createAPIKey(c *gin.Context) {
	var input struct {
		Name      string `json:"name" binding:"required"`
		ExpiresIn *int   `json:"expires_in_days"` // optional, number of days
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if len(input.Name) > 255 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name must be 255 characters or fewer"})
		return
	}

	// Generate the key
	rawKey, keyHash, err := generateAPIKey()
	if err != nil {
		internalError(c, "failed to generate API key", err)
		return
	}

	key := &compliance.APIKey{
		ID:          generateUUID(),
		Name:        input.Name,
		KeyPrefix:   rawKey[:12], // "ppk_" + 8 chars
		Permissions: []string{"rates:write"},
	}

	if input.ExpiresIn != nil && *input.ExpiresIn > 0 {
		expires := time.Now().Add(time.Duration(*input.ExpiresIn) * 24 * time.Hour)
		key.ExpiresAt = &expires
	}

	if err := s.db.CreateAPIKey(c.Request.Context(), key, keyHash); err != nil {
		internalError(c, "failed to create API key", err)
		return
	}

	// Return the plaintext key ONCE
	c.JSON(http.StatusCreated, gin.H{
		"key":  rawKey,
		"id":   key.ID,
		"name": key.Name,
		"key_prefix":  key.KeyPrefix,
		"permissions": key.Permissions,
		"expires_at":  key.ExpiresAt,
		"created_at":  key.CreatedAt,
	})
}

func (s *Server) revokeAPIKey(c *gin.Context) {
	id := c.Param("id")

	if err := s.db.RevokeAPIKey(c.Request.Context(), id); err != nil {
		internalError(c, "failed to revoke API key", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
}

// Currency admin endpoints

func (s *Server) getBaseCurrency(c *gin.Context) {
	currency, err := s.db.GetSystemSetting(c.Request.Context(), "base_currency")
	if err != nil {
		internalError(c, "failed to get base currency", err)
		return
	}
	if currency == "" {
		currency = "usd"
	}

	type currencyInfo struct {
		Code   string `json:"code"`
		Name   string `json:"name"`
		Symbol string `json:"symbol"`
	}

	allCurrencies := make([]currencyInfo, 0, len(compliance.ValidCurrencies))
	for code, name := range compliance.ValidCurrencies {
		allCurrencies = append(allCurrencies, currencyInfo{
			Code:   string(code),
			Name:   name,
			Symbol: compliance.CurrencySymbols[code],
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"currency":       currency,
		"all_currencies": allCurrencies,
	})
}

func (s *Server) setBaseCurrency(c *gin.Context) {
	var input struct {
		Currency string `json:"currency" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !compliance.IsValidCurrency(input.Currency) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported currency; valid options: usd, eur, chf, gbp, aed"})
		return
	}

	ctx := c.Request.Context()

	// Save the new currency
	if err := s.db.SetSystemSetting(ctx, "base_currency", input.Currency); err != nil {
		internalError(c, "failed to set base currency", err)
		return
	}

	// Zero out CoinGecko-sourced system prices to force re-fetch in new currency
	// External prices are not touched — they are already in the correct currency.
	prices, err := s.db.ListSystemTokenPrices(ctx)
	if err == nil {
		for _, p := range prices {
			if p.Source == "coingecko" {
				p.PriceFiat = 0
				p.UpdatedAt = time.Now()
				s.db.UpsertSystemTokenPrice(ctx, p)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"currency": input.Currency,
		"message":  "Base currency updated. CoinGecko prices have been zeroed and will be re-fetched in the new currency.",
	})
}
