package server

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

var hexAddressRe = regexp.MustCompile(`^0x[0-9a-f]{40}$`)

// registerExternalRatesRoutes registers the external rates API routes.
// These are authenticated via API keys, completely separate from JWT/localhost auth.
func (s *Server) registerExternalRatesRoutes(router *gin.Engine) {
	external := router.Group("/api/v1/external")
	external.Use(s.authRateLimiter.Middleware())
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

	// Normalize and validate token address
	input.TokenAddress = strings.ToLower(strings.TrimSpace(input.TokenAddress))
	if input.TokenAddress != "native" {
		if len(input.TokenAddress) != 42 || !hexAddressRe.MatchString(input.TokenAddress) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token_address must be 'native' or a valid 42-character hex address starting with 0x"})
			return
		}
	}

	ctx := c.Request.Context()

	// Try to find by token_address first
	existing, err := s.db.GetSystemTokenPriceByAddress(ctx, input.TokenAddress)
	if err != nil {
		internalError(c, "failed to look up system token price", err)
		return
	}

	if existing != nil {
		// Reject overriding CoinGecko-sourced tokens via external API
		if existing.Source == "coingecko" {
			c.JSON(http.StatusConflict, gin.H{"error": "cannot override CoinGecko-sourced token via external API; use the admin dashboard to manage CoinGecko tokens"})
			return
		}

		// Update existing external token
		existing.PriceFiat = input.Price
		existing.Source = "external"
		existing.UpdatedAt = time.Now()
		if err := s.db.UpdateSystemTokenPriceByID(ctx, existing); err != nil {
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
	if err != nil {
		log.Printf("WARNING: failed to list system token prices after currency change: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"currency": input.Currency,
			"message":  "Base currency updated, but failed to zero CoinGecko prices. They may show values in the old currency until the next CoinGecko fetch.",
		})
		return
	}

	var zeroErrors int
	for _, p := range prices {
		if p.Source == "coingecko" {
			p.PriceFiat = 0
			p.UpdatedAt = time.Now()
			if err := s.db.UpsertSystemTokenPrice(ctx, p); err != nil {
				log.Printf("WARNING: failed to zero price for %s: %v", p.Symbol, err)
				zeroErrors++
			}
		}
	}

	msg := "Base currency updated. CoinGecko prices have been zeroed and will be re-fetched in the new currency."
	if zeroErrors > 0 {
		msg = fmt.Sprintf("Base currency updated. %d CoinGecko price(s) failed to zero — they may show values in the old currency until the next fetch.", zeroErrors)
	}

	c.JSON(http.StatusOK, gin.H{
		"currency": input.Currency,
		"message":  msg,
	})
}
