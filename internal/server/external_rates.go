package server

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"strconv"
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
		external.PUT("/rates/batch", s.putExternalRateBatch)
	}
}

type rateResult struct {
	ID           int    `json:"id,omitempty"`
	TokenAddress string `json:"token_address"`
	Symbol       string `json:"symbol"`
	PriceFiat    float64 `json:"price_fiat"`
	Source       string  `json:"source"`
	UpdatedAt    string  `json:"updated_at,omitempty"`
	Decimals     *int    `json:"decimals,omitempty"`
}

// processSingleRate handles one rate update/create. Returns (httpStatus, result, errorMsg).
// If errorMsg is non-empty, the operation failed.
func (s *Server) processSingleRate(ctx context.Context, tokenAddress string, price float64, symbol string, decimals *int, apiKeyID, apiKeyName, ip string, ipChanged bool) (int, *rateResult, string) {
	// Look up existing
	existing, err := s.db.GetSystemTokenPriceByAddress(ctx, tokenAddress)
	if err != nil {
		return http.StatusInternalServerError, nil, "failed to look up system token price"
	}

	if existing != nil {
		// CoinGecko protection
		if existing.Source == "coingecko" {
			return http.StatusConflict, nil, "cannot override CoinGecko-sourced token via external API; use the admin dashboard to manage CoinGecko tokens"
		}

		// Bounds check
		oldPrice := existing.PriceFiat
		if oldPrice > 0 {
			deviationPct := math.Abs(price-oldPrice) / oldPrice * 100
			maxDeviation := 50.0
			if v, _ := s.db.GetSystemSetting(ctx, "max_price_deviation_pct"); v != "" {
				if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 {
					maxDeviation = parsed
				}
			}
			if deviationPct > maxDeviation {
				return http.StatusUnprocessableEntity, nil, fmt.Sprintf(
					"price change of %.1f%% exceeds maximum allowed deviation of %.1f%% (current: %.2f, proposed: %.2f). Use the admin dashboard for larger adjustments.",
					deviationPct, maxDeviation, oldPrice, price,
				)
			}
		}

		// Cooldown check
		cooldownMinutes := 1440
		if v, _ := s.db.GetSystemSetting(ctx, "price_update_cooldown_minutes"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				cooldownMinutes = parsed
			}
		}
		if cooldownMinutes > 0 {
			elapsed := time.Since(existing.UpdatedAt)
			cooldown := time.Duration(cooldownMinutes) * time.Minute
			if elapsed < cooldown {
				remaining := cooldown - elapsed
				return http.StatusTooManyRequests, nil, fmt.Sprintf(
					"price for %s was updated %dm ago; next update allowed in %dm. Cooldown: %d minutes (configurable via admin settings).",
					existing.Symbol, int(elapsed.Minutes()), int(remaining.Minutes()), cooldownMinutes,
				)
			}
		}

		// Update
		oldPriceVal := existing.PriceFiat
		existing.PriceFiat = price
		existing.Source = "external"
		existing.UpdatedAt = time.Now()
		if err := s.db.UpdateSystemTokenPriceByID(ctx, existing); err != nil {
			return http.StatusInternalServerError, nil, "failed to update system token price"
		}

		// Audit log
		s.logPriceChange(ctx, tokenAddress, existing.Symbol, &oldPriceVal, price, apiKeyID, apiKeyName, ip, ipChanged)

		return http.StatusOK, &rateResult{
			ID:           existing.ID,
			TokenAddress: tokenAddress,
			Symbol:       existing.Symbol,
			PriceFiat:    existing.PriceFiat,
			Source:       existing.Source,
			UpdatedAt:    existing.UpdatedAt.Format(time.RFC3339),
		}, ""
	}

	// New token — require symbol and decimals
	if symbol == "" {
		return http.StatusBadRequest, nil, "symbol is required for new tokens"
	}
	if decimals == nil {
		return http.StatusBadRequest, nil, "decimals is required for new tokens"
	}
	if *decimals < 0 || *decimals > 77 {
		return http.StatusBadRequest, nil, "decimals must be between 0 and 77"
	}
	if len(symbol) > 20 {
		return http.StatusBadRequest, nil, "symbol must be 20 characters or fewer"
	}

	newPrice := &compliance.SystemTokenPrice{
		Symbol:       symbol,
		Decimals:     *decimals,
		PriceFiat:    price,
		Source:       "external",
		TokenAddress: &tokenAddress,
		UpdatedAt:    time.Now(),
	}
	if err := s.db.CreateSystemTokenPrice(ctx, newPrice); err != nil {
		return http.StatusInternalServerError, nil, "failed to create system token price"
	}

	// Audit log (new token, no old price)
	s.logPriceChange(ctx, tokenAddress, symbol, nil, price, apiKeyID, apiKeyName, ip, ipChanged)

	d := newPrice.Decimals
	return http.StatusCreated, &rateResult{
		ID:           newPrice.ID,
		TokenAddress: tokenAddress,
		Symbol:       newPrice.Symbol,
		PriceFiat:    newPrice.PriceFiat,
		Source:       newPrice.Source,
		UpdatedAt:    newPrice.UpdatedAt.Format(time.RFC3339),
		Decimals:     &d,
	}, ""
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

	// Normalize address
	input.TokenAddress = strings.ToLower(strings.TrimSpace(input.TokenAddress))
	if input.TokenAddress != "native" {
		if len(input.TokenAddress) != 42 || !hexAddressRe.MatchString(input.TokenAddress) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token_address must be 'native' or a valid 42-character hex address starting with 0x"})
			return
		}
	}

	// IP change detection
	apiKeyID := c.GetString("api_key_id")
	apiKeyName := c.GetString("api_key_name")
	currentIP := c.ClientIP()
	ipChanged := s.detectIPChange(c.Request.Context(), apiKeyID, apiKeyName, currentIP)

	status, result, errMsg := s.processSingleRate(c.Request.Context(), input.TokenAddress, input.Price, input.Symbol, input.Decimals, apiKeyID, apiKeyName, currentIP, ipChanged)
	if errMsg != "" {
		c.JSON(status, gin.H{"error": errMsg})
		return
	}
	c.JSON(status, result)
}

func (s *Server) putExternalRateBatch(c *gin.Context) {
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

	apiKeyID := c.GetString("api_key_id")
	apiKeyName := c.GetString("api_key_name")
	currentIP := c.ClientIP()
	ipChanged := s.detectIPChange(c.Request.Context(), apiKeyID, apiKeyName, currentIP)
	ctx := c.Request.Context()

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
		addr := strings.ToLower(strings.TrimSpace(item.TokenAddress))
		results[i].TokenAddress = addr

		// Validate
		if item.Price <= 0 {
			results[i].Status = "error"
			results[i].Error = "price must be greater than 0"
			continue
		}
		if addr != "native" {
			if len(addr) != 42 || !hexAddressRe.MatchString(addr) {
				results[i].Status = "error"
				results[i].Error = "invalid token address format"
				continue
			}
		}

		status, result, errMsg := s.processSingleRate(ctx, addr, item.Price, item.Symbol, item.Decimals, apiKeyID, apiKeyName, currentIP, ipChanged)
		if errMsg != "" {
			results[i].Status = "error"
			results[i].Error = errMsg
			_ = status // status code not used in batch response per-item
			continue
		}
		results[i].Status = "ok"
		results[i].PriceFiat = result.PriceFiat
		results[i].Symbol = result.Symbol
		results[i].Source = result.Source
	}

	c.JSON(http.StatusOK, gin.H{"results": results})
}

// detectIPChange checks if the API key is being used from a new IP address.
// It logs a warning if the IP has changed and updates the stored IP asynchronously.
func (s *Server) detectIPChange(ctx context.Context, apiKeyID, apiKeyName, currentIP string) bool {
	ipChanged := false
	lastIP, err := s.db.GetAPIKeyLastIP(ctx, apiKeyID)
	if err != nil {
		log.Printf("WARNING: failed to get last IP for API key %s: %v", apiKeyID, err)
	} else if lastIP != nil && *lastIP != currentIP {
		ipChanged = true
		log.Printf("WARNING: API key '%s' used from new IP %s (previous: %s)", apiKeyName, currentIP, *lastIP)
	}

	// Update last_ip async
	go func() {
		bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.db.UpdateAPIKeyLastIP(bgCtx, apiKeyID, currentIP); err != nil {
			log.Printf("WARNING: failed to update API key last_ip: %v", err)
		}
	}()

	return ipChanged
}

// logPriceChange records a price change in the audit log.
func (s *Server) logPriceChange(ctx context.Context, tokenAddress, symbol string, oldPrice *float64, newPrice float64, apiKeyID, apiKeyName, ip string, ipChanged bool) {
	entry := &compliance.PriceChangeLog{
		APIKeyID:     apiKeyID,
		APIKeyName:   apiKeyName,
		TokenAddress: tokenAddress,
		Symbol:       symbol,
		OldPrice:     oldPrice,
		NewPrice:     newPrice,
		IPAddress:    ip,
		IPChanged:    ipChanged,
	}
	if oldPrice != nil && *oldPrice > 0 {
		dev := math.Abs(newPrice-*oldPrice) / *oldPrice * 100
		entry.DeviationPct = &dev
	}
	if err := s.db.CreatePriceChangeLog(ctx, entry); err != nil {
		log.Printf("WARNING: failed to log price change for %s: %v", tokenAddress, err)
	}
}

// Admin settings endpoints for external rates protection

func (s *Server) getExternalRatesSettings(c *gin.Context) {
	ctx := c.Request.Context()

	maxDev := 50.0
	if v, _ := s.db.GetSystemSetting(ctx, "max_price_deviation_pct"); v != "" {
		if parsed, err := strconv.ParseFloat(v, 64); err == nil && parsed > 0 {
			maxDev = parsed
		}
	}

	cooldown := 1440
	if v, _ := s.db.GetSystemSetting(ctx, "price_update_cooldown_minutes"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			cooldown = parsed
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"max_price_deviation_pct":       maxDev,
		"price_update_cooldown_minutes": cooldown,
	})
}

func (s *Server) setExternalRatesSettings(c *gin.Context) {
	var input struct {
		MaxPriceDeviationPct   *float64 `json:"max_price_deviation_pct"`
		PriceUpdateCooldownMin *int     `json:"price_update_cooldown_minutes"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	if input.MaxPriceDeviationPct != nil {
		if *input.MaxPriceDeviationPct <= 0 || *input.MaxPriceDeviationPct > 1000 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "max_price_deviation_pct must be between 0 and 1000"})
			return
		}
		if err := s.db.SetSystemSetting(ctx, "max_price_deviation_pct", fmt.Sprintf("%.1f", *input.MaxPriceDeviationPct)); err != nil {
			internalError(c, "failed to save setting", err)
			return
		}
	}

	if input.PriceUpdateCooldownMin != nil {
		if *input.PriceUpdateCooldownMin < 0 || *input.PriceUpdateCooldownMin > 525600 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "price_update_cooldown_minutes must be between 0 and 525600 (1 year)"})
			return
		}
		if err := s.db.SetSystemSetting(ctx, "price_update_cooldown_minutes", strconv.Itoa(*input.PriceUpdateCooldownMin)); err != nil {
			internalError(c, "failed to save setting", err)
			return
		}
	}

	// Return current settings
	s.getExternalRatesSettings(c)
}

func (s *Server) listPriceChangeLogs(c *gin.Context) {
	limit := 50
	offset := 0
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}
	if v := c.Query("offset"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	logs, total, err := s.db.ListPriceChangeLogs(c.Request.Context(), limit, offset)
	if err != nil {
		internalError(c, "failed to list price change logs", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
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
		"key":         rawKey,
		"id":          key.ID,
		"name":        key.Name,
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
		"currency":                   currency,
		"all_currencies":             allCurrencies,
		"coingecko_enabled":          !s.config.DisableCoinGecko,
		"external_rates_api_enabled": s.config.EnableExternalRatesAPI,
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

	// Trigger immediate re-fetch in the new currency
	if s.priceService != nil {
		s.priceService.RefreshNow()
	}

	msg := "Base currency updated to " + strings.ToUpper(input.Currency) + ". CoinGecko prices are being re-fetched in the new currency."
	if zeroErrors > 0 {
		msg = fmt.Sprintf("Base currency updated. %d CoinGecko price(s) failed to zero — they may show values in the old currency until the next fetch.", zeroErrors)
	}

	c.JSON(http.StatusOK, gin.H{
		"currency": input.Currency,
		"message":  msg,
	})
}
