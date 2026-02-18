package server

import (
	"errors"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/db"
)

// Default travel rule record expiration duration.
const travelRuleRecordTTL = 24 * time.Hour

// Max pagination limit to prevent memory exhaustion from unbounded queries.
const maxPaginationLimit = 1000

// internalError logs the real error server-side and returns a generic message to the client.
func internalError(c *gin.Context, msg string, err error) {
	log.Printf("ERROR: %s: %v", msg, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
}

// registerComplianceRoutes adds compliance management endpoints to the admin API.
func (s *Server) registerComplianceRoutes(adminGroup *gin.RouterGroup) {
	// org-scoped routes
	orgRoutes := adminGroup.Group("/orgs/:org_id/compliance")
	orgRoutes.GET("/config", s.getComplianceConfig)
	orgRoutes.PUT("/config", s.updateComplianceConfig)
	orgRoutes.GET("/tokens", s.listTokenPrices)
	orgRoutes.PUT("/tokens/:token_address", s.upsertTokenPrice)
	orgRoutes.DELETE("/tokens/:token_address", s.deleteTokenPrice)
	orgRoutes.POST("/travel-rule-records", s.createTravelRuleRecord)
	orgRoutes.GET("/travel-rule-records", s.listTravelRuleRecords)
	orgRoutes.DELETE("/travel-rule-records/:id", s.deleteTravelRuleRecord)
	orgRoutes.GET("/logs", s.listComplianceLogs)
	orgRoutes.GET("/address-thresholds", s.listAddressThresholdOverrides)
	orgRoutes.PUT("/address-thresholds/:address", s.upsertAddressThresholdOverride)
	orgRoutes.DELETE("/address-thresholds/:address", s.deleteAddressThresholdOverride)

	// global routes
	adminGroup.GET("/compliance/sanctions", s.listSanctionedAddresses)
	adminGroup.POST("/compliance/sanctions", s.addSanctionedAddress)
	adminGroup.DELETE("/compliance/sanctions/:id", s.removeSanctionedAddress)
}

// compliancePaginationParams parses and caps pagination parameters.
func compliancePaginationParams(c *gin.Context, defaultLimit int) (int, int) {
	limit, offset := parsePaginationParams(c, defaultLimit)
	if limit > maxPaginationLimit {
		limit = maxPaginationLimit
	}
	return limit, offset
}

// Compliance Config handlers

func (s *Server) getComplianceConfig(c *gin.Context) {
	orgID := c.Param("org_id")

	config, err := s.db.GetComplianceConfig(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to load compliance config", err)
		return
	}

	// Return default config if none exists
	if config == nil {
		config = &compliance.ComplianceConfig{
			OrgID:        orgID,
			Enabled:      false,
			ThresholdUSD: 1000,
		}
	}

	c.JSON(http.StatusOK, config)
}

func (s *Server) updateComplianceConfig(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		Enabled      *bool    `json:"enabled"`
		ThresholdUSD *float64 `json:"threshold_usd"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Fetch existing config or create a new one
	config, err := s.db.GetComplianceConfig(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to load compliance config", err)
		return
	}

	if config == nil {
		config = &compliance.ComplianceConfig{
			ID:           uuid.New().String(),
			OrgID:        orgID,
			Enabled:      false,
			ThresholdUSD: 1000,
		}
	}

	if input.Enabled != nil {
		config.Enabled = *input.Enabled
	}
	if input.ThresholdUSD != nil {
		if *input.ThresholdUSD < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "threshold_usd must be >= 0"})
			return
		}
		config.ThresholdUSD = *input.ThresholdUSD
	}

	if err := s.db.UpsertComplianceConfig(c.Request.Context(), config); err != nil {
		internalError(c, "failed to save compliance config", err)
		return
	}

	c.JSON(http.StatusOK, config)
}

// Token Price handlers

func (s *Server) listTokenPrices(c *gin.Context) {
	orgID := c.Param("org_id")

	prices, err := s.db.ListTokenPrices(c.Request.Context(), orgID)
	if err != nil {
		internalError(c, "failed to list token prices", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": prices})
}

func (s *Server) upsertTokenPrice(c *gin.Context) {
	orgID := c.Param("org_id")
	tokenAddress := strings.ToLower(c.Param("token_address"))

	var input struct {
		Symbol   string  `json:"symbol" binding:"required"`
		Decimals int     `json:"decimals"`
		PriceUSD float64 `json:"price_usd"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.PriceUSD <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "price_usd must be greater than 0"})
		return
	}
	// Validate decimals range (EVM tokens use 0-77; standard tokens 0-18)
	if input.Decimals < 0 || input.Decimals > 77 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decimals must be between 0 and 77"})
		return
	}
	// Validate symbol length
	if len(input.Symbol) > 20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "symbol must be 20 characters or fewer"})
		return
	}

	// Check if a price entry already exists
	existing, err := s.db.GetTokenPrice(c.Request.Context(), orgID, tokenAddress)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}

	price := &compliance.TokenPrice{
		OrgID:        orgID,
		TokenAddress: tokenAddress,
		Symbol:       input.Symbol,
		Decimals:     input.Decimals,
		PriceUSD:     input.PriceUSD,
	}

	if existing != nil {
		price.ID = existing.ID
	} else {
		price.ID = uuid.New().String()
	}

	if err := s.db.UpsertTokenPrice(c.Request.Context(), price); err != nil {
		internalError(c, "failed to save token price", err)
		return
	}

	c.JSON(http.StatusOK, price)
}

func (s *Server) deleteTokenPrice(c *gin.Context) {
	orgID := c.Param("org_id")
	tokenAddress := strings.ToLower(c.Param("token_address"))

	existing, err := s.db.GetTokenPrice(c.Request.Context(), orgID, tokenAddress)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token price not found"})
		return
	}

	if err := s.db.DeleteTokenPrice(c.Request.Context(), orgID, tokenAddress); err != nil {
		internalError(c, "failed to delete token price", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token price deleted"})
}

// Travel Rule Record handlers

// M5: No rate limit on record creation. This is an admin-only endpoint accessible
// only from localhost. Rate limiting is out of scope for PoC but should be added
// before production deployment.

func (s *Server) createTravelRuleRecord(c *gin.Context) {
	orgID := c.Param("org_id")

	// C3: amount_usd is NOT accepted from input — it is computed server-side from
	// amount_wei and the configured token price to prevent forged USD values.
	var input struct {
		OriginatorUserID   string         `json:"originator_user_id" binding:"required"`
		OriginatorData     map[string]any `json:"originator_data" binding:"required"`
		BeneficiaryData    map[string]any `json:"beneficiary_data" binding:"required"`
		TransferType       string         `json:"transfer_type" binding:"required"`
		TokenAddress       *string        `json:"token_address"`
		BeneficiaryAddress string         `json:"beneficiary_address" binding:"required"`
		AmountWei          string         `json:"amount_wei" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// H3: Validate amount_wei is a valid positive numeric string
	amountWei, ok := new(big.Int).SetString(input.AmountWei, 10)
	if !ok || amountWei.Sign() <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "amount_wei must be a positive integer string"})
		return
	}

	// Validate transfer type
	transferType := compliance.TransferType(input.TransferType)
	if transferType != compliance.TransferTypeETH && transferType != compliance.TransferTypeERC20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transfer_type, must be 'eth' or 'erc20'"})
		return
	}

	// H5: Require token_address for ERC-20 records
	if transferType == compliance.TransferTypeERC20 {
		if input.TokenAddress == nil || !auth.IsValidAddress(*input.TokenAddress) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "token_address is required and must be a valid address for erc20 transfer type"})
			return
		}
	}

	// Validate beneficiary address
	if !auth.IsValidAddress(input.BeneficiaryAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid beneficiary_address format"})
		return
	}

	// C3: Look up the token price and compute amount_usd server-side.
	tokenAddr := "native"
	if transferType == compliance.TransferTypeERC20 && input.TokenAddress != nil {
		tokenAddr = strings.ToLower(*input.TokenAddress)
	}

	ctx := c.Request.Context()
	tokenPrice, err := s.db.GetTokenPrice(ctx, orgID, tokenAddr)
	if err != nil {
		internalError(c, "failed to look up token price", err)
		return
	}
	if tokenPrice == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no token price configured for " + tokenAddr + "; configure it in Token Prices first"})
		return
	}

	amountUSD, err := compliance.WeiToUSD(amountWei, tokenPrice.Decimals, tokenPrice.PriceUSD)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to compute USD value: " + err.Error()})
		return
	}
	if amountUSD <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "computed amount_usd must be greater than 0"})
		return
	}

	record := &compliance.TravelRuleRecord{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		OriginatorUserID:   input.OriginatorUserID,
		OriginatorData:     input.OriginatorData,
		BeneficiaryData:    input.BeneficiaryData,
		TransferType:       transferType,
		TokenAddress:       lowercasePtr(input.TokenAddress),
		BeneficiaryAddress: strings.ToLower(input.BeneficiaryAddress),
		AmountWei:          input.AmountWei,
		AmountUSD:          amountUSD,
		ExpiresAt:          time.Now().Add(travelRuleRecordTTL),
	}

	if err := s.db.CreateTravelRuleRecord(c.Request.Context(), record); err != nil {
		internalError(c, "failed to create travel rule record", err)
		return
	}

	c.JSON(http.StatusCreated, record)
}

func (s *Server) listTravelRuleRecords(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	records, total, err := s.db.ListTravelRuleRecords(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list travel rule records", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": records, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) deleteTravelRuleRecord(c *gin.Context) {
	orgID := c.Param("org_id")
	id := c.Param("id")

	// Validate id is a valid UUID
	if _, err := uuid.Parse(id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid record id format"})
		return
	}

	err := s.db.DeleteTravelRuleRecord(c.Request.Context(), orgID, id)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "travel rule record not found"})
			return
		}
		if errors.Is(err, db.ErrRecordAlreadyUsed) {
			c.JSON(http.StatusConflict, gin.H{"error": "cannot delete used travel rule record"})
			return
		}
		internalError(c, "failed to delete travel rule record", err)
		return
	}

	c.Status(http.StatusNoContent)
}

// Sanctioned Address handlers

func (s *Server) listSanctionedAddresses(c *gin.Context) {
	limit, offset := compliancePaginationParams(c, 50)

	var orgID *string
	if q := c.Query("org_id"); q != "" {
		orgID = &q
	}

	addresses, total, err := s.db.ListSanctionedAddresses(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list sanctioned addresses", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": addresses, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) addSanctionedAddress(c *gin.Context) {
	var input struct {
		OrgID   *string `json:"org_id"`
		Address string  `json:"address" binding:"required"`
		Reason  string  `json:"reason" binding:"required"`
		Source  string  `json:"source"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !auth.IsValidAddress(input.Address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}
	// Validate reason length
	if len(input.Reason) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reason must be 1000 characters or fewer"})
		return
	}

	sanction := &compliance.SanctionedAddress{
		ID:      uuid.New().String(),
		OrgID:   input.OrgID,
		Address: strings.ToLower(input.Address),
		Reason:  input.Reason,
		Source:  input.Source,
	}

	if err := s.db.AddSanctionedAddress(c.Request.Context(), sanction); err != nil {
		internalError(c, "failed to add sanctioned address", err)
		return
	}

	c.JSON(http.StatusCreated, sanction)
}

func (s *Server) removeSanctionedAddress(c *gin.Context) {
	id := c.Param("id")

	existing, err := s.db.GetSanctionedAddress(c.Request.Context(), id)
	if err != nil {
		internalError(c, "failed to look up sanctioned address", err)
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "sanctioned address not found"})
		return
	}

	if err := s.db.RemoveSanctionedAddress(c.Request.Context(), id); err != nil {
		internalError(c, "failed to remove sanctioned address", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "sanctioned address removed"})
}

// Address Threshold Override handlers

func (s *Server) listAddressThresholdOverrides(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	overrides, total, err := s.db.ListAddressThresholdOverrides(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		internalError(c, "failed to list address threshold overrides", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": overrides, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) upsertAddressThresholdOverride(c *gin.Context) {
	orgID := c.Param("org_id")
	address := strings.ToLower(c.Param("address"))

	if !auth.IsValidAddress(address) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address format"})
		return
	}

	var input struct {
		ThresholdUSD float64 `json:"threshold_usd"`
		Note         string  `json:"note"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if input.ThresholdUSD < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "threshold_usd must be >= 0"})
		return
	}
	if len(input.Note) > 1000 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "note must be 1000 characters or fewer"})
		return
	}

	// Check if an override already exists
	existing, err := s.db.GetAddressThresholdOverride(c.Request.Context(), orgID, address)
	if err != nil {
		internalError(c, "failed to look up address threshold override", err)
		return
	}

	override := &compliance.AddressThresholdOverride{
		OrgID:        orgID,
		Address:      address,
		ThresholdUSD: input.ThresholdUSD,
		Note:         input.Note,
	}

	if existing != nil {
		override.ID = existing.ID
	} else {
		override.ID = uuid.New().String()
	}

	if err := s.db.UpsertAddressThresholdOverride(c.Request.Context(), override); err != nil {
		internalError(c, "failed to save address threshold override", err)
		return
	}

	c.JSON(http.StatusOK, override)
}

func (s *Server) deleteAddressThresholdOverride(c *gin.Context) {
	orgID := c.Param("org_id")
	address := strings.ToLower(c.Param("address"))

	existing, err := s.db.GetAddressThresholdOverride(c.Request.Context(), orgID, address)
	if err != nil {
		internalError(c, "failed to look up address threshold override", err)
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "address threshold override not found"})
		return
	}

	if err := s.db.DeleteAddressThresholdOverride(c.Request.Context(), orgID, address); err != nil {
		internalError(c, "failed to delete address threshold override", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "address threshold override deleted"})
}

// Compliance Log handlers

func (s *Server) listComplianceLogs(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := compliancePaginationParams(c, 50)

	filters := &compliance.ComplianceLogFilters{
		Limit:  limit,
		Offset: offset,
	}

	if userSearch := c.Query("user_search"); userSearch != "" {
		filters.UserSearch = &userSearch
	}
	// Whitelist decision values
	if decision := c.Query("decision"); decision == "allowed" || decision == "denied" {
		filters.Decision = &decision
	}
	// Whitelist transfer_type values
	if transferType := c.Query("transfer_type"); transferType == "eth" || transferType == "erc20" {
		tt := compliance.TransferType(transferType)
		filters.TransferType = &tt
	}

	logs, total, err := s.db.ListComplianceLogs(c.Request.Context(), orgID, filters)
	if err != nil {
		internalError(c, "failed to list compliance logs", err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
}

// lowercasePtr returns a pointer to the lowercased string, or nil if the input is nil.
func lowercasePtr(s *string) *string {
	if s == nil {
		return nil
	}
	lower := strings.ToLower(*s)
	return &lower
}
