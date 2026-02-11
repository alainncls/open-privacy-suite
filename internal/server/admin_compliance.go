package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
)

// Default travel rule record expiration duration.
const travelRuleRecordTTL = 24 * time.Hour

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
	orgRoutes.GET("/logs", s.listComplianceLogs)

	// global routes
	adminGroup.GET("/compliance/sanctions", s.listSanctionedAddresses)
	adminGroup.POST("/compliance/sanctions", s.addSanctionedAddress)
	adminGroup.DELETE("/compliance/sanctions/:id", s.removeSanctionedAddress)
}

// Compliance Config handlers

func (s *Server) getComplianceConfig(c *gin.Context) {
	orgID := c.Param("org_id")

	config, err := s.db.GetComplianceConfig(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		config.ThresholdUSD = *input.ThresholdUSD
	}

	if err := s.db.UpsertComplianceConfig(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, config)
}

// Token Price handlers

func (s *Server) listTokenPrices(c *gin.Context) {
	orgID := c.Param("org_id")

	prices, err := s.db.ListTokenPrices(c.Request.Context(), orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		PriceUSD float64 `json:"price_usd" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if a price entry already exists
	existing, err := s.db.GetTokenPrice(c.Request.Context(), orgID, tokenAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, price)
}

func (s *Server) deleteTokenPrice(c *gin.Context) {
	orgID := c.Param("org_id")
	tokenAddress := strings.ToLower(c.Param("token_address"))

	existing, err := s.db.GetTokenPrice(c.Request.Context(), orgID, tokenAddress)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "token price not found"})
		return
	}

	if err := s.db.DeleteTokenPrice(c.Request.Context(), orgID, tokenAddress); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token price deleted"})
}

// Travel Rule Record handlers

func (s *Server) createTravelRuleRecord(c *gin.Context) {
	orgID := c.Param("org_id")

	var input struct {
		OriginatorUserID   string         `json:"originator_user_id" binding:"required"`
		OriginatorData     map[string]any `json:"originator_data" binding:"required"`
		BeneficiaryData    map[string]any `json:"beneficiary_data" binding:"required"`
		TransferType       string         `json:"transfer_type" binding:"required"`
		TokenAddress       *string        `json:"token_address"`
		BeneficiaryAddress string         `json:"beneficiary_address" binding:"required"`
		AmountWei          string         `json:"amount_wei" binding:"required"`
		AmountUSD          float64        `json:"amount_usd" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate transfer type
	transferType := compliance.TransferType(input.TransferType)
	if transferType != compliance.TransferTypeETH && transferType != compliance.TransferTypeERC20 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid transfer_type, must be 'eth' or 'erc20'"})
		return
	}

	// Validate beneficiary address
	if !auth.IsValidAddress(input.BeneficiaryAddress) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid beneficiary_address format"})
		return
	}

	record := &compliance.TravelRuleRecord{
		ID:                 uuid.New().String(),
		OrgID:              orgID,
		OriginatorUserID:   input.OriginatorUserID,
		OriginatorData:     input.OriginatorData,
		BeneficiaryData:    input.BeneficiaryData,
		TransferType:       transferType,
		TokenAddress:       input.TokenAddress,
		BeneficiaryAddress: strings.ToLower(input.BeneficiaryAddress),
		AmountWei:          input.AmountWei,
		AmountUSD:          input.AmountUSD,
		ExpiresAt:          time.Now().Add(travelRuleRecordTTL),
	}

	if err := s.db.CreateTravelRuleRecord(c.Request.Context(), record); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, record)
}

func (s *Server) listTravelRuleRecords(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	records, total, err := s.db.ListTravelRuleRecords(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": records, "total": total, "limit": limit, "offset": offset})
}

// Sanctioned Address handlers

func (s *Server) listSanctionedAddresses(c *gin.Context) {
	limit, offset := parsePaginationParams(c, 50)

	var orgID *string
	if q := c.Query("org_id"); q != "" {
		orgID = &q
	}

	addresses, total, err := s.db.ListSanctionedAddresses(c.Request.Context(), orgID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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

	sanction := &compliance.SanctionedAddress{
		ID:      uuid.New().String(),
		OrgID:   input.OrgID,
		Address: strings.ToLower(input.Address),
		Reason:  input.Reason,
		Source:  input.Source,
	}

	if err := s.db.AddSanctionedAddress(c.Request.Context(), sanction); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, sanction)
}

func (s *Server) removeSanctionedAddress(c *gin.Context) {
	id := c.Param("id")

	existing, err := s.db.GetSanctionedAddress(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "sanctioned address not found"})
		return
	}

	if err := s.db.RemoveSanctionedAddress(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "sanctioned address removed"})
}

// Compliance Log handlers

func (s *Server) listComplianceLogs(c *gin.Context) {
	orgID := c.Param("org_id")
	limit, offset := parsePaginationParams(c, 50)

	filters := &compliance.ComplianceLogFilters{
		Limit:  limit,
		Offset: offset,
	}

	if userID := c.Query("user_id"); userID != "" {
		filters.UserID = &userID
	}
	if decision := c.Query("decision"); decision != "" {
		filters.Decision = &decision
	}
	if transferType := c.Query("transfer_type"); transferType != "" {
		tt := compliance.TransferType(transferType)
		filters.TransferType = &tt
	}

	logs, total, err := s.db.ListComplianceLogs(c.Request.Context(), orgID, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
}
