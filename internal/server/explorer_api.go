package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/proxy"

	"github.com/gin-gonic/gin"
)

// Explorer API Response Types

// OwnAddress represents an address owned by the viewer
type OwnAddress struct {
	Address string  `json:"address"`
	ENSName *string `json:"ens_name,omitempty"`
}

// DisclosedAddress represents an address disclosed to the viewer via a grant
// SECURITY: For non-full disclosures, Address contains the pseudonym or placeholder, NOT the real address
type DisclosedAddress struct {
	Address         string     `json:"address"`    // Pseudonym for pseudonymous, "[REDACTED]" for redacted, real for full
	AddressID       string     `json:"address_id"` // Opaque identifier for routing (hash of real address)
	OwnerDID        string     `json:"owner_did"`
	DisclosureLevel string     `json:"disclosure_level"`
	GrantID         string     `json:"grant_id"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ENSName         *string    `json:"ens_name,omitempty"` // Only included for full disclosure
}

// ViewableAddressesResponse is the response for GET /api/v1/explorer/viewable-addresses
type ViewableAddressesResponse struct {
	ViewerWallet       string             `json:"viewer_wallet"`
	ViewerDID          string             `json:"viewer_did,omitempty"`
	OwnAddresses       []OwnAddress       `json:"own_addresses"`
	DisclosedAddresses []DisclosedAddress `json:"disclosed_addresses"`
}

// VisibilityLevel represents how much of an address's data is visible
type VisibilityLevel string

const (
	VisibilityFull         VisibilityLevel = "full"
	VisibilityPseudonymous VisibilityLevel = "pseudonymous"
	VisibilityRedacted     VisibilityLevel = "redacted"
	VisibilityHidden       VisibilityLevel = "hidden"
)

// VisibilityReason explains why an address has certain visibility
type VisibilityReason string

const (
	ReasonOwnAddress      VisibilityReason = "own_address"
	ReasonDisclosureGrant VisibilityReason = "disclosure_grant"
	ReasonPublicAddress   VisibilityReason = "public_address"
	ReasonNoAccess        VisibilityReason = "no_access"
	ReasonRBACGroupMember VisibilityReason = "rbac_group_member"
)

// AddressVisibility represents the visibility status of a single address
type AddressVisibility struct {
	Address   string           `json:"address"`
	Visible   bool             `json:"visible"`
	Level     VisibilityLevel  `json:"level"`
	Reason    VisibilityReason `json:"reason"`
	Pseudonym *string          `json:"pseudonym,omitempty"`
	GrantID   *string          `json:"grant_id,omitempty"`
	ExpiresAt *time.Time       `json:"expires_at,omitempty"`
}

// CheckAddressResponse is the response for GET /api/v1/explorer/check-address/:address
type CheckAddressResponse struct {
	AddressVisibility
}

// BatchCheckAddressesRequest is the request body for POST /api/v1/explorer/check-addresses
type BatchCheckAddressesRequest struct {
	Addresses []string `json:"addresses" binding:"required,min=1,max=100"`
	DID       string   `json:"did,omitempty"` // Optional: DID to use directly (bypasses wallet->DID lookup)
}

// BatchCheckAddressesResponse is the response for POST /api/v1/explorer/check-addresses
type BatchCheckAddressesResponse struct {
	Results map[string]AddressVisibility `json:"results"`
}

// ResolveAddressResponse is returned when resolving an address_id
type ResolveAddressResponse struct {
	RealAddress     string `json:"real_address"`
	DisclosureLevel string `json:"disclosure_level"`
	GrantID         string `json:"grant_id"`
	Pseudonym       string `json:"pseudonym,omitempty"` // For pseudonymous, the display name to use
}

// registerExplorerRoutes registers the explorer API endpoints
// These endpoints are designed to be called by the explorer backend (internal).
// Network boundary: localhost-only. JWT: optional — if present it is validated and the
// viewer DID is extracted from it; if absent the request is treated as anonymous.
func (s *Server) registerExplorerRoutes(router *gin.Engine) {
	explorer := router.Group("/api/v1/explorer")
	explorer.Use(s.localhostOnlyMiddleware())
	explorer.Use(auth.OptionalJWTAuthMiddleware(s.jwtService, s.db))
	{
		explorer.GET("/viewable-addresses", s.getViewableAddresses)
		explorer.GET("/check-address/:address", s.checkAddressVisibility)
		explorer.POST("/check-addresses", s.batchCheckAddresses)
		// Resolve address_id to real address (for explorer backend internal use)
		explorer.GET("/grant/:grant_id/resolve/:address_id", s.resolveAddressID)

		// Data Retrieval Endpoints
		explorer.GET("/chain-id", s.getExplorerChainID)
		explorer.GET("/stats", s.getExplorerStats)
		explorer.GET("/stats/tx-history", s.getExplorerTransactionHistory)

		// Blocks — register specific routes before parameterized ones
		explorer.GET("/blocks", s.getExplorerBlocks)
		explorer.GET("/blocks/latest/number", s.getExplorerLatestBlockNumber)
		explorer.GET("/blocks/hash/:hash", s.getExplorerBlockByHash)
		explorer.GET("/blocks/:number", s.getExplorerBlock)
		explorer.GET("/blocks/:number/transactions", s.getExplorerBlockTransactions)
		explorer.GET("/blocks/:number/internal", s.getExplorerBlockInternalTxs)

		// Transactions — register specific routes before parameterized ones
		explorer.GET("/transactions/paginated", s.getExplorerTransactionsPaginated)
		explorer.GET("/transactions", s.getExplorerTransactions)
		explorer.GET("/transactions/:hash", s.getExplorerTransaction)
		explorer.GET("/transactions/:hash/internal", s.getExplorerTransactionInternal)
		explorer.GET("/transactions/:hash/transfers", s.getExplorerTransactionTransfers)
		explorer.GET("/transactions/:hash/logs", s.getExplorerTransactionLogs)
		explorer.GET("/transactions/:hash/op-deposit", s.getExplorerTransactionOPDeposit)

		// Addresses
		explorer.GET("/addresses/:address/stats", s.getExplorerAddressStats)
		explorer.GET("/addresses/:address/transactions", s.getExplorerAddressTransactions)
		explorer.GET("/addresses/:address/balance", s.getExplorerAddressBalance)
		explorer.GET("/addresses/:address/code", s.getExplorerAddressCode)
		explorer.GET("/addresses/:address/balances", s.getExplorerAddressTokenBalances)
		explorer.GET("/addresses/:address/transfers", s.getExplorerAddressTransfers)
		explorer.GET("/addresses/:address/internal", s.getExplorerAddressInternal)
		explorer.GET("/addresses/:address/logs", s.getExplorerAddressLogs)
		explorer.GET("/addresses/:address/contract", s.getExplorerAddressContract)
		explorer.GET("/addresses/:address/is-contract", s.getExplorerAddressIsContract)
		explorer.POST("/addresses/:address/abi", s.updateExplorerAddressABI)

		// Logs
		explorer.GET("/logs", s.getExplorerLogs)

		// Tokens
		explorer.GET("/tokens", s.getExplorerTokens)
		explorer.GET("/tokens/:address", s.getExplorerToken)
		explorer.GET("/tokens/:address/holders", s.getExplorerTokenHolders)
		explorer.GET("/tokens/:address/transfers", s.getExplorerTokenTransfers)

		// Transfers
		explorer.GET("/transfers", s.getExplorerAllTransfers)

		// Accounts
		explorer.GET("/accounts", s.getExplorerAccounts)

		// Search
		explorer.GET("/search/suggestions", s.getExplorerSearchSuggestions)

		// Sync
		explorer.GET("/sync/status", s.getExplorerSyncStatus)
		explorer.GET("/sync/indexer-progress", s.getExplorerIndexerProgress)
		explorer.GET("/sync/catchup", s.getExplorerCatchupProgress)

		// Indexing
		explorer.POST("/index/block/:number", s.indexExplorerBlock)
	}
}

// getViewableAddresses returns all addresses the wallet owner can view
// GET /api/v1/explorer/viewable-addresses?wallet=0x1234...&did=did:example:123
// Either wallet or did (or both) can be provided. If did is provided, it is used directly.
// If only wallet is provided, the DID is looked up from the wallet address.
func (s *Server) getViewableAddresses(c *gin.Context) {
	wallet := c.Query("wallet")
	did := c.Query("did")

	if wallet == "" && did == "" {
		respondBadRequest(c, "either wallet or did parameter is required")
		return
	}

	// Normalize wallet address if provided
	if wallet != "" {
		wallet = strings.ToLower(wallet)
	}

	ctx := c.Request.Context()
	response := ViewableAddressesResponse{
		ViewerWallet:       wallet,
		OwnAddresses:       []OwnAddress{},
		DisclosedAddresses: []DisclosedAddress{},
	}

	var viewerDID string
	var err error

	// If DID is provided directly, use it (skip wallet->DID lookup)
	if did != "" {
		viewerDID = did
	} else {
		// Look up DID from wallet address
		viewerDID, err = s.db.GetDIDByEthAddress(ctx, wallet)
		if err != nil {
			respondInternalError(c, "failed to look up DID: "+err.Error())
			return
		}
	}

	if viewerDID == "" {
		// Viewer is anonymous - no DID linked to this wallet
		// Return empty lists
		c.JSON(http.StatusOK, response)
		return
	}

	response.ViewerDID = viewerDID

	// 2. Get viewer's own addresses
	ownLinks, err := s.db.GetEthAddressesByDID(ctx, viewerDID)
	if err != nil {
		respondInternalError(c, "failed to get own addresses: "+err.Error())
		return
	}

	for _, link := range ownLinks {
		response.OwnAddresses = append(response.OwnAddresses, OwnAddress{
			Address: link.EthAddress,
			ENSName: link.ENSName,
		})
	}

	// 3. Get disclosure grants where the viewer is the requester
	// We need to find all grants where requester_did = viewerDID
	grants, err := s.getDisclosedAddressesForViewer(ctx, viewerDID)
	if err != nil {
		respondInternalError(c, "failed to get disclosed addresses: "+err.Error())
		return
	}
	response.DisclosedAddresses = grants

	c.JSON(http.StatusOK, response)
}

// getDisclosedAddressesForViewer returns all addresses disclosed to a viewer via grants
func (s *Server) getDisclosedAddressesForViewer(ctx context.Context, viewerDID string) ([]DisclosedAddress, error) {
	// Query for all active grants where the viewer is the requester
	query := `SELECT g.id, g.scope, g.expires_at, r.requester_did, u.external_id as target_did
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users u ON r.target_user_id = u.id
		WHERE r.requester_did = $1
		AND g.revoked_at IS NULL
		AND g.expires_at > NOW()`

	rows, err := s.db.Conn().QueryContext(ctx, query, viewerDID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []DisclosedAddress

	for rows.Next() {
		var grantID string
		var scope []byte
		var expiresAt time.Time
		var requesterDID, targetDID string

		if err := rows.Scan(&grantID, &scope, &expiresAt, &requesterDID, &targetDID); err != nil {
			return nil, err
		}

		// Get all addresses owned by the target DID
		targetAddresses, err := s.db.GetEthAddressesByDID(ctx, targetDID)
		if err != nil {
			return nil, err
		}

		// Parse scope JSON to determine disclosure level
		var scopeData disclosure.Scope
		disclosureLevel := "full" // Default to full
		if err := json.Unmarshal(scope, &scopeData); err == nil {
			if scopeData.DisclosureLevel != "" {
				disclosureLevel = string(scopeData.DisclosureLevel)
			}
		}

		for _, addr := range targetAddresses {
			// Generate opaque address ID for routing (hash-based)
			addressID := explorer.GenerateAddressID(addr.EthAddress, grantID)

			disclosed := DisclosedAddress{
				AddressID:       addressID,
				OwnerDID:        targetDID,
				DisclosureLevel: disclosureLevel,
				GrantID:         grantID,
				ExpiresAt:       &expiresAt,
			}

			// SECURITY: Only include real address for full disclosure
			switch disclosureLevel {
			case "full":
				disclosed.Address = addr.EthAddress
				disclosed.ENSName = addr.ENSName
			case "pseudonymous":
				disclosed.Address = explorer.GeneratePseudonym(addr.EthAddress)
				// Don't include ENS name - it could reveal identity
			case "redacted":
				disclosed.Address = "[REDACTED]"
				// Don't include ENS name
			default:
				// SECURITY: Fail-safe - treat unknown disclosure levels as redacted
				disclosed.Address = "[REDACTED]"
			}

			result = append(result, disclosed)
		}
	}

	return result, nil
}

// checkAddressVisibility checks if a specific address is visible to the viewer
// GET /api/v1/explorer/check-address/:address?wallet=0x1234...&did=did:example:123
// Either wallet or did (or both) can be provided. If did is provided, it is used directly.
func (s *Server) checkAddressVisibility(c *gin.Context) {
	wallet := c.Query("wallet")
	did := c.Query("did")

	if wallet == "" && did == "" {
		respondBadRequest(c, "either wallet or did parameter is required")
		return
	}

	targetAddress := c.Param("address")
	if targetAddress == "" {
		respondBadRequest(c, "address parameter is required")
		return
	}

	// Normalize addresses
	if wallet != "" {
		wallet = strings.ToLower(wallet)
	}
	targetAddress = strings.ToLower(targetAddress)

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), wallet, did, targetAddress)
	c.JSON(http.StatusOK, CheckAddressResponse{AddressVisibility: visibility})
}

// batchCheckAddresses checks visibility of multiple addresses at once
// POST /api/v1/explorer/check-addresses?wallet=0x1234...&did=did:example:123
// Either wallet or did (or both) can be provided via query string or request body.
// If did is provided, it is used directly.
func (s *Server) batchCheckAddresses(c *gin.Context) {
	wallet := c.Query("wallet")
	did := c.Query("did")

	var req BatchCheckAddressesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondBadRequest(c, "invalid request body: "+err.Error())
		return
	}

	// DID from request body takes precedence over query string
	if req.DID != "" {
		did = req.DID
	}

	if wallet == "" && did == "" {
		respondBadRequest(c, "either wallet or did parameter is required (in query string or request body)")
		return
	}

	// Normalize wallet address if provided
	if wallet != "" {
		wallet = strings.ToLower(wallet)
	}

	results := make(map[string]AddressVisibility)
	for _, addr := range req.Addresses {
		normalizedAddr := strings.ToLower(addr)
		results[normalizedAddr] = s.calculateAddressVisibilityWithDID(c.Request.Context(), wallet, did, normalizedAddr)
	}

	c.JSON(http.StatusOK, BatchCheckAddressesResponse{Results: results})
}

// resolveAddressID resolves an opaque address_id back to the real address
// GET /api/v1/explorer/grant/:grant_id/resolve/:address_id
// This is an internal API for the explorer backend to fetch data for disclosed addresses.
// SECURITY: This endpoint is localhost-only and returns the real address for backend use.
// The explorer backend must apply appropriate redaction before sending to the frontend.
func (s *Server) resolveAddressID(c *gin.Context) {
	grantID := c.Param("grant_id")
	addressID := c.Param("address_id")

	if grantID == "" || addressID == "" {
		respondBadRequest(c, "grant_id and address_id are required")
		return
	}

	// Look up the grant with its request
	grantWithRequest, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil || grantWithRequest == nil {
		respondNotFound(c, "grant not found")
		return
	}

	grant := grantWithRequest.Grant

	// Check grant is still valid
	if grant.RevokedAt != nil {
		respondForbidden(c, "grant has been revoked")
		return
	}
	if grant.ExpiresAt.Before(time.Now()) {
		respondForbidden(c, "grant has expired")
		return
	}

	// Get target DID from the request
	request := grantWithRequest.Request
	targetUser, err := s.db.GetUser(c.Request.Context(), request.TargetUserID)
	if err != nil || targetUser == nil {
		respondInternalError(c, "failed to get target user")
		return
	}
	targetDID := targetUser.ExternalID

	// Get all addresses for the target DID
	addresses, err := s.db.GetEthAddressesByDID(c.Request.Context(), targetDID)
	if err != nil {
		respondInternalError(c, "failed to get addresses")
		return
	}

	// Find the address matching the address_id
	var realAddress string
	for _, addr := range addresses {
		computedID := explorer.GenerateAddressID(addr.EthAddress, grantID)
		if computedID == addressID {
			realAddress = addr.EthAddress
			break
		}
	}

	if realAddress == "" {
		respondNotFound(c, "address not found for this grant")
		return
	}

	// Get disclosure level from grant scope
	disclosureLevel := "full"
	if grant.Scope.DisclosureLevel != "" {
		disclosureLevel = string(grant.Scope.DisclosureLevel)
	}

	response := ResolveAddressResponse{
		RealAddress:     realAddress,
		DisclosureLevel: disclosureLevel,
		GrantID:         grantID,
	}

	// Include pseudonym for pseudonymous disclosures
	if disclosureLevel == "pseudonymous" {
		response.Pseudonym = explorer.GeneratePseudonym(realAddress)
	}

	c.JSON(http.StatusOK, response)
}

// calculateAddressVisibility determines the visibility of a target address for a viewer (wallet-based)
// Deprecated: Use calculateAddressVisibilityWithDID instead for new code.
func (s *Server) calculateAddressVisibility(ctx context.Context, viewerWallet, targetAddress string) AddressVisibility {
	return s.calculateAddressVisibilityWithDID(ctx, viewerWallet, "", targetAddress)
}

// calculateAddressVisibilityWithDID determines the visibility of a target address for a viewer.
// If did is provided, it is used directly (skips wallet->DID lookup).
// If only wallet is provided, the DID is looked up from the wallet address.
func (s *Server) calculateAddressVisibilityWithDID(ctx context.Context, viewerWallet, did, targetAddress string) AddressVisibility {
	result := AddressVisibility{
		Address: targetAddress,
		Visible: false,
		Level:   VisibilityHidden,
		Reason:  ReasonNoAccess,
	}

	var viewerDID string
	var err error

	// 1. Determine viewer DID - use provided DID or look up from wallet
	if did != "" {
		viewerDID = did
	} else if viewerWallet != "" {
		viewerDID, err = s.db.GetDIDByEthAddress(ctx, viewerWallet)
		if err != nil {
			// Error looking up DID - treat as anonymous
			return result
		}
	}

	// 2. Is targetAddress owned by viewer?
	if viewerDID != "" {
		ownAddresses, err := s.db.GetEthAddressesByDID(ctx, viewerDID)
		if err == nil {
			for _, link := range ownAddresses {
				if strings.EqualFold(link.EthAddress, targetAddress) {
					return AddressVisibility{
						Address: targetAddress,
						Visible: true,
						Level:   VisibilityFull,
						Reason:  ReasonOwnAddress,
					}
				}
			}
		}
	}

	// 3. Find owner of targetAddress
	ownerDID, err := s.db.GetDIDByEthAddress(ctx, targetAddress)
	if err != nil {
		// Error looking up owner
		return result
	}

	if ownerDID == "" {
		// No user wallet owner — check if this is an org-owned contract
		contract, err := s.db.GetContractByAddressGlobal(ctx, targetAddress)
		if err == nil && contract != nil {
			// It's an org-owned contract. Check if viewer has group membership.
			if viewerDID != "" {
				hasAccess, err := s.db.ViewerHasContractAccess(ctx, viewerDID, contract.ID)
				if err == nil && hasAccess {
					return AddressVisibility{
						Address: targetAddress,
						Visible: true,
						Level:   VisibilityFull,
						Reason:  ReasonRBACGroupMember,
					}
				}
			}
			// No access to this org contract
			return result // result defaults to VisibilityHidden, ReasonNoAccess
		}
		// Not an org contract — truly public address
		return AddressVisibility{
			Address: targetAddress,
			Visible: true,
			Level:   VisibilityFull,
			Reason:  ReasonPublicAddress,
		}
	}

	// 4. Check disclosure grant (if viewer has a DID)
	if viewerDID != "" {
		grantWithRequest, err := s.db.GetActiveGrantByRequesterDID(ctx, viewerDID, ownerDID)
		if err == nil && grantWithRequest != nil {
			grant := grantWithRequest.Grant

			// Map disclosure level from grant scope to visibility level
			level := VisibilityFull
			var pseudonym *string
			switch grant.Scope.DisclosureLevel {
			case disclosure.DisclosurePseudonymous:
				level = VisibilityPseudonymous
				// Generate a consistent pseudonym based on the address
				p := explorer.GeneratePseudonym(targetAddress)
				pseudonym = &p
			case disclosure.DisclosureRedacted:
				level = VisibilityRedacted
			case disclosure.DisclosureFull, "":
				level = VisibilityFull
			default:
				// SECURITY: Fail-safe - treat unknown disclosure levels as redacted
				level = VisibilityRedacted
			}

			return AddressVisibility{
				Address:   targetAddress,
				Visible:   true,
				Level:     level,
				Reason:    ReasonDisclosureGrant,
				Pseudonym: pseudonym,
				GrantID:   &grant.ID,
				ExpiresAt: &grant.ExpiresAt,
			}
		}
	}

	// 5. No access
	return result
}

func (s *Server) getExplorerChainID(c *gin.Context) {
	// Approximation: return 1 or get from proxy if needed
	c.JSON(http.StatusOK, gin.H{"chain_id": 1})
}

func (s *Server) getExplorerStats(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	stats, err := s.explorerStore.GetChainStats(c.Request.Context())
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) getExplorerBlocks(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}
	blocks, err := s.explorerStore.GetBlocks(c.Request.Context(), limit, beforeBlock)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, blocks)
}

func (s *Server) getExplorerBlock(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	block, err := s.explorerStore.GetBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if block == nil {
		respondNotFound(c, "block not found")
		return
	}
	c.JSON(http.StatusOK, block)
}

func (s *Server) getExplorerBlockByHash(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	block, err := s.explorerStore.GetBlockByHash(c.Request.Context(), hash)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if block == nil {
		respondNotFound(c, "block not found")
		return
	}
	c.JSON(http.StatusOK, block)
}

// getViewerDIDFromRequest extracts the viewer's DID.
// Priority: (1) validated JWT claims set by OptionalJWTAuthMiddleware, (2) ?did= query param,
// (3) wallet->DID lookup via ?wallet= query param.
// JWT claims are preferred because they are cryptographically signed; query params are
// unsigned and accepted only for backward-compatibility when no JWT is present.
func (s *Server) getViewerDIDFromRequest(c *gin.Context) string {
	// 1. JWT claims (set by OptionalJWTAuthMiddleware)
	if subject, exists := c.Get("subject"); exists {
		if did, ok := subject.(string); ok && did != "" {
			return did
		}
	}
	// 2. Explicit DID query param
	if did := c.Query("did"); did != "" {
		return did
	}
	// 3. Wallet address lookup
	if wallet := c.Query("wallet"); wallet != "" {
		viewerDID, _ := s.db.GetDIDByEthAddress(c.Request.Context(), strings.ToLower(wallet))
		return viewerDID
	}
	return ""
}

func (s *Server) getExplorerTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}
	txs, err := s.explorerStore.GetTransactions(c.Request.Context(), limit, beforeBlock)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	redactedTxs, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, redactedTxs)
}

func (s *Server) getExplorerTransaction(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	tx, err := s.explorerStore.GetTransaction(c.Request.Context(), hash)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if tx == nil {
		respondNotFound(c, "transaction not found")
		return
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	redactedTxs, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), []explorer.Transaction{*tx}, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if len(redactedTxs) == 0 {
		// Transaction was completely hidden
		respondNotFound(c, "transaction not found")
		return
	}

	c.JSON(http.StatusOK, redactedTxs[0])
}

func (s *Server) getExplorerAddressStats(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := c.Param("address")

	// Pre-authorization check: Can they even see this address?
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "address not found") // Masking forbidden as not found to avoid info leaks
		return
	}

	stats, err := s.explorerStore.GetAddressStats(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (s *Server) getExplorerAddressTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := c.Param("address")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}

	// Pre-authorization check: Can they even see this address?
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "address not found") // Masking forbidden as not found
		return
	}

	txs, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), address, limit, beforeBlock)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

	viewerDID := s.getViewerDIDFromRequest(c)
	redactedTxs, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, redactedTxs)
}

func (s *Server) getExplorerSyncStatus(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	status, err := s.explorerStore.GetSyncStatus(c.Request.Context())
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, status)
}

func (s *Server) indexExplorerBlock(c *gin.Context) {
	// Proxy to indexer or return not implemented for now
	respondInternalError(c, "manual indexing through proxy not yet implemented")
}

// --- Block sub-endpoints ---

func (s *Server) getExplorerBlockTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	txs, err := s.explorerStore.GetTransactionsByBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if txs == nil {
		txs = []explorer.Transaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Transaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerBlockInternalTxs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := strconv.ParseUint(c.Param("number"), 10, 64)
	if err != nil {
		respondBadRequest(c, "invalid block number")
		return
	}
	itxs, err := s.explorerStore.GetInternalTransactionsByBlock(c.Request.Context(), num)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerLatestBlockNumber(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	num, err := s.explorerStore.GetLatestBlockNumber(c.Request.Context())
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"number": num})
}

// --- Transaction sub-endpoints ---

func (s *Server) getExplorerTransactionsPaginated(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	page := 1
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 25
	if ps := c.Query("pageSize"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	withCategories := c.Query("with_categories") == "true"

	var txs []explorer.Transaction
	var total int64
	var err error
	if withCategories {
		txs, total, err = s.explorerStore.GetTransactionsPaginatedWithCategories(c.Request.Context(), page, pageSize)
	} else {
		txs, total, err = s.explorerStore.GetTransactionsPaginated(c.Request.Context(), page, pageSize)
	}
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if txs == nil {
		txs = []explorer.Transaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Transaction{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

func (s *Server) getExplorerTransactionInternal(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	itxs, err := s.explorerStore.GetInternalTransactionsByTx(c.Request.Context(), hash)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	transfers, err := s.explorerStore.GetTransfersByTransaction(c.Request.Context(), hash)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	logs, err := s.explorerStore.GetLogsByTransaction(c.Request.Context(), hash)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransactionOPDeposit(c *gin.Context) {
	// This is not an OP Stack chain — always return 404
	respondNotFound(c, "OP deposit not found (not an OP Stack chain)")
}

// --- Address sub-endpoints ---

func (s *Server) getExplorerAddressBalance(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	// Forward eth_getBalance to the node via JSON-RPC
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getBalance",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)
	respBody, _, err := s.proxy.Forward(reqBody)
	if err != nil {
		respondInternalError(c, "failed to get balance: "+err.Error())
		return
	}

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		respondInternalError(c, "failed to parse balance response")
		return
	}

	c.JSON(http.StatusOK, rpcResp.Result)
}

func (s *Server) getExplorerAddressCode(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getCode",
		Params:  []interface{}{address, "latest"},
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)
	respBody, _, err := s.proxy.Forward(reqBody)
	if err != nil {
		respondInternalError(c, "failed to get code: "+err.Error())
		return
	}

	var rpcResp struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		respondInternalError(c, "failed to parse code response")
		return
	}

	// Return as raw bytes (hex-encoded string)
	codeBytes := []byte(rpcResp.Result)
	c.JSON(http.StatusOK, codeBytes)
}

func (s *Server) getExplorerAddressTokenBalances(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	balances, err := s.explorerStore.GetTokenBalances(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if balances == nil {
		balances = []explorer.Balance{}
	}

	// Filter out balances whose token contract is restricted for this viewer.
	// A private org token contract must not appear in balance lists for non-members.
	if len(balances) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		tokenAddrs := make([]string, len(balances))
		for i, b := range balances {
			tokenAddrs[i] = strings.ToLower(b.TokenAddress)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, tokenAddrs)
		if err != nil {
			respondInternalError(c, err.Error())
			return
		}
		filtered := balances[:0]
		for _, b := range balances {
			level := visMap[strings.ToLower(b.TokenAddress)]
			switch level {
			case explorer.VisibilityFull:
				filtered = append(filtered, b)
			case explorer.VisibilityPseudonymous:
				b.TokenAddress = explorer.GeneratePseudonym(b.TokenAddress)
				filtered = append(filtered, b)
			// VisibilityHidden, VisibilityRedacted: drop this balance entry
			}
		}
		balances = filtered
	}

	c.JSON(http.StatusOK, balances)
}

func (s *Server) getExplorerAddressTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}

	transfers, err := s.explorerStore.GetTransfersByAddress(c.Request.Context(), address, limit, beforeBlock)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerAddressInternal(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	itxs, total, err := s.explorerStore.GetInternalTransactionsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

func (s *Server) getExplorerAddressLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	logs, total, err := s.explorerStore.GetLogsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

func (s *Server) getExplorerAddressContract(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	contract, err := s.explorerStore.GetContract(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if contract == nil {
		respondNotFound(c, "contract not found")
		return
	}
	// Redact the creator address - it may belong to a private user
	if contract.Creator != "" {
		viewerDID := s.getViewerDIDFromRequest(c)
		redactedCreator, err := s.explorerRedactor.RedactAddress(c.Request.Context(), contract.Creator, viewerDID)
		if err == nil {
			contract.Creator = redactedCreator
		}
	}
	c.JSON(http.StatusOK, contract)
}

func (s *Server) getExplorerAddressIsContract(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), c.Query("did"), address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "address not found")
		return
	}

	isContract, err := s.explorerStore.IsContract(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"is_contract": isContract})
}

func (s *Server) updateExplorerAddressABI(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Require full visibility: only org members (or public contracts) may update ABI.
	// This prevents unauthorized writes to private org contracts.
	viewerDID := s.getViewerDIDFromRequest(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), c.Query("wallet"), viewerDID, address)
	if visibility.Level != VisibilityFull {
		respondNotFound(c, "address not found")
		return
	}

	var body json.RawMessage
	if err := c.ShouldBindJSON(&body); err != nil {
		respondBadRequest(c, "invalid request body: "+err.Error())
		return
	}

	if err := s.explorerStore.SetContractABI(c.Request.Context(), address, body); err != nil {
		respondInternalError(c, err.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "address": address})
}

// --- Logs ---

func (s *Server) getExplorerLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	var address, topic0 *string
	var fromBlock, toBlock *uint64

	if a := c.Query("address"); a != "" {
		lower := strings.ToLower(a)
		address = &lower
	}
	if t := c.Query("topic0"); t != "" {
		topic0 = &t
	}
	if fb := c.Query("from"); fb != "" {
		if v, err := strconv.ParseUint(fb, 10, 64); err == nil {
			fromBlock = &v
		}
	}
	if tb := c.Query("to"); tb != "" {
		if v, err := strconv.ParseUint(tb, 10, 64); err == nil {
			toBlock = &v
		}
	}

	limit := 100
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	logs, err := s.explorerStore.GetLogs(c.Request.Context(), address, topic0, fromBlock, toBlock, limit)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	c.JSON(http.StatusOK, redacted)
}

// --- Tokens ---

func (s *Server) getExplorerTokens(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	tokenType := c.Query("type")

	tokens, total, err := s.explorerStore.GetTokens(c.Request.Context(), limit, offset, tokenType)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if tokens == nil {
		tokens = []explorer.Token{}
	}
	c.JSON(http.StatusOK, gin.H{"data": tokens, "total": total})
}

func (s *Server) getExplorerToken(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))
	token, err := s.explorerStore.GetToken(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if token == nil {
		respondNotFound(c, "token not found")
		return
	}
	c.JSON(http.StatusOK, token)
}

func (s *Server) getExplorerTokenHolders(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	holders, total, err := s.explorerStore.GetTokenHolders(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if holders == nil {
		holders = []explorer.TokenHolder{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTokenHolders(c.Request.Context(), holders, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenHolder{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

func (s *Server) getExplorerTokenTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	transfers, total, err := s.explorerStore.GetTransfersByToken(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

// --- Transfers ---

func (s *Server) getExplorerAllTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	transfers, total, err := s.explorerStore.GetAllTransfers(c.Request.Context(), limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	viewerDID := s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": total})
}

// --- Accounts ---

func (s *Server) getExplorerAccounts(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	page := 1
	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 25
	if ps := c.Query("pageSize"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	accounts, total, err := s.explorerStore.GetAccountsPaginated(c.Request.Context(), page, pageSize)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if accounts == nil {
		accounts = []explorer.AddressStats{}
	}

	// Filter/mask accounts based on visibility so private org addresses don't leak.
	if len(accounts) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		addrs := make([]string, len(accounts))
		for i, a := range accounts {
			addrs[i] = strings.ToLower(a.Address)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, addrs)
		if err != nil {
			respondInternalError(c, err.Error())
			return
		}
		filtered := accounts[:0]
		for _, a := range accounts {
			level := visMap[strings.ToLower(a.Address)]
			switch level {
			case explorer.VisibilityFull:
				filtered = append(filtered, a)
			case explorer.VisibilityPseudonymous:
				a.Address = explorer.GeneratePseudonym(a.Address)
				filtered = append(filtered, a)
			// VisibilityHidden, VisibilityRedacted: drop this account
			}
		}
		total -= int64(len(accounts) - len(filtered))
		if total < 0 {
			total = 0
		}
		accounts = filtered
	}

	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": total})
}

// --- Search ---

func (s *Server) getExplorerSearchSuggestions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	q := strings.TrimSpace(c.Query("q"))
	if q == "" {
		c.JSON(http.StatusOK, []explorer.SearchSuggestion{})
		return
	}

	limit := 10
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 50 {
			limit = v
		}
	}

	suggestions, err := s.explorerStore.SearchSuggestions(c.Request.Context(), q, limit)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if suggestions == nil {
		suggestions = []explorer.SearchSuggestion{}
	}

	// Filter address-type suggestions based on visibility so private org contracts
	// cannot be discovered via search autocomplete.
	if len(suggestions) > 0 {
		var addrValues []string
		for _, sug := range suggestions {
			v := strings.ToLower(sug.Value)
			if len(v) == 42 && strings.HasPrefix(v, "0x") {
				addrValues = append(addrValues, v)
			}
		}
		if len(addrValues) > 0 {
			viewerDID := s.getViewerDIDFromRequest(c)
			visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, addrValues)
			if err != nil {
				respondInternalError(c, err.Error())
				return
			}
			filtered := suggestions[:0]
			for _, sug := range suggestions {
				v := strings.ToLower(sug.Value)
				if len(v) == 42 && strings.HasPrefix(v, "0x") {
					level := visMap[v]
					if level == explorer.VisibilityHidden || level == explorer.VisibilityRedacted {
						continue // drop hidden/restricted address suggestions
					}
					if level == explorer.VisibilityPseudonymous {
						pseudo := explorer.GeneratePseudonym(sug.Value)
						sug.Value = pseudo
						sug.Label = pseudo
					}
				}
				filtered = append(filtered, sug)
			}
			suggestions = filtered
		}
	}

	c.JSON(http.StatusOK, suggestions)
}

// --- Stats ---

func (s *Server) getExplorerTransactionHistory(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}

	interval := 60
	if i := c.Query("interval"); i != "" {
		if v, err := strconv.Atoi(i); err == nil && v > 0 {
			interval = v
		}
	}
	limit := 30
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}

	history, err := s.explorerStore.GetTransactionHistory(c.Request.Context(), interval, limit)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if history == nil {
		history = []explorer.TxHistoryPoint{}
	}
	c.JSON(http.StatusOK, history)
}

// --- Sync sub-endpoints ---

func (s *Server) getExplorerIndexerProgress(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	progress, err := s.explorerStore.GetIndexerProgress(c.Request.Context())
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if progress == nil {
		// Return zero-value progress
		c.JSON(http.StatusOK, explorer.IndexerProgress{})
		return
	}
	c.JSON(http.StatusOK, progress)
}

func (s *Server) getExplorerCatchupProgress(c *gin.Context) {
	// The proxy has no indexer of its own — return static "not running" response
	c.JSON(http.StatusOK, gin.H{
		"processed":       0,
		"total":           0,
		"percentComplete": 0,
		"isRunning":       false,
	})
}
