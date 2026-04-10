package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

// Type aliases for explorer visibility types — the canonical definitions live in
// the explorer package. API handlers and the RedactionEngine share the same types.
type VisibilityLevel = explorer.VisibilityLevel
type VisibilityReason = explorer.VisibilityReason
type AddressVisibility = explorer.AddressVisibility

// Re-export visibility constants so existing handler/test code compiles unchanged.
const (
	VisibilityFull         = explorer.VisibilityFull
	VisibilityPseudonymous = explorer.VisibilityPseudonymous
	VisibilityRedacted     = explorer.VisibilityRedacted
	VisibilityHidden       = explorer.VisibilityHidden

	ReasonOwnAddress      = explorer.ReasonOwnAddress
	ReasonDisclosureGrant = explorer.ReasonDisclosureGrant
	ReasonPublicAddress   = explorer.ReasonPublicAddress
	ReasonNoAccess        = explorer.ReasonNoAccess
	ReasonRBACGroupMember = explorer.ReasonRBACGroupMember
)

// ResolveAddressResponse is returned when resolving an address_id.
// SECURITY: RealAddress is only populated for "full" disclosure level.
type ResolveAddressResponse struct {
	RealAddress     *string  `json:"real_address,omitempty"`
	DisclosureLevel string   `json:"disclosure_level"`
	GrantID         string   `json:"grant_id"`
	Pseudonym       string   `json:"pseudonym,omitempty"` // For pseudonymous, the display name to use
	ScopeMethods    []string `json:"scope_methods,omitempty"` // Methods from grant scope (e.g. "transaction_history", "activity_logs")
}

// GrantTransactionsResponse is the response for GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
type GrantTransactionsResponse struct {
	Transactions    []GrantTransaction `json:"transactions"`
	DisclosureLevel string             `json:"disclosure_level"`
	AddressLabels   map[string]string  `json:"address_labels"`
	HasMore         bool               `json:"has_more"`
}

// GrantTransaction represents a transaction in the context of a disclosure grant.
// For pseudonymous grants, addresses are replaced with pseudonyms and financial data is hidden.
type GrantTransaction struct {
	TxHash         *string `json:"tx_hash,omitempty"` // only for full disclosure
	BlockNumber    uint64  `json:"block_number"`
	BlockTimestamp uint64  `json:"block_timestamp,omitempty"`
	Direction      string  `json:"direction"` // "in", "out", "self"
	From           string  `json:"from"`
	To             string  `json:"to,omitempty"`
	Value          string  `json:"value"`
	GasUsed        uint64  `json:"gas_used"`
	Status         int     `json:"status"`
}

// registerExplorerRoutes registers the explorer API endpoints
// These endpoints are designed to be called by the explorer backend (internal).
// Network boundary: localhost-only. JWT: optional — if present it is validated and the
// viewer DID is extracted from it; if absent the request is treated as anonymous.
//
// Security measures:
// - G15: explorerLogRedactionMiddleware strips Ethereum addresses from logged request paths.
func (s *Server) registerExplorerRoutes(router *gin.Engine) {
	explorer := router.Group("/api/v1/explorer")
	explorer.Use(s.localhostOnlyMiddleware())
	explorer.Use(auth.OptionalJWTAuthMiddleware(s.jwtService, s.db))
	// G15: Redact Ethereum addresses from access log paths
	explorer.Use(explorerLogRedactionMiddleware())
	{
		explorer.GET("/viewable-addresses", s.getViewableAddresses)

		// Resolve address_id to real address (for explorer backend internal use)
		explorer.GET("/grant/:grant_id/resolve/:address_id", s.resolveAddressID)
		// Grant-scoped transactions for a disclosed address
		explorer.GET("/grant/:grant_id/:address_id/transactions", s.getGrantTransactions)
		// Grant-scoped activity logs (user-facing, JWT required)
		explorer.GET("/grant/:grant_id/activity", s.getGrantActivityLogs)

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

	// SECURITY: Resolve viewer DID from JWT (validated) or wallet (DB-verified).
	// DID is never accepted directly from query params.
	viewerDID := s.getViewerDIDFromRequest(c)

	if wallet == "" && viewerDID == "" {
		respondBadRequest(c, "either wallet or JWT authentication is required")
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

	var err error

	// If no DID from JWT, look up from wallet
	if viewerDID == "" && wallet != "" {
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
		DisclosureLevel: disclosureLevel,
		GrantID:         grantID,
		ScopeMethods:    grant.Scope.Methods,
	}

	// SECURITY: Only include real address for full disclosure.
	// The explorer backend is an untrusted client and must not see real addresses
	// for pseudonymous or redacted grants.
	if disclosureLevel == "full" {
		response.RealAddress = &realAddress
	}

	// Include pseudonym for pseudonymous disclosures
	if disclosureLevel == "pseudonymous" {
		response.Pseudonym = explorer.GeneratePseudonym(realAddress)
	}

	c.JSON(http.StatusOK, response)
}

// generateExternalPseudonym creates a deterministic pseudonym for an external address
// in the context of a specific grant. The pseudonym is derived from the address and grant ID
// so it is consistent within a grant but cannot be correlated across grants.
func generateExternalPseudonym(address, grantID string) string {
	h := sha256.New()
	h.Write([]byte(strings.ToLower(address)))
	h.Write([]byte(":"))
	h.Write([]byte(grantID))
	sum := h.Sum(nil)
	return fmt.Sprintf("External-%X", sum[:2])
}

// getGrantTransactions returns transactions for a disclosed address, pseudonymized
// according to the grant's disclosure level.
// GET /api/v1/explorer/grant/:grant_id/:address_id/transactions
// SECURITY: This endpoint never exposes real addresses for non-full grants.
// The explorer backend receives pre-pseudonymized data and cannot reverse it.
func (s *Server) getGrantTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondInternalError(c, "explorer store not configured")
		return
	}

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

	// Get disclosure level
	disclosureLevel := "full"
	if grant.Scope.DisclosureLevel != "" {
		disclosureLevel = string(grant.Scope.DisclosureLevel)
	}

	// For redacted grants, return empty transactions
	if disclosureLevel == "redacted" {
		c.JSON(http.StatusOK, GrantTransactionsResponse{
			Transactions:    []GrantTransaction{},
			DisclosureLevel: disclosureLevel,
			AddressLabels:   map[string]string{},
			HasMore:         false,
		})
		return
	}

	// Get target user and their addresses
	request := grantWithRequest.Request
	targetUser, err := s.db.GetUser(c.Request.Context(), request.TargetUserID)
	if err != nil || targetUser == nil {
		respondInternalError(c, "failed to get target user")
		return
	}
	targetDID := targetUser.ExternalID

	addresses, err := s.db.GetEthAddressesByDID(c.Request.Context(), targetDID)
	if err != nil {
		respondInternalError(c, "failed to get addresses")
		return
	}

	// Find the real address by matching address_id
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

	// Parse pagination params
	limit := 25
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	var beforeBlock *uint64
	if beforeStr := c.Query("before"); beforeStr != "" {
		if parsed, err := strconv.ParseUint(beforeStr, 10, 64); err == nil {
			beforeBlock = &parsed
		}
	}

	// Fetch one extra to detect has_more
	txs, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), realAddress, limit+1, beforeBlock)
	if err != nil {
		respondInternalError(c, "failed to get transactions")
		return
	}

	hasMore := len(txs) > limit
	if hasMore {
		txs = txs[:limit]
	}

	realAddrLower := strings.ToLower(realAddress)
	labels := make(map[string]string)

	// Resolve viewer's own addresses so we can label them "mine" on the grant page
	viewerAddrs := make(map[string]bool)
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID != "" {
		linked, err := s.db.GetLinkedAddresses(c.Request.Context(), viewerDID)
		if err == nil {
			for _, a := range linked {
				viewerAddrs[strings.ToLower(a)] = true
			}
		}
	}

	var grantTxs []GrantTransaction
	for _, tx := range txs {
		gt := GrantTransaction{
			BlockNumber:    tx.BlockNumber,
			BlockTimestamp: tx.BlockTimestamp,
			GasUsed:        tx.GasUsed,
			Status:         tx.Status,
		}

		fromLower := strings.ToLower(tx.From)
		var toLower string
		if tx.HasRecipient() {
			toLower = strings.ToLower(*tx.To)
		}

		// Determine direction
		fromIsDisclosed := fromLower == realAddrLower
		toIsDisclosed := toLower == realAddrLower
		if fromIsDisclosed && toIsDisclosed {
			gt.Direction = "self"
		} else if fromIsDisclosed {
			gt.Direction = "out"
		} else {
			gt.Direction = "in"
		}

		switch disclosureLevel {
		case "full":
			hash := tx.Hash
			gt.TxHash = &hash
			gt.From = tx.From
			if tx.HasRecipient() {
				gt.To = *tx.To
			}
			gt.Value = string(tx.Value)

		case "pseudonymous":
			disclosedPseudonym := explorer.GeneratePseudonym(realAddress)
			labels[disclosedPseudonym] = "disclosed"

			if fromIsDisclosed {
				gt.From = disclosedPseudonym
			} else if viewerAddrs[fromLower] {
				gt.From = "Mine"
				labels["Mine"] = "mine"
			} else {
				ext := generateExternalPseudonym(tx.From, grantID)
				gt.From = ext
				labels[ext] = "external"
			}

			if tx.HasRecipient() {
				if toIsDisclosed {
					gt.To = disclosedPseudonym
				} else if viewerAddrs[toLower] {
					gt.To = "Mine"
					labels["Mine"] = "mine"
				} else {
					ext := generateExternalPseudonym(*tx.To, grantID)
					gt.To = ext
					labels[ext] = "external"
				}
			}

			gt.Value = "hidden"
			// tx hash intentionally omitted for pseudonymous
		}

		grantTxs = append(grantTxs, gt)
	}

	// Ensure non-nil slices in JSON
	if grantTxs == nil {
		grantTxs = []GrantTransaction{}
	}

	c.JSON(http.StatusOK, GrantTransactionsResponse{
		Transactions:    grantTxs,
		DisclosureLevel: disclosureLevel,
		AddressLabels:   labels,
		HasMore:         hasMore,
	})
}

// GrantActivityLogsResponse is the response for GET /api/v1/explorer/grant/:grant_id/activity
type GrantActivityLogsResponse struct {
	Logs   []GrantActivityLogEntry `json:"logs"`
	Total  int                     `json:"total"`
	Limit  int                     `json:"limit"`
	Offset int                     `json:"offset"`
}

// GrantActivityLogEntry is a stripped-down log entry safe for grant holders.
// SECURITY: Does NOT include request_params, ip_address, correlation_id, or entry_hash.
type GrantActivityLogEntry struct {
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Timestamp  string `json:"timestamp"` // RFC 3339
}

// getGrantActivityLogs returns activity logs scoped to a disclosure grant.
// GET /api/v1/explorer/grant/:grant_id/activity
//
// SECURITY:
//   - JWT required -- anonymous requests are rejected.
//   - Grant holder verification: the viewer's DID must match the grant's requester_did.
//   - Scope check: grant must include "activity_logs" or "full_disclosure".
//   - Time-bounded: only logs within the grant's validity period are returned.
//   - Stripped response: only method, status_code, and timestamp are returned.
//   - Uniform 404 for "not found" and "not your grant" to prevent enumeration.
func (s *Server) getGrantActivityLogs(c *gin.Context) {
	grantID := c.Param("grant_id")
	if grantID == "" {
		respondBadRequest(c, "grant_id is required")
		return
	}

	// 1. JWT required -- reject anonymous
	viewerDID := s.getViewerDIDFromRequest(c)
	if viewerDID == "" {
		respondUnauthorized(c, "authentication required")
		return
	}

	// 2. Look up the grant with its request
	grantWithRequest, err := s.db.GetDisclosureGrantWithRequest(c.Request.Context(), grantID)
	if err != nil || grantWithRequest == nil {
		// Uniform 404 prevents enumeration
		respondNotFound(c, "grant not found")
		return
	}

	grant := grantWithRequest.Grant
	request := grantWithRequest.Request

	// 3. Grant holder verification: viewer DID must match requester_did
	if request.RequesterDID != viewerDID {
		// Same 404 -- do not reveal that the grant exists
		respondNotFound(c, "grant not found")
		return
	}

	// 4. Check grant is still active (not expired, not revoked)
	if grant.RevokedAt != nil || grant.ExpiresAt.Before(time.Now()) {
		respondNotFound(c, "grant not found")
		return
	}

	// 5. Scope check: must include "activity_logs" or "full_disclosure"
	hasScope := false
	for _, m := range grant.Scope.Methods {
		if m == "activity_logs" || m == "full_disclosure" {
			hasScope = true
			break
		}
	}
	if !hasScope {
		respondForbidden(c, "grant scope does not include activity_logs")
		return
	}

	// 6. Parse pagination
	limit := 25
	if limitStr := c.Query("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	offset := 0
	if offsetStr := c.Query("offset"); offsetStr != "" {
		if parsed, err := strconv.Atoi(offsetStr); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// 7. Query activity logs scoped to grant time bounds
	logs, total, err := s.db.GetActivityLogsForGrant(c.Request.Context(), grantID, limit, offset)
	if err != nil {
		respondInternalError(c, "failed to get activity logs")
		return
	}

	// 8. Build stripped response
	entries := make([]GrantActivityLogEntry, 0, len(logs))
	for _, log := range logs {
		entries = append(entries, GrantActivityLogEntry{
			Method:     log.Method,
			StatusCode: log.StatusCode,
			Timestamp:  log.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, GrantActivityLogsResponse{
		Logs:   entries,
		Total:  total,
		Limit:  limit,
		Offset: offset,
	})
}

// getViewerIdentity extracts the viewer's DID and wallet from a gin context.
// DID is extracted ONLY from the validated JWT (set by OptionalJWTAuthMiddleware).
// Wallet comes from the "wallet" query parameter.
// SECURITY: DID is never accepted from query parameters to prevent identity spoofing.
func getViewerIdentity(c *gin.Context) (wallet, did string) {
	wallet = c.Query("wallet")
	if subject, ok := c.Get("subject"); ok {
		if s, ok := subject.(string); ok && s != "" {
			did = s
			return
		}
	}
	return
}

// resolveViewerDID resolves the viewer's DID from an explicit DID or wallet address.
// Returns empty string if neither is provided or the wallet has no linked DID.
func (s *Server) resolveViewerDID(ctx context.Context, wallet, did string) string {
	if did != "" {
		return did
	}
	if wallet != "" {
		viewerDID, err := s.db.GetDIDByEthAddress(ctx, wallet)
		if err != nil {
			return ""
		}
		return viewerDID
	}
	return ""
}

// calculateAddressVisibility determines the visibility of a target address for a wallet-based viewer.
// Delegates to GetBatchVisibilityDetailed so the visibility decision is made by the same
// code path that the RedactionEngine uses (via GetBatchVisibility).
func (s *Server) calculateAddressVisibility(ctx context.Context, viewerWallet, targetAddress string) AddressVisibility {
	return s.calculateAddressVisibilityWithDID(ctx, viewerWallet, "", targetAddress)
}

// calculateAddressVisibilityWithDID determines the visibility of a single address.
// It delegates to GetBatchVisibilityDetailed (single-element batch) so that the
// visibility level decision matches the RedactionEngine's GetBatchVisibility.

// maskAsPublic returns a visibility response identical to a genuinely public
// (unregistered) address. This eliminates the 1-bit oracle: an attacker cannot
// distinguish "registered but hidden" from "not registered at all."
func maskAsPublic(address string) AddressVisibility {
	return AddressVisibility{
		Address: strings.ToLower(address),
		Visible: true,
		Level:   VisibilityFull,
		Reason:  ReasonPublicAddress,
	}
}

func (s *Server) calculateAddressVisibilityWithDID(ctx context.Context, viewerWallet, did, targetAddress string) AddressVisibility {
	viewerDID := s.resolveViewerDID(ctx, viewerWallet, did)
	results, err := s.db.GetBatchVisibilityDetailed(ctx, viewerDID, []string{targetAddress})
	if err != nil {
		return AddressVisibility{
			Address: strings.ToLower(targetAddress),
			Visible: false,
			Level:   VisibilityHidden,
			Reason:  ReasonNoAccess,
		}
	}
	if vis, ok := results[strings.ToLower(targetAddress)]; ok {
		return vis
	}
	return AddressVisibility{
		Address: strings.ToLower(targetAddress),
		Visible: false,
		Level:   VisibilityHidden,
		Reason:  ReasonNoAccess,
	}
}

// viewerHasFullDisclosureGrant checks if the authenticated viewer has an active
// full-disclosure grant on the target address. This is used by address-specific
// endpoints to allow full disclosure recipients to view address pages.
//
// NOTE: GetBatchVisibility now includes disclosure grants (G17 reverted), so this
// check is a secondary fallback for address-specific endpoints where the target
// address is already known from the URL path.
func (s *Server) viewerHasFullDisclosureGrant(ctx context.Context, viewerDID, targetAddress string) bool {
	if viewerDID == "" || targetAddress == "" {
		return false
	}
	has, err := s.db.ViewerHasFullDisclosureGrant(ctx, viewerDID, targetAddress)
	if err != nil {
		return false
	}
	return has
}

// addressVisibleOrFullGrant returns true if the address is visible via standard
// RBAC/ownership checks OR the viewer has a full disclosure grant on it.
// Used by address-specific endpoints (not transaction lists) to upgrade visibility.
func (s *Server) addressVisibleOrFullGrant(ctx context.Context, viewerWallet, viewerDID, address string) bool {
	visibility := s.calculateAddressVisibilityWithDID(ctx, viewerWallet, viewerDID, address)
	if visibility.Level != VisibilityHidden && visibility.Level != VisibilityRedacted {
		return true
	}
	// Fallback: check disclosure grants for the specific address the viewer
	// navigated to. GetBatchVisibility should already handle this, but this
	// ensures coverage for edge cases.
	resolvedDID := s.resolveViewerDID(ctx, viewerWallet, viewerDID)
	return s.viewerHasFullDisclosureGrant(ctx, resolvedDID, address)
}

// addDisclosureAddressToFilter returns a copy of the visibility filter with the
// disclosure address added to the visible set. This ensures that transaction
// counts and filtered queries include transactions involving the disclosed address.
func (s *Server) addDisclosureAddressToFilter(filter *explorer.VisibilityFilter, address string) *explorer.VisibilityFilter {
	if filter == nil {
		return &explorer.VisibilityFilter{
			AllPrivate:       true,
			VisibleAddresses: []string{address},
		}
	}
	// Check if already present
	for _, addr := range filter.VisibleAddresses {
		if addr == address {
			return filter
		}
	}
	// Copy to avoid mutating the original
	newFilter := &explorer.VisibilityFilter{
		AllPrivate:       filter.AllPrivate,
		VisibleAddresses: make([]string, len(filter.VisibleAddresses)+1),
	}
	copy(newFilter.VisibleAddresses, filter.VisibleAddresses)
	newFilter.VisibleAddresses[len(filter.VisibleAddresses)] = address
	return newFilter
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
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	stats, err := s.explorerStore.GetChainStatsFiltered(c.Request.Context(), filter)
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

	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	blocks, err := s.explorerStore.GetBlocksFiltered(c.Request.Context(), limit, beforeBlock, filter)
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
	// Adjust TransactionCount to reflect only visible transactions
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	if filter != nil {
		filteredCount, err := s.explorerStore.GetBlockTransactionCountFiltered(c.Request.Context(), num, filter)
		if err == nil {
			block.TransactionCount = filteredCount
		}
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
	// Adjust TransactionCount to reflect only visible transactions
	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	if filter != nil {
		filteredCount, err := s.explorerStore.GetBlockTransactionCountFiltered(c.Request.Context(), block.Number, filter)
		if err == nil {
			block.TransactionCount = filteredCount
		}
	}
	c.JSON(http.StatusOK, block)
}

// getViewerDIDFromRequest extracts the viewer's DID.
// Priority: (1) validated JWT claims set by OptionalJWTAuthMiddleware,
// (2) wallet->DID lookup via ?wallet= query param (verified via DB).
// SECURITY: DID is never accepted directly from query parameters to prevent
// identity spoofing. The ?wallet= param is safe because the DB lookup verifies
// the wallet is actually linked to a DID.
func (s *Server) getViewerDIDFromRequest(c *gin.Context) string {
	// 1. JWT claims (set by OptionalJWTAuthMiddleware)
	if subject, exists := c.Get("subject"); exists {
		if did, ok := subject.(string); ok && did != "" {
			return did
		}
	}
	// 2. Wallet address lookup (DB-verified)
	if wallet := c.Query("wallet"); wallet != "" {
		viewerDID, _ := s.db.GetDIDByEthAddress(c.Request.Context(), strings.ToLower(wallet))
		return viewerDID
	}
	return ""
}

// buildVisibilityFilter resolves which addresses should be excluded from
// transaction queries at the SQL level. Only org-registered addresses and
// user EOAs can be hidden — unregistered addresses default to VisibilityFull (public).
func (s *Server) buildVisibilityFilter(ctx context.Context, viewerDID string) *explorer.VisibilityFilter {
	// All contracts are private by default — use allowlist mode.
	// Only addresses the viewer has VisibilityFull on are shown.

	// 1. Get all registered org contracts
	orgAddrs, err := s.db.GetAllRegisteredAddresses(ctx)
	if err != nil {
		orgAddrs = []string{}
	}

	// 2. Get all linked user EOAs
	userAddrs, err := s.db.GetAllLinkedEOAAddresses(ctx)
	if err != nil {
		userAddrs = []string{}
	}

	// Combine to get all known addresses
	allAddrs := append(orgAddrs, userAddrs...)

	// Even with no known addresses, we still need AllPrivate=true to hide
	// everything by default. With an empty visible list, no txs are shown.
	filter := &explorer.VisibilityFilter{
		AllPrivate: true,
	}

	if len(allAddrs) == 0 {
		return filter
	}

	visMap, err := s.db.GetBatchVisibility(ctx, viewerDID, allAddrs)
	if err != nil {
		return filter
	}

	var visible []string
	for addr, level := range visMap {
		if level == explorer.VisibilityFull {
			visible = append(visible, addr)
		}
	}
	filter.VisibleAddresses = visible

	// Add visibleTo tx hashes: txs shared with the viewer via the visibleTo param
	// should appear in regular explorer views.
	if viewerDID != "" {
		visibleTxHashes, err := s.db.GetVisibleTxHashesForDID(ctx, viewerDID)
		if err == nil && len(visibleTxHashes) > 0 {
			filter.VisibleTxHashes = visibleTxHashes
		}
	}

	return filter
}

func (s *Server) getExplorerTransactions(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	var beforeBlock *uint64
	if b := c.Query("before"); b != "" {
		if val, err := strconv.ParseUint(b, 10, 64); err == nil {
			beforeBlock = &val
		}
	}
	withCategories := c.Query("with_categories") == "true"
	viewerDID := s.getViewerDIDFromRequest(c)

	// Build SQL-level visibility filter to exclude transactions where both
	// participants (or the deployer for contract creations) are hidden.
	// This replaces the previous fetch-redact loop with a single query.
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	var txs []explorer.Transaction
	var err error
	if withCategories {
		txs, err = s.explorerStore.GetTransactionsWithCategoriesFiltered(c.Request.Context(), limit, beforeBlock, filter)
	} else {
		txs, err = s.explorerStore.GetTransactionsFiltered(c.Request.Context(), limit, beforeBlock, filter)
	}
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

	// Field-level redaction still needed (replacing addresses with [PRIVATE],
	// stripping values, etc.) — the SQL filter only drops entire rows.
	redacted, err := s.explorerRedactor.RedactTransactions(c.Request.Context(), txs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}

	c.JSON(http.StatusOK, redacted)
}

func (s *Server) getExplorerTransaction(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	hash := c.Param("hash")
	withCategories := c.Query("with_categories") == "true"
	var tx *explorer.Transaction
	var err error
	if withCategories {
		tx, err = s.explorerStore.GetTransactionWithCategories(c.Request.Context(), hash)
	} else {
		tx, err = s.explorerStore.GetTransaction(c.Request.Context(), hash)
	}
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

	// Pre-authorization check: Can they see this address via RBAC or full disclosure grant?
	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
		respondNotFound(c, "address not found") // Masking forbidden as not found to avoid info leaks
		return
	}

	stats, err := s.explorerStore.GetAddressStats(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

	// G22: Always compute live filtered tx count from the transactions table
	// instead of using the pre-computed address_stats.tx_count, which may be
	// stale and does not respect visibility filtering. Same class of fix as
	// block transaction count (RD-758).
	resolvedDID := s.resolveViewerDID(c.Request.Context(), viewerWallet, viewerDID)
	filter := s.buildVisibilityFilter(c.Request.Context(), resolvedDID)

	// If the viewer can see this address via disclosure grant, ensure the
	// target address is in the visibility filter's allowlist so the filtered
	// tx count includes transactions involving this address.
	normalizedAddr := strings.ToLower(address)
	if s.viewerHasFullDisclosureGrant(c.Request.Context(), resolvedDID, normalizedAddr) {
		filter = s.addDisclosureAddressToFilter(filter, normalizedAddr)
	}

	filteredCount, err := s.explorerStore.GetAddressTransactionCountFiltered(c.Request.Context(), address, filter)
	if err == nil {
		stats.TxCount = filteredCount
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

	// Pre-authorization check: Can they see this address via RBAC or full disclosure grant?
	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
		respondNotFound(c, "address not found") // Masking forbidden as not found
		return
	}

	txs, err := s.explorerStore.GetTransactionsByAddress(c.Request.Context(), address, limit, beforeBlock)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}

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
	viewerDID := s.getViewerDIDFromRequest(c)

	// Build SQL-level visibility filter
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)

	var txs []explorer.Transaction
	var total int64
	var err error
	if withCategories {
		txs, total, err = s.explorerStore.GetTransactionsPaginatedWithCategoriesFiltered(c.Request.Context(), page, pageSize, filter)
	} else {
		txs, total, err = s.explorerStore.GetTransactionsPaginatedFiltered(c.Request.Context(), page, pageSize, filter)
	}
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if txs == nil {
		txs = []explorer.Transaction{}
	}

	// Field-level redaction still needed for address masking and value stripping.
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

	// Fetch parent tx to get from/to for participant override.
	// If the viewer is the sender/receiver, they should see the logs.
	var participantAddrs []string
	if parentTx, err := s.explorerStore.GetTransaction(c.Request.Context(), hash); err == nil && parentTx != nil {
		participantAddrs = append(participantAddrs, parentTx.From)
		if parentTx.To != nil {
			participantAddrs = append(participantAddrs, *parentTx.To)
		}
	}

	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID, participantAddrs...)
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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
	viewerDID = s.getViewerDIDFromRequest(c)
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	itxs, _, err := s.explorerStore.GetInternalTransactionsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if itxs == nil {
		itxs = []explorer.InternalTransaction{}
	}
	viewerDID = s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactInternalTransactions(c.Request.Context(), itxs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.InternalTransaction{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerAddressLogs(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
		respondNotFound(c, "address not found")
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "25"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	logs, _, err := s.explorerStore.GetLogsByAddress(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if logs == nil {
		logs = []explorer.Log{}
	}
	viewerDID = s.getViewerDIDFromRequest(c)
	redacted, err := s.explorerRedactor.RedactLogs(c.Request.Context(), logs, viewerDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.Log{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerAddressContract(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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

	viewerWallet, viewerDID := getViewerIdentity(c)
	if !s.addressVisibleOrFullGrant(c.Request.Context(), viewerWallet, viewerDID, address) {
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

	tokens, _, err := s.explorerStore.GetTokens(c.Request.Context(), limit, offset, tokenType)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if tokens == nil {
		tokens = []explorer.Token{}
	}

	// Apply visibility filtering: collect token addresses, check visibility,
	// then drop Hidden tokens and redact Redacted/Pseudonymous tokens.
	if len(tokens) > 0 {
		viewerDID := s.getViewerDIDFromRequest(c)
		tokenAddrs := make([]string, len(tokens))
		for i, t := range tokens {
			tokenAddrs[i] = strings.ToLower(t.Address)
		}
		visMap, err := s.db.GetBatchVisibility(c.Request.Context(), viewerDID, tokenAddrs)
		if err != nil {
			respondInternalError(c, "visibility check failed: "+err.Error())
			return
		}

		var filtered []explorer.Token
		for _, t := range tokens {
			level := visMap[strings.ToLower(t.Address)]
			switch level {
			case explorer.VisibilityHidden:
				// Drop entirely — token must not appear in the list.
				continue
			case explorer.VisibilityRedacted:
				t.Address = "[PRIVATE]"
				t.Name = nil
				t.Symbol = ""
				t.TotalSupply = nil
				t.HolderCount = 0
				t.TransferCount = 0
				t.CreationTx = nil
				t.L1Address = nil
				t.USDPrice = nil
				t.IconURL = nil
			case explorer.VisibilityPseudonymous:
				pseudonym := explorer.GeneratePseudonym(t.Address)
				t.Address = pseudonym
				t.Name = nil
				t.Symbol = ""
				t.TotalSupply = nil
				t.HolderCount = 0
				t.TransferCount = 0
				t.CreationTx = nil
				t.L1Address = nil
				t.USDPrice = nil
				t.IconURL = nil
			// VisibilityFull or unrecognized: return as-is
			}
			filtered = append(filtered, t)
		}
		if filtered == nil {
			filtered = []explorer.Token{}
		}
		// Never expose raw DB total — return filtered count only.
		c.JSON(http.StatusOK, gin.H{"data": filtered, "total": len(filtered)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": tokens, "total": len(tokens)})
}

func (s *Server) getExplorerToken(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check: if the token address is Hidden, pretend it doesn't exist.
	viewerWallet, viewerDID := getViewerIdentity(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerWallet, viewerDID, address)
	if visibility.Level == VisibilityHidden {
		respondNotFound(c, "token not found")
		return
	}

	token, err := s.explorerStore.GetToken(c.Request.Context(), address)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if token == nil {
		respondNotFound(c, "token not found")
		return
	}

	// Redact sensitive fields for non-full visibility.
	if visibility.Level == VisibilityRedacted {
		token.Address = "[PRIVATE]"
		token.Name = nil
		token.Symbol = ""
		token.TotalSupply = nil
		token.HolderCount = 0
		token.TransferCount = 0
		token.CreationTx = nil
		token.L1Address = nil
		token.USDPrice = nil
		token.IconURL = nil
	} else if visibility.Level == VisibilityPseudonymous {
		pseudonym := explorer.GeneratePseudonym(token.Address)
		token.Address = pseudonym
		token.Name = nil
		token.Symbol = ""
		token.TotalSupply = nil
		token.HolderCount = 0
		token.TransferCount = 0
		token.CreationTx = nil
		token.L1Address = nil
		token.USDPrice = nil
		token.IconURL = nil
	}

	c.JSON(http.StatusOK, token)
}

func (s *Server) getExplorerTokenHolders(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerWallet, viewerDID := getViewerIdentity(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerWallet, viewerDID, address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "token not found")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	holders, _, err := s.explorerStore.GetTokenHolders(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if holders == nil {
		holders = []explorer.TokenHolder{}
	}
	resolvedDID := s.resolveViewerDID(c.Request.Context(), viewerWallet, viewerDID)
	redacted, err := s.explorerRedactor.RedactTokenHolders(c.Request.Context(), holders, resolvedDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenHolder{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
}

func (s *Server) getExplorerTokenTransfers(c *gin.Context) {
	if s.explorerStore == nil {
		respondServiceUnavailable(c, "explorer store not configured")
		return
	}
	address := strings.ToLower(c.Param("address"))

	// Visibility pre-check on the token address itself.
	viewerWallet, viewerDID := getViewerIdentity(c)
	visibility := s.calculateAddressVisibilityWithDID(c.Request.Context(), viewerWallet, viewerDID, address)
	if visibility.Level == VisibilityHidden || visibility.Level == VisibilityRedacted {
		respondNotFound(c, "token not found")
		return
	}

	limit := 25
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	transfers, _, err := s.explorerStore.GetTransfersByToken(c.Request.Context(), address, limit, offset)
	if err != nil {
		respondInternalError(c, err.Error())
		return
	}
	if transfers == nil {
		transfers = []explorer.TokenTransfer{}
	}
	resolvedDID := s.resolveViewerDID(c.Request.Context(), viewerWallet, viewerDID)
	redacted, err := s.explorerRedactor.RedactTransfers(c.Request.Context(), transfers, resolvedDID)
	if err != nil {
		respondInternalError(c, "redaction failed: "+err.Error())
		return
	}
	if redacted == nil {
		redacted = []explorer.TokenTransfer{}
	}
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
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

	transfers, _, err := s.explorerStore.GetAllTransfers(c.Request.Context(), limit, offset)
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
	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": redacted, "total": len(redacted)})
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

	accounts, _, err := s.explorerStore.GetAccountsPaginated(c.Request.Context(), page, pageSize)
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
		accounts = filtered
	}

	// Never expose raw DB total — it reveals how many rows were redacted (private data)
	c.JSON(http.StatusOK, gin.H{"data": accounts, "total": len(accounts)})
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

	viewerDID := s.getViewerDIDFromRequest(c)
	filter := s.buildVisibilityFilter(c.Request.Context(), viewerDID)
	history, err := s.explorerStore.GetTransactionHistoryFiltered(c.Request.Context(), interval, limit, filter)
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

