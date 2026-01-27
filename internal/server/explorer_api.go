package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"privacy-proxy/internal/disclosure"

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
	Address         string     `json:"address"`          // Pseudonym for pseudonymous, "[REDACTED]" for redacted, real for full
	AddressID       string     `json:"address_id"`       // Opaque identifier for routing (hash of real address)
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
	VisibilityFull        VisibilityLevel = "full"
	VisibilityPseudonymous VisibilityLevel = "pseudonymous"
	VisibilityRedacted    VisibilityLevel = "redacted"
	VisibilityHidden      VisibilityLevel = "hidden"
)

// VisibilityReason explains why an address has certain visibility
type VisibilityReason string

const (
	ReasonOwnAddress      VisibilityReason = "own_address"
	ReasonDisclosureGrant VisibilityReason = "disclosure_grant"
	ReasonPublicAddress   VisibilityReason = "public_address"
	ReasonNoAccess        VisibilityReason = "no_access"
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
// These endpoints are designed to be called by the explorer backend (internal, no auth)
func (s *Server) registerExplorerRoutes(router *gin.Engine) {
	explorer := router.Group("/api/v1/explorer")
	// No auth middleware - these are internal APIs called by explorer backend
	// Security is enforced by explorer backend which authenticates users
	explorer.Use(s.localhostOnlyMiddleware())
	{
		explorer.GET("/viewable-addresses", s.getViewableAddresses)
		explorer.GET("/check-address/:address", s.checkAddressVisibility)
		explorer.POST("/check-addresses", s.batchCheckAddresses)
		// Resolve address_id to real address (for explorer backend internal use)
		explorer.GET("/grant/:grant_id/resolve/:address_id", s.resolveAddressID)
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
			addressID := generateAddressID(addr.EthAddress, grantID)

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
				disclosed.Address = generatePseudonym(addr.EthAddress)
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
		computedID := generateAddressID(addr.EthAddress, grantID)
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
		response.Pseudonym = generatePseudonym(realAddress)
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
		// No owner - public address (contract, burn address, etc.)
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
				p := generatePseudonym(targetAddress)
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

// generateAddressID creates an opaque identifier for an address that can be used for routing.
// The ID is derived from the address and grant ID to be unique per grant.
// SECURITY: This allows routing without revealing the real address.
func generateAddressID(address string, grantID string) string {
	// Create a hash-based ID that's consistent but doesn't reveal the address
	// Using first 16 chars of hex-encoded hash for reasonable uniqueness
	data := strings.ToLower(address) + ":" + grantID
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // 16 hex chars
}

// generatePseudonym creates a consistent pseudonym for an address.
// The pseudonym is derived from the address hash to ensure the same address
// always produces the same pseudonym within a session.
func generatePseudonym(address string) string {
	// Use first 4 bytes of address (after 0x) to create a letter-based pseudonym
	// This creates pseudonyms like "Address-ABCD" where ABCD is derived from address
	if len(address) < 6 {
		return "Address-Unknown"
	}

	// Extract hex characters and convert to letters (A-P for 0-F)
	hex := strings.ToUpper(address[2:6])
	letters := make([]byte, 4)
	for i, c := range hex {
		if c >= '0' && c <= '9' {
			letters[i] = byte('A' + (c - '0'))
		} else if c >= 'A' && c <= 'F' {
			letters[i] = byte('K' + (c - 'A'))
		} else {
			letters[i] = 'X'
		}
	}
	return "Address-" + string(letters)
}
