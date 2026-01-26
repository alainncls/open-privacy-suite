package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Explorer API Response Types

// OwnAddress represents an address owned by the viewer
type OwnAddress struct {
	Address string  `json:"address"`
	ENSName *string `json:"ens_name,omitempty"`
}

// DisclosedAddress represents an address disclosed to the viewer via a grant
type DisclosedAddress struct {
	Address         string     `json:"address"`
	OwnerDID        string     `json:"owner_did"`
	DisclosureLevel string     `json:"disclosure_level"`
	GrantID         string     `json:"grant_id"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	ENSName         *string    `json:"ens_name,omitempty"`
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

		// Determine disclosure level from scope
		disclosureLevel := "full" // Default to full for now
		// TODO: Parse scope JSON to determine actual disclosure level

		for _, addr := range targetAddresses {
			result = append(result, DisclosedAddress{
				Address:         addr.EthAddress,
				OwnerDID:        targetDID,
				DisclosureLevel: disclosureLevel,
				GrantID:         grantID,
				ExpiresAt:       &expiresAt,
				ENSName:         addr.ENSName,
			})
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

			// Determine disclosure level from grant scope
			level := VisibilityFull
			// TODO: Parse grant.Scope to determine actual level

			return AddressVisibility{
				Address:   targetAddress,
				Visible:   true,
				Level:     level,
				Reason:    ReasonDisclosureGrant,
				GrantID:   &grant.ID,
				ExpiresAt: &grant.ExpiresAt,
			}
		}
	}

	// 5. No access
	return result
}
