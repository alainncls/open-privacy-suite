package server

import (
	"net/http"
	"privacy-proxy/internal/auth"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// LinkChallenge represents a pending ETH address linking challenge
type LinkChallenge struct {
	DID       string
	Nonce     string
	Address   string    // Optional: pre-specified address
	Message   string    // The message to be signed
	CreatedAt time.Time
}

// ChallengeStore stores pending link challenges with TTL
type ChallengeStore struct {
	challenges map[string]*LinkChallenge // key: nonce
	mu         sync.RWMutex
	ttl        time.Duration
}

// NewChallengeStore creates a new challenge store with cleanup
func NewChallengeStore(ttl time.Duration, cleanupInterval time.Duration) *ChallengeStore {
	cs := &ChallengeStore{
		challenges: make(map[string]*LinkChallenge),
		ttl:        ttl,
	}

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			cs.cleanup()
		}
	}()

	return cs
}

// CreateChallenge creates a new link challenge
func (cs *ChallengeStore) CreateChallenge(did string) (*LinkChallenge, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, err
	}

	message := auth.GenerateLinkMessage(did, nonce)

	challenge := &LinkChallenge{
		DID:       did,
		Nonce:     nonce,
		Message:   message,
		CreatedAt: time.Now(),
	}

	cs.mu.Lock()
	cs.challenges[nonce] = challenge
	cs.mu.Unlock()

	return challenge, nil
}

// GetChallenge retrieves and removes a challenge by nonce
func (cs *ChallengeStore) GetChallenge(nonce string) *LinkChallenge {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	challenge, exists := cs.challenges[nonce]
	if !exists {
		return nil
	}

	// Check TTL
	if time.Since(challenge.CreatedAt) > cs.ttl {
		delete(cs.challenges, nonce)
		return nil
	}

	// Remove after retrieval (one-time use)
	delete(cs.challenges, nonce)
	return challenge
}

// cleanup removes expired challenges
func (cs *ChallengeStore) cleanup() {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	for nonce, challenge := range cs.challenges {
		if now.Sub(challenge.CreatedAt) > cs.ttl {
			delete(cs.challenges, nonce)
		}
	}
}

// ChallengeRequest is the request body for creating a challenge
type ChallengeRequest struct {
	Address string `json:"address,omitempty"` // Optional: pre-specify the address to link
}

// ChallengeResponse is the response for a link challenge
type ChallengeResponse struct {
	Nonce   string `json:"nonce"`
	Message string `json:"message"`
}

// VerifyLinkRequest is the request body for verifying a link
type VerifyLinkRequest struct {
	Nonce     string `json:"nonce" binding:"required"`
	Address   string `json:"address" binding:"required"`
	Signature string `json:"signature" binding:"required"`
}

// EthAddressResponse represents a linked ETH address in API responses
type EthAddressResponse struct {
	Address    string `json:"address"`
	VerifiedAt string `json:"verified_at"`
}

// handleEthLinkChallenge handles POST /eth/link/challenge - create a challenge to sign
func (s *Server) handleEthLinkChallenge(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	// Create challenge
	challenge, err := s.challengeStore.CreateChallenge(userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create challenge: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, ChallengeResponse{
		Nonce:   challenge.Nonce,
		Message: challenge.Message,
	})
}

// handleEthLinkVerify handles POST /eth/link/verify - verify signature and link address
func (s *Server) handleEthLinkVerify(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	var req VerifyLinkRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Get the challenge
	challenge := s.challengeStore.GetChallenge(req.Nonce)
	if challenge == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired nonce"})
		return
	}

	// Verify the challenge belongs to this user
	if challenge.DID != userDID {
		c.JSON(http.StatusForbidden, gin.H{"error": "challenge does not belong to this user"})
		return
	}

	// Normalize the address
	normalizedAddr := auth.NormalizeAddress(req.Address)

	// Verify the signature
	if err := auth.VerifyAddressOwnership(normalizedAddr, challenge.Message, req.Signature); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "signature verification failed: " + err.Error()})
		return
	}

	// Get the message hash for storage
	messageHash := auth.MessageHashHex(challenge.Message)

	// Store the link in the database
	if err := s.db.LinkEthAddress(userDID, normalizedAddr, req.Signature, messageHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to link address: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "address linked successfully",
		"address": normalizedAddr,
	})
}

// handleGetEthAddresses handles GET /eth/addresses - list linked addresses for current user
func (s *Server) handleGetEthAddresses(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	// Get linked addresses
	links, err := s.db.GetEthAddressesByDID(userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get addresses: " + err.Error()})
		return
	}

	// Convert to response format
	addresses := make([]EthAddressResponse, 0, len(links))
	for _, link := range links {
		addresses = append(addresses, EthAddressResponse{
			Address:    link.EthAddress,
			VerifiedAt: link.VerifiedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"addresses": addresses})
}

// handleDeleteEthAddress handles DELETE /eth/addresses/:address - unlink an address
func (s *Server) handleDeleteEthAddress(c *gin.Context) {
	// Get user DID from JWT context
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing identity in context"})
		return
	}

	userDID, ok := subject.(string)
	if !ok || userDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid identity in context"})
		return
	}

	// Get and normalize the address
	address := c.Param("address")
	if address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "address parameter required"})
		return
	}
	normalizedAddr := strings.ToLower(address)

	// Revoke the link
	if err := s.db.RevokeEthAddressLink(userDID, normalizedAddr); err != nil {
		if strings.Contains(err.Error(), "no matching link") {
			c.JSON(http.StatusNotFound, gin.H{"error": "address not found or not linked to your account"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unlink address: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "address unlinked successfully"})
}
