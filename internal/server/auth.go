package server

import (
	"context"
	"net/http"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/gin-gonic/gin"
)

// AuthRequest represents the request body for /auth endpoint
type AuthRequest struct {
	JWZToken string `json:"jwz_token" binding:"required"`
}

// AuthResponse represents the response from /auth endpoint
type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// RefreshRequest represents the request body for /refresh endpoint
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// handleAuth handles POST /auth - verifies JWZ proof and issues JWT tokens
func (s *Server) handleAuth(c *gin.Context) {
	var req AuthRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Verify JWZ token using Privado ID verifier
	ctx := context.Background()
	userDID, err := s.privadoVerifier.VerifyJWZ(ctx, req.JWZToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "JWZ verification failed: " + err.Error()})
		return
	}

	// Check if user has a policy (to determine KYC status)
	// If no policy exists, we can still issue a token but KYC will be false
	policy, _ := s.db.GetPolicy(userDID)
	kyc := false
	if policy != nil {
		kyc = policy.KYC
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(userDID, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(userDID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token: " + err.Error()})
		return
	}

	// Store refresh token in database
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	if err := s.db.SaveRefreshToken(tokenHash, userDID, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token: " + err.Error()})
		return
	}

	// Return tokens
	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800, // 30 minutes in seconds
	})
}

// handleRefresh handles POST /refresh - issues new access token from refresh token
func (s *Server) handleRefresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate refresh token
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		if err == auth.ErrExpiredToken {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token: " + err.Error()})
		}
		return
	}

	// Check if refresh token is revoked in database
	tokenHash := auth.HashToken(req.RefreshToken)
	storedToken, err := s.db.GetRefreshToken(tokenHash)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check refresh token: " + err.Error()})
		return
	}

	if storedToken == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token not found"})
		return
	}

	if storedToken.Revoked {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token revoked"})
		return
	}

	// Check if token expired in database
	expiresAt, err := time.Parse(time.RFC3339, storedToken.ExpiresAt)
	if err == nil && time.Now().After(expiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	// Get user policy to determine KYC status
	policy, _ := s.db.GetPolicy(claims.Subject)
	kyc := false
	if policy != nil {
		kyc = policy.KYC
	}

	// Issue new access token
	accessToken, err := s.jwtService.IssueAccessToken(claims.Subject, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return
	}

	// Optionally rotate refresh token (security best practice)
	// For now, we'll issue a new refresh token and revoke the old one
	newRefreshToken, err := s.jwtService.IssueRefreshToken(claims.Subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue new refresh token: " + err.Error()})
		return
	}

	// Revoke old refresh token
	if err := s.db.RevokeRefreshToken(tokenHash); err != nil {
		// Log error but continue (non-critical)
		_ = err
	}

	// Store new refresh token
	newTokenHash := auth.HashToken(newRefreshToken)
	newExpiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days
	if err := s.db.SaveRefreshToken(newTokenHash, claims.Subject, newExpiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save new refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    1800, // 30 minutes in seconds
	})
}

// handleRevoke handles POST /revoke - revokes a refresh token
func (s *Server) handleRevoke(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request: " + err.Error()})
		return
	}

	// Validate token to get subject (optional, but helps with logging)
	claims, err := s.jwtService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		// Even if token is invalid/expired, we can still revoke it (defense in depth)
		// Log but continue
		_ = claims
	}

	// Revoke refresh token
	tokenHash := auth.HashToken(req.RefreshToken)
	if err := s.db.RevokeRefreshToken(tokenHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "token revoked successfully"})
}
