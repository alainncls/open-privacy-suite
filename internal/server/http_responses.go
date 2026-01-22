package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HTTP Response Helpers
//
// These helpers provide consistent JSON error and success responses.
// Use these instead of inline c.JSON() calls for consistent formatting.
//
// ## Error Message Conventions
//
// 1. Start with lowercase (e.g., "invalid request" not "Invalid request")
// 2. Use consistent prefixes:
//   - "invalid X" for validation errors
//   - "X not found" for missing resources
//   - "failed to X" for operation failures
//   - "missing X" for required fields/context
//
// 3. Don't expose internal error details to clients (log them instead)
// 4. Keep messages concise and actionable
//
// ## Examples
//
//	respondBadRequest(c, "invalid email format")
//	respondNotFound(c, "user not found")
//	respondInternalError(c, "failed to process request")
//	respondUnauthorized(c, "missing or invalid token")

func respondBadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": message})
}

func respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": message})
}

func respondForbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, gin.H{"error": message})
}

func respondNotFound(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, gin.H{"error": message})
}

func respondConflict(c *gin.Context, message string) {
	c.JSON(http.StatusConflict, gin.H{"error": message})
}

func respondTooManyRequests(c *gin.Context, message string) {
	c.JSON(http.StatusTooManyRequests, gin.H{"error": message})
}

func respondInternalError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, gin.H{"error": message})
}

func respondBadGateway(c *gin.Context, message string) {
	c.JSON(http.StatusBadGateway, gin.H{"error": message})
}

// Success response helpers

func respondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

func respondCreated(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

func respondMessage(c *gin.Context, message string) {
	c.JSON(http.StatusOK, gin.H{"message": message})
}

func respondDeleted(c *gin.Context, resourceType string) {
	c.JSON(http.StatusOK, gin.H{"message": resourceType + " deleted"})
}
