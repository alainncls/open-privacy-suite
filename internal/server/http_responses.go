package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Error response helpers provide consistent JSON error responses.
// Usage: respondBadRequest(c, "invalid input")
// Output: {"error": "invalid input"} with HTTP 400

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
