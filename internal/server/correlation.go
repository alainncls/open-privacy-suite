package server

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	// CorrelationIDHeader is the primary correlation ID header.
	CorrelationIDHeader = "X-Correlation-ID"
	// RequestIDHeader is a fallback header for correlation ID.
	RequestIDHeader = "X-Request-ID"
	// correlationIDKey is the Gin context key for the correlation ID.
	correlationIDKey = "correlation_id"
)

// correlationIDMiddleware extracts or generates a correlation ID for each request.
// It checks X-Correlation-ID first, then X-Request-ID, and generates a UUIDv4 if neither is present.
// The ID is stored in the Gin context and echoed back in the X-Correlation-ID response header.
func correlationIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		correlationID := c.GetHeader(CorrelationIDHeader)
		if correlationID == "" {
			correlationID = c.GetHeader(RequestIDHeader)
		}
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		c.Set(correlationIDKey, correlationID)
		c.Header(CorrelationIDHeader, correlationID)
		c.Next()
	}
}

// getCorrelationID retrieves the correlation ID from the Gin context.
// Returns empty string if not set.
func getCorrelationID(c *gin.Context) string {
	if id, exists := c.Get(correlationIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}
