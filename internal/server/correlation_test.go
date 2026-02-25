package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCorrelationIDMiddleware_GeneratesUUID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(correlationIDMiddleware())

	var capturedID string
	router.GET("/test", func(c *gin.Context) {
		capturedID = getCorrelationID(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, capturedID)
	// Should be a valid UUID (36 chars with hyphens)
	assert.Len(t, capturedID, 36)
	// Should echo back in response header
	assert.Equal(t, capturedID, w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDMiddleware_PreservesCorrelationID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(correlationIDMiddleware())

	existingID := "existing-correlation-id-123"
	var capturedID string
	router.GET("/test", func(c *gin.Context) {
		capturedID = getCorrelationID(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(CorrelationIDHeader, existingID)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, existingID, capturedID)
	assert.Equal(t, existingID, w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDMiddleware_FallsBackToRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(correlationIDMiddleware())

	requestID := "request-id-456"
	var capturedID string
	router.GET("/test", func(c *gin.Context) {
		capturedID = getCorrelationID(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(RequestIDHeader, requestID)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, requestID, capturedID)
	assert.Equal(t, requestID, w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDMiddleware_PrefersCorrelationIDOverRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(correlationIDMiddleware())

	correlationID := "correlation-id-789"
	requestID := "request-id-should-be-ignored"
	var capturedID string
	router.GET("/test", func(c *gin.Context) {
		capturedID = getCorrelationID(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set(CorrelationIDHeader, correlationID)
	req.Header.Set(RequestIDHeader, requestID)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, correlationID, capturedID)
}

func TestGetCorrelationID_ReturnsEmptyWhenNotSet(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	require.Empty(t, getCorrelationID(c))
}
