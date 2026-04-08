package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListSessions_NilSessionStore_ReturnsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &Server{sessionStore: nil}

	router := gin.New()
	router.GET("/sessions", srv.listSessions)

	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp SessionListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Empty(t, resp.Sessions)
	assert.Equal(t, int64(0), resp.Total)
}

func TestDeleteSession_NilSessionStore_ReturnsNotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &Server{sessionStore: nil}

	router := gin.New()
	router.DELETE("/sessions/:session_id", srv.deleteSession)

	req := httptest.NewRequest(http.MethodDelete, "/sessions/some-id", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
