package server

import (
	"github.com/gin-gonic/gin"
)

// Session management handlers

// SessionListResponse represents the response for listing sessions.
type SessionListResponse struct {
	Sessions []*sessionInfoResponse `json:"sessions"`
	Total    int64                  `json:"total"`
}

type sessionInfoResponse struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	Completed   bool   `json:"completed"`
	CompletedAt string `json:"completed_at,omitempty"`
}

func (s *Server) listSessions(c *gin.Context) {
	sessions := s.sessionStore.ListSessions()
	count := s.sessionStore.Count()

	// Convert to response format
	var responseItems []*sessionInfoResponse
	for _, session := range sessions {
		item := &sessionInfoResponse{
			ID:        session.ID,
			CreatedAt: session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			Completed: session.Completed,
		}
		if session.Completed && !session.CompletedAt.IsZero() {
			item.CompletedAt = session.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		responseItems = append(responseItems, item)
	}

	respondOK(c, SessionListResponse{
		Sessions: responseItems,
		Total:    count,
	})
}

func (s *Server) deleteSession(c *gin.Context) {
	sessionID := c.Param("session_id")

	// Check if session exists
	session := s.sessionStore.GetSession(sessionID)
	if session == nil {
		respondNotFound(c, "session not found or expired")
		return
	}

	// Delete the session
	s.sessionStore.DeleteSession(sessionID)

	respondDeleted(c, "session")
}
