package types

import "time"

// OAuthSession represents the serializable data for a pending OAuth authorization session.
// This struct is shared between the in-memory store (server package) and the Redis store
// (redis package). It deliberately omits sync.Mutex since Redis handles concurrency natively
// and the mutex cannot be serialized.
type OAuthSession struct {
	// OAuth parameters from the authorize request
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`

	// Link to the underlying auth session (Privado ID flow)
	AuthSessionID string `json:"auth_session_id"`

	// Authorization code (set after successful auth)
	Code        string    `json:"code"`
	CodeUsed    bool      `json:"code_used"`
	CodeExpires time.Time `json:"code_expires"`

	// User info (set after successful auth)
	UserDID string `json:"user_did"`
	KYC     bool   `json:"kyc"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
