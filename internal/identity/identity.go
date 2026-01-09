package identity

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Identity struct {
	Subject string                 `json:"subject"`
	KYC     bool                   `json:"kyc"`
	Claims  map[string]interface{} `json:"claims"`
}

type Service struct {
	billionsURL string
	client      *http.Client
}

func NewService(billionsURL string) *Service {
	return &Service{
		billionsURL: billionsURL,
		client:      &http.Client{},
	}
}

// ResolveIdentity resolves an identity from a Bearer token
// Token format: "provider:user_id" (e.g., "billions:user_123")
// If token has a prefix matching a known provider, forwards to that provider
// Otherwise returns an error
func (s *Service) ResolveIdentity(token string) (*Identity, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token")
	}

	// Parse token to extract provider prefix
	parts := strings.Split(token, ":")
	if len(parts) < 2 {
		return nil, fmt.Errorf("token must be in format 'provider:user_id', got: %s", token)
	}

	provider := parts[0]
	userID := strings.Join(parts[1:], ":") // Handle cases where user_id might contain colons

	// Route to appropriate provider service
	switch provider {
	case "billions":
		// Forward to Billions service with just the user_id part
		return s.ResolveIdentityFromBillions(userID)
	default:
		return nil, fmt.Errorf("unknown provider: %s. Supported providers: billions", provider)
	}
}


// ResolveIdentityFromBillions makes actual HTTP call to Billions service
// Receives the user_id part (without the "billions:" prefix)
func (s *Service) ResolveIdentityFromBillions(userID string) (*Identity, error) {
	req, err := http.NewRequest("GET", s.billionsURL+"/verify", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Send user_id as the token to Billions service
	req.Header.Set("Authorization", "Bearer "+userID)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call Billions: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Billions returned status %d: %s", resp.StatusCode, string(body))
	}

	var identity Identity
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Ensure the subject matches the full token format (billions:user_id)
	// If Billions returns just the user_id, prepend the provider prefix
	if !strings.Contains(identity.Subject, ":") {
		identity.Subject = "billions:" + identity.Subject
	}

	return &identity, nil
}
