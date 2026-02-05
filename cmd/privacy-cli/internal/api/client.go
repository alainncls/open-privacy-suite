// Package api provides a client for the privacy proxy API.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a client for the privacy proxy API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new API client.
func NewClient(baseURL, token string) *Client {
	// Ensure baseURL doesn't have trailing slash
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PreregisteredAddress represents a preregistered address in the API response.
type PreregisteredAddress struct {
	ID             string  `json:"id"`
	OrgID          string  `json:"org_id"`
	Address        string  `json:"address"`
	Factory        string  `json:"factory"`
	Salt           string  `json:"salt"` // Hex-encoded
	Note           string  `json:"note,omitempty"`
	ConstructorABI string  `json:"constructor_abi,omitempty"`
	CreatedAt      string  `json:"created_at"`
	UsedAt         *string `json:"used_at,omitempty"`
}

// RegisterAddressesRequest is the request body for registering addresses.
type RegisterAddressesRequest struct {
	Addresses []AddressToRegister `json:"addresses"`
}

// AddressToRegister represents a single address to register.
type AddressToRegister struct {
	Address        string `json:"address"`
	ContractName   string `json:"contract_name,omitempty"`
	DeploymentType string `json:"deployment_type,omitempty"`
	Note           string `json:"note,omitempty"`
}

// RegisterAddressesResponse is the response from registering addresses.
type RegisterAddressesResponse struct {
	Registered []PreregisteredAddress `json:"registered"`
	Skipped    []SkippedAddress       `json:"skipped,omitempty"`
}

// SkippedAddress represents an address that was skipped during registration.
type SkippedAddress struct {
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// PreregisterRequest is the request body for the preregister endpoint.
// This uses CREATE3 address generation.
type PreregisterRequest struct {
	Factory        string `json:"factory"`
	SaltPrefix     string `json:"salt_prefix"`
	Count          int    `json:"count"`
	Note           string `json:"note,omitempty"`
	ConstructorABI string `json:"constructor_abi,omitempty"`
}

// PreregisterResponse is the response from the preregister endpoint.
type PreregisterResponse struct {
	Addresses []PreregisteredAddress `json:"addresses"`
}

// APIError represents an error response from the API.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// doRequest performs an HTTP request with authentication.
func (c *Client) doRequest(method, path string, body any) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	return c.httpClient.Do(req)
}

// handleResponse reads and handles the API response.
func handleResponse(resp *http.Response, result any) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return &APIError{StatusCode: resp.StatusCode, Message: errResp.Error}
		}
		return &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	if result != nil {
		if err := json.Unmarshal(body, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// PreregisterAddresses registers new CREATE3 addresses for an organization.
// This endpoint generates addresses using the specified factory and salt prefix.
func (c *Client) PreregisterAddresses(orgID string, req *PreregisterRequest) (*PreregisterResponse, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/addresses/preregister", orgID)

	resp, err := c.doRequest(http.MethodPost, path, req)
	if err != nil {
		return nil, err
	}

	var result PreregisterResponse
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ListPreregisteredAddresses returns all preregistered addresses for an organization.
func (c *Client) ListPreregisteredAddresses(orgID string) ([]PreregisteredAddress, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/addresses/preregistered", orgID)

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result []PreregisteredAddress
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// DeletePreregisteredAddress deletes a preregistered address.
func (c *Client) DeletePreregisteredAddress(orgID, address string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/addresses/preregistered/%s", orgID, address)

	resp, err := c.doRequest(http.MethodDelete, path, nil)
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}

// UpdateConstructorABI updates the constructor ABI for a preregistered address.
func (c *Client) UpdateConstructorABI(orgID, address, abi string) error {
	path := fmt.Sprintf("/api/v1/orgs/%s/addresses/preregistered/%s/abi", orgID, address)

	body := struct {
		ConstructorABI string `json:"constructor_abi"`
	}{ConstructorABI: abi}

	resp, err := c.doRequest(http.MethodPut, path, body)
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}

// Create3Config represents the CREATE3 configuration for an organization.
type Create3Config struct {
	Factory    string `json:"factory"`
	Configured bool   `json:"configured"`
	Message    string `json:"message,omitempty"`
}

// GetCreate3Config retrieves the CREATE3 factory configuration for an organization.
func (c *Client) GetCreate3Config(orgID string) (*Create3Config, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/config/create3", orgID)

	resp, err := c.doRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result Create3Config
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// SetCreate3Config sets the CREATE3 factory address for an organization.
func (c *Client) SetCreate3Config(orgID, factory string) (*Create3Config, error) {
	path := fmt.Sprintf("/api/v1/orgs/%s/config/create3", orgID)

	body := struct {
		Factory string `json:"factory"`
	}{Factory: factory}

	resp, err := c.doRequest(http.MethodPut, path, body)
	if err != nil {
		return nil, err
	}

	var result Create3Config
	if err := handleResponse(resp, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
