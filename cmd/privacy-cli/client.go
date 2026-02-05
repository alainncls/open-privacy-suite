package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProxyClient is a client for the Privacy Proxy API.
type ProxyClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewProxyClient creates a new proxy client.
func NewProxyClient(baseURL, token string) *ProxyClient {
	return &ProxyClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PrepareDeployment registers a deployment plan with the proxy.
func (c *ProxyClient) PrepareDeployment(orgID string, req *PrepareRequest) (*PrepareResponse, error) {
	url := fmt.Sprintf("%s/orgs/%s/deployments/prepare", c.baseURL, orgID)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result PrepareResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Deployment represents a deployment record.
type Deployment struct {
	ID         string            `json:"id"`
	OrgID      string            `json:"org_id"`
	Status     string            `json:"status"`
	Addresses  map[string]string `json:"addresses"`
	CreatedAt  string            `json:"created_at"`
	ExpiresAt  string            `json:"expires_at"`
	VerifiedAt string            `json:"verified_at,omitempty"`
}

// GetDeployment retrieves a deployment by ID.
func (c *ProxyClient) GetDeployment(deploymentID string) (*Deployment, error) {
	url := fmt.Sprintf("%s/deployments/%s", c.baseURL, deploymentID)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result Deployment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ListDeploymentsResponse represents the response from listing deployments.
type ListDeploymentsResponse struct {
	Deployments []Deployment `json:"deployments"`
	Total       int          `json:"total"`
}

// ListDeployments lists deployments for an organization.
func (c *ProxyClient) ListDeployments(orgID string, status string) (*ListDeploymentsResponse, error) {
	url := fmt.Sprintf("%s/orgs/%s/deployments", c.baseURL, orgID)
	if status != "" {
		url += "?status=" + status
	}

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result ListDeploymentsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// VerifyDeploymentRequest represents a request to verify a deployment.
type VerifyDeploymentRequest struct {
	DeploymentID string `json:"deployment_id"`
}

// VerifyDeploymentResponse represents the response from verifying a deployment.
type VerifyDeploymentResponse struct {
	Verified  bool                      `json:"verified"`
	Contracts []ContractVerificationResult `json:"contracts"`
	Errors    []string                  `json:"errors,omitempty"`
}

// ContractVerificationResult represents the verification result for a single contract.
type ContractVerificationResult struct {
	Name             string `json:"name"`
	ExpectedAddress  string `json:"expected_address"`
	ActualAddress    string `json:"actual_address,omitempty"`
	Verified         bool   `json:"verified"`
	BytecodeMatch    bool   `json:"bytecode_match"`
	Error            string `json:"error,omitempty"`
}

// VerifyDeployment verifies that a deployment matches its registration.
func (c *ProxyClient) VerifyDeployment(deploymentID string) (*VerifyDeploymentResponse, error) {
	url := fmt.Sprintf("%s/deployments/%s/verify", c.baseURL, deploymentID)

	httpReq, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result VerifyDeploymentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// DiscoverFactory attempts to discover the CREATE3 factory address from the proxy.
func (c *ProxyClient) DiscoverFactory() (string, error) {
	url := fmt.Sprintf("%s/dev/create3-factory", c.baseURL)

	httpReq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("factory discovery not available (status %d)", resp.StatusCode)
	}

	var result struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Address, nil
}

// setHeaders sets common HTTP headers for API requests.
func (c *ProxyClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}
