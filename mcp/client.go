package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type httpClient struct {
	baseURL    string
	adminToken string
	http       *http.Client
}

func newHTTPClient(baseURL, adminToken string) *httpClient {
	return &httpClient{
		baseURL:    baseURL,
		adminToken: adminToken,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (c *httpClient) get(path string) (json.RawMessage, error) {
	return c.do(http.MethodGet, path, nil)
}

func (c *httpClient) post(path string, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPost, path, payload)
}

func (c *httpClient) put(path string, payload any) (json.RawMessage, error) {
	return c.do(http.MethodPut, path, payload)
}

func (c *httpClient) del(path string) (json.RawMessage, error) {
	return c.do(http.MethodDelete, path, nil)
}

func (c *httpClient) do(method, path string, payload any) (json.RawMessage, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.adminToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 500))
	}

	return json.RawMessage(respBody), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
