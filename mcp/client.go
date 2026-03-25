package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type httpClient struct {
	baseURL    *url.URL
	adminToken string
	http       *http.Client
}

func newHTTPClient(rawURL, adminToken string) (*httpClient, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("base URL must be http or https, got %q", u.Scheme)
	}
	return &httpClient{
		baseURL:    u,
		adminToken: adminToken,
		http: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
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

	target := c.baseURL.JoinPath(path)
	if strings.Contains(path, "?") {
		parts := strings.SplitN(path, "?", 2)
		target = c.baseURL.JoinPath(parts[0])
		target.RawQuery = parts[1]
	}
	req, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.adminToken != "" {
		req.Header.Set("X-Admin-Token", c.adminToken)
	}

	resp, err := c.http.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
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
