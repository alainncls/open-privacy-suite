package main

// HTTP client for the proxy's /auth/request → /auth/verify exchange.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/iden3/iden3comm/v2/protocol"
)

// authRequestResponse is the shape returned by the proxy's /auth/request
// endpoint (see internal/server/auth.go:handleAuthRequest). The
// embedded protocol.AuthorizationRequestMessage is what the wallet
// signs.
type authRequestResponse struct {
	SessionID string                                  `json:"session_id"`
	Request   protocol.AuthorizationRequestMessage    `json:"auth_request"`
}

// authVerifyResponse is the JWT response from /auth/verify. The proxy
// returns access + refresh tokens after a successful proof check.
type authVerifyResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// httpClient is the shared client. The 30-second timeout covers the
// state-resolver round-trip on /auth/verify; raise it via env if needed
// on a sluggish staging environment.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// fetchAuthRequest hits POST /auth/request on the proxy. The proxy
// generates a session ID and an AuthorizationRequestMessage with a
// fresh challenge (nonce); the wallet signs that exact request.
func fetchAuthRequest(ctx context.Context, proxyURL string) (*authRequestResponse, error) {
	target, err := url.JoinPath(proxyURL, "/auth/request")
	if err != nil {
		return nil, fmt.Errorf("join URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", target, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d %s — %s", target, resp.StatusCode, http.StatusText(resp.StatusCode), string(body))
	}

	var out authRequestResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode auth-request response: %w (body: %s)", err, string(body))
	}
	if out.SessionID == "" {
		return nil, fmt.Errorf("auth-request response missing session_id (body: %s)", string(body))
	}
	return &out, nil
}

// postAuthVerify submits the packed JWZ token to /auth/verify. The proxy
// runs FullVerify (signature + on-chain state + verifier-ID match), and
// on success issues access + refresh JWTs.
func postAuthVerify(ctx context.Context, proxyURL, sessionID string, jwzToken []byte) (*authVerifyResponse, error) {
	target, err := url.JoinPath(proxyURL, "/auth/verify")
	if err != nil {
		return nil, fmt.Errorf("join URL: %w", err)
	}

	body, err := json.Marshal(map[string]string{
		"session_id": sessionID,
		"jwz_token":  string(jwzToken),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal verify request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", target, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %d %s — %s", target, resp.StatusCode, http.StatusText(resp.StatusCode), string(respBody))
	}

	var out authVerifyResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode auth-verify response: %w (body: %s)", err, string(respBody))
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("auth-verify response missing access_token (body: %s)", string(respBody))
	}
	return &out, nil
}
