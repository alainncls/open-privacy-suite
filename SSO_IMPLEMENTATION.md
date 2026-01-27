# SSO Implementation: Privacy-Proxy + Explorer

## Overview

This document describes the Single Sign-On (SSO) implementation between the privacy-proxy and block explorer.

## Architecture

The SSO implementation uses an OAuth 2.0 Authorization Code flow with a QR code polling mechanism for mobile app authentication.

```
┌─────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│  Block Explorer │     │    Privacy-Proxy    │     │  Privado App │
│   (OAuth Client)│     │  (Identity Provider)│     │  (ZK Proofs) │
└────────┬────────┘     └──────────┬──────────┘     └──────┬───────┘
         │                         │                        │
         │ 1. POST /api/auth/login │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 2. GET /oauth/authorize │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 3. Return QR code data  │                        │
         │    (auth request)       │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 4. Display QR code      │                        │
         │    to user              │                        │
         │                         │                        │
         │                         │ 5. User scans QR,      │
         │                         │    submits ZK proof    │
         │                         │ <──────────────────────│
         │                         │                        │
         │ 6. Poll session status  │                        │
         │    GET /oauth/session   │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 7. Return redirect URL  │                        │
         │    with ?code=xxx       │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 8. Follow redirect to   │                        │
         │    /api/auth/callback   │                        │
         │                         │                        │
         │ 9. POST /oauth/token    │                        │
         │    (exchange code)      │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 10. Return JWT          │                        │
         │     (contains DID)      │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 11. Set auth cookie,    │                        │
         │     redirect to app     │                        │
         │                         │                        │
```

## Privacy-Proxy Endpoints (Identity Provider)

### GET /oauth/authorize

Initiates the OAuth authorization flow.

**Parameters:**
- `client_id` (required): Client identifier (e.g., "explorer")
- `redirect_uri` (required): URL to redirect after auth
- `response_type` (required): Must be "code"
- `state` (required): CSRF protection token

**Behavior:**
1. Validates parameters
2. Creates OAuth session linked to Privado auth session
3. Renders auth page with QR code (same as normal /auth flow)
4. After successful Privado auth, redirects to `redirect_uri?code=xxx&state=yyy`

### POST /oauth/token

Exchanges authorization code for JWT.

**Parameters (form or JSON):**
- `grant_type`: Must be "authorization_code"
- `code`: The authorization code from callback
- `redirect_uri`: Must match the original
- `client_id`: Must match the original

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### GET /oauth/session/:id/status

Polls the status of an OAuth session (for QR-code flows).

**Response (pending):**
```json
{
  "completed": false
}
```

**Response (completed):**
```json
{
  "completed": true,
  "redirect_url": "http://explorer/api/auth/callback?code=xxx&state=yyy"
}
```

## Explorer Endpoints (OAuth Client)

### POST /api/auth/login

Initiates SSO login via QR code flow.

**Request Body:**
```json
{
  "return_url": "/address/0x123"  // optional
}
```

**Response:**
```json
{
  "oauth_session_id": "abc-123",
  "auth_session_id": "def-456",
  "auth_request": { /* Privado auth request for QR code */ },
  "state": "random-state-token"
}
```

**Behavior:**
1. Calls privacy-proxy `/oauth/authorize` to initiate session
2. Returns auth request data for QR code display
3. Frontend polls `/api/auth/session/:id/status` until complete

### GET /api/auth/callback

Handles OAuth callback after QR code authentication.

**Parameters:**
- `code`: Authorization code from privacy-proxy
- `state`: CSRF protection token

**Behavior:**
1. Validates state parameter
2. Exchanges code for JWT via POST /oauth/token
3. Extracts DID from JWT claims
4. Sets `auth_token` cookie with JWT
5. Redirects to original page (from state)

### GET /api/auth/status

Returns current authentication status.

**Response (not authenticated):**
```json
{
  "authenticated": false
}
```

**Response (authenticated):**
```json
{
  "authenticated": true,
  "did": "did:polygonid:polygon:amoy:xxx",
  "expires_at": 1706300000
}
```

### POST /api/auth/logout

Clears authentication cookie.

**Response:**
```json
{
  "success": true
}
```

### GET /api/auth/session/:id/status

Polls the status of an SSO login session.

**Response (pending):**
```json
{
  "completed": false
}
```

**Response (completed):**
```json
{
  "completed": true,
  "redirect_url": "http://explorer/api/auth/callback?code=xxx&state=yyy"
}
```

## Security Considerations

1. **Redirect URI Validation**: Only localhost and configured BASE_URL allowed
2. **State Parameter**: Required for CSRF protection
3. **Code Expiry**: Authorization codes expire in 5 minutes
4. **Single Use**: Codes can only be exchanged once
5. **HTTPS**: Required in production

## Configuration

### Privacy-Proxy

No additional configuration needed - uses existing auth and JWT configuration.

### Explorer

| Variable | Description | Default |
|----------|-------------|---------|
| `PRIVACY_PROXY_URL` | Privacy-proxy base URL | (disabled if empty) |
| `SSO_CLIENT_ID` | OAuth client ID | `explorer` |
| `SSO_REDIRECT_URI` | OAuth callback URL | `http://localhost:8080/api/auth/callback` |

```bash
# Enable SSO with privacy-proxy
export PRIVACY_PROXY_URL=http://localhost:8080
export SSO_CLIENT_ID=explorer
export SSO_REDIRECT_URI=http://localhost:8080/api/auth/callback
```

## Usage Modes

| Mode | PRIVACY_PROXY_URL | Auth | Privacy Features |
|------|-------------------|------|------------------|
| Standalone | Not set | Wallet only | None |
| Anonymous | Set | None | Public data only |
| Authenticated | Set | Privado SSO | Full disclosure |

## API Changes

### Explorer API (privacy-proxy side)

Updated to accept `did` parameter directly:

```
GET /api/v1/explorer/viewable-addresses?did=did:polygonid:xxx
GET /api/v1/explorer/check-address/0x123?did=did:polygonid:xxx
POST /api/v1/explorer/check-addresses
  Body: { "addresses": [...], "did": "did:polygonid:xxx" }
```

When `did` is provided, the wallet→DID lookup is skipped.

## Testing

```bash
# Privacy-proxy OAuth tests
go test ./internal/server/... -run TestOAuth -v

# Explorer SSO tests
cd /Users/blade/work/software/explorer/backend
go test ./... -run TestSSO -v
```
