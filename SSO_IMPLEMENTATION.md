# SSO Implementation: Privacy-Proxy + Explorer

## Overview

This document describes the Single Sign-On (SSO) implementation between the privacy-proxy and block explorer.

## Architecture

```
┌─────────────────┐     ┌─────────────────────┐     ┌──────────────┐
│  Block Explorer │     │    Privacy-Proxy    │     │  Privado App │
│   (OAuth Client)│     │  (Identity Provider)│     │  (ZK Proofs) │
└────────┬────────┘     └──────────┬──────────┘     └──────┬───────┘
         │                         │                        │
         │ 1. User clicks          │                        │
         │    "Sign in with        │                        │
         │     Privado"            │                        │
         │                         │                        │
         │ 2. Redirect to          │                        │
         │    /oauth/authorize     │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │                         │ 3. Show QR code        │
         │                         │    (auth request)      │
         │                         │ ──────────────────────>│
         │                         │                        │
         │                         │ 4. User scans,         │
         │                         │    submits ZK proof    │
         │                         │ <──────────────────────│
         │                         │                        │
         │ 5. Redirect to          │                        │
         │    explorer callback    │                        │
         │    with ?code=xxx       │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 6. POST /oauth/token    │                        │
         │    (exchange code)      │                        │
         │ ───────────────────────>│                        │
         │                         │                        │
         │ 7. Return JWT           │                        │
         │    (contains DID)       │                        │
         │ <───────────────────────│                        │
         │                         │                        │
         │ 8. Use JWT for API      │                        │
         │    calls (DID-based     │                        │
         │    disclosure access)   │                        │
         │ ───────────────────────>│                        │
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

## Explorer Endpoints (OAuth Client)

### GET /auth/privado/login

Initiates SSO login.

**Behavior:**
1. Generates random `state` parameter
2. Stores state in session/cookie
3. Redirects to privacy-proxy `/oauth/authorize`

### GET /auth/privado/callback

Handles OAuth callback.

**Parameters:**
- `code`: Authorization code
- `state`: Must match stored state

**Behavior:**
1. Validates state parameter
2. Exchanges code for JWT via POST /oauth/token
3. Extracts DID from JWT
4. Stores JWT in session/cookie
5. Redirects to original page

## Security Considerations

1. **Redirect URI Validation**: Only localhost and configured BASE_URL allowed
2. **State Parameter**: Required for CSRF protection
3. **Code Expiry**: Authorization codes expire in 5 minutes
4. **Single Use**: Codes can only be exchanged once
5. **HTTPS**: Required in production

## Configuration

### Privacy-Proxy

No additional configuration needed - uses existing auth config.

### Explorer

```bash
PRIVACY_PROXY_URL=http://localhost:8080  # Enables SSO feature
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
