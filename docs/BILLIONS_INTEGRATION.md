# Billions KYC Integration

## Overview

The privacy proxy integrates with the Billions identity service to verify KYC (Know Your Customer) status for users. Authentication is handled via Privado ID zero-knowledge proofs, with Billions providing the KYC verification backend.

## Architecture

```
┌─────────────┐     ┌───────────────┐     ┌─────────────┐
│   Client    │────▶│ Privacy Proxy │────▶│  Billions   │
│  (Wallet)   │     │   (Go/Gin)    │     │   Service   │
└─────────────┘     └───────────────┘     └─────────────┘
       │                    │                    │
       │  1. Auth Request   │                    │
       │◀───────────────────│                    │
       │                    │                    │
       │  2. JWZ Proof      │                    │
       │───────────────────▶│                    │
       │                    │  3. Verify KYC     │
       │                    │───────────────────▶│
       │                    │                    │
       │                    │  4. Identity       │
       │                    │◀───────────────────│
       │  5. JWT Token      │                    │
       │◀───────────────────│                    │
```

## Key Components

| File | Purpose |
|------|---------|
| `internal/identity/identity.go` | Billions HTTP client for KYC verification |
| `internal/auth/privado.go` | Privado ID ZK proof verification |
| `internal/auth/jwt.go` | JWT token issuance and validation |
| `internal/server/auth.go` | Authentication HTTP endpoints |
| `internal/config/config.go` | Environment configuration |

---

## Authentication Flow

### Step 1: Client Requests Auth Challenge

**Endpoint:** `POST /auth/request`

The client initiates authentication by requesting a Privado ID authorization challenge.

**Server Actions** (`internal/server/auth.go:49-86`):
1. Generate session ID
2. Create Privado authorization request with callback URL
3. Store session with auth request
4. Return session ID and auth request to client

**Response:**
```json
{
  "session_id": "abc123...",
  "auth_request": {
    "id": "request-id",
    "type": "https://iden3-communication.io/authorization/1.0/request",
    "body": {
      "callbackUrl": "http://localhost:8080/auth/callback?session=abc123...",
      "reason": "Authenticate to access Ethereum node"
    }
  }
}
```

### Step 2: Wallet Generates ZK Proof

The client's Privado wallet creates a JWZ (JSON Web Zero-knowledge) token:
- Proves DID ownership without revealing private keys
- Cryptographically bound to the authorization request
- Cannot be replayed to other verifiers

### Step 3: Client Submits Proof

**Endpoint:** `POST /auth/callback?session={session_id}` (wallet callback)
**Endpoint:** `POST /auth/verify` (manual, development only)

**Server Actions** (`internal/server/auth.go:90-142`):
1. Retrieve session by ID
2. Extract JWZ token from request body
3. Verify JWZ against original auth request
4. Extract user DID from verified proof

### Step 4: Server Verifies KYC via Billions

**Note:** The current implementation retrieves KYC status from the local policy database rather than calling Billions directly. The Billions integration is available via `internal/identity/identity.go` but is not used in the main auth flow.

**Billions API Contract** (`internal/identity/identity.go:57-91`):
```
GET {BILLIONS_URL}/verify
Headers: Authorization: Bearer {user_id}

Response:
{
  "subject": "billions:{user_id}",
  "kyc": true,
  "claims": {
    "token": "user_id",
    "iat": 1234567890,
    "exp": 1234571490
  }
}
```

### Step 5: JWT Tokens Issued

**Server Actions** (`internal/server/auth.go:169-218`):
1. Issue access token (30 min TTL)
2. Issue refresh token (7 day TTL)
3. Store refresh token hash in database
4. Return tokens to client

**Response:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

---

## Privado ID Prover Mechanism

### Overview

Privado ID uses zero-knowledge proofs to verify identity without revealing sensitive data. The proxy verifies these proofs using the go-iden3-auth library.

**Location:** `internal/auth/privado.go`

### Components

| Component | Value | Purpose |
|-----------|-------|---------|
| State Contract | `0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896` | On-chain identity state verification |
| State Resolver | ETH RPC resolver | Reads identity state from blockchain |
| Key Loader | Embedded keys from go-iden3-auth | Verification keys for ZK proofs |
| IPFS Gateway | `https://ipfs-proxy-cache.privado.id` | Schema resolution for credentials |

### Verification Flow

```go
// internal/auth/privado.go:75-110

// 1. Verify JWZ token against original request
authResponse, err := p.verifier.FullVerify(ctx, jwzToken, *authRequest)

// 2. Security check - verify proof target
if authResponse.To != verifierID {
    return error  // Prevent proof replay
}

// 3. Extract user DID
userDID := authResponse.From
```

### Trust Model

1. **User's wallet** holds private credentials
2. **Wallet generates ZK proof** proving identity without revealing secrets
3. **Server verifies proof cryptographically** using go-iden3-auth
4. **State contract confirms** identity is valid on-chain
5. **No private data leaves** user's device

---

## JWT Token Structure

### Access Token Claims

```go
// internal/auth/jwt.go:29-34
type TokenClaims struct {
    Subject string `json:"sub"` // User DID from Privado ID
    KYC     bool   `json:"kyc"` // KYC status
    jwt.RegisteredClaims
}
```

| Claim | Description |
|-------|-------------|
| `sub` | User's DID (e.g., `did:privado:test_user`) |
| `kyc` | Boolean KYC verification status |
| `jti` | Unique token ID (UUID) |
| `exp` | Expiration time (30 min for access, 7 days for refresh) |
| `iat` | Issued at time |
| `nbf` | Not before time |

### Token Lifecycle

1. **Access Token** (30 min):
   - Used for API requests
   - Contains KYC status
   - Short-lived for security

2. **Refresh Token** (7 days):
   - Used to obtain new access tokens
   - Hash stored in database
   - Rotated on each use (old token revoked)

### Token Refresh

**Endpoint:** `POST /refresh`

```json
{
  "refresh_token": "eyJhbGc..."
}
```

**Server Actions** (`internal/server/auth.go:220-306`):
1. Validate refresh token JWT
2. Check token not revoked in database
3. Issue new access token
4. Issue new refresh token (rotation)
5. Revoke old refresh token

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BILLIONS_URL` | `http://localhost:9000` | Billions service URL (deprecated, kept for compatibility) |
| `PRIVADO_RPC_URL` | `https://rpc-mainnet.privado.id` | Privado network RPC for state verification |
| `IPFS_GATEWAY` | `https://ipfs-proxy-cache.privado.id` | IPFS gateway for schema resolution |
| `JWT_SECRET` | (auto-generated in dev) | Secret for signing access tokens |
| `JWT_REFRESH_SECRET` | (auto-generated in dev) | Secret for signing refresh tokens |
| `VERIFIER_ID` | (required in prod) | DID of the verifier service |
| `BASE_URL` | `http://localhost:8080` | Base URL for callback URLs |
| `ENVIRONMENT` | `development` | `production` or `development` |

### Production Requirements

1. Set strong, unique `JWT_SECRET` and `JWT_REFRESH_SECRET`
2. Configure `VERIFIER_ID` with your service's DID
3. Set `BASE_URL` to your public URL
4. Set `ENVIRONMENT=production` (disables `/auth/verify` endpoint)

---

## Error Handling

### Authentication Errors

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `session parameter required` | Missing session ID in callback |
| 400 | `jwz_token required` | Missing proof token |
| 401 | `session not found or expired` | Invalid or expired session (10 min TTL) |
| 401 | `JWZ verification failed` | Invalid ZK proof |
| 401 | `refresh token expired` | Refresh token past expiry |
| 401 | `refresh token revoked` | Token was revoked |
| 500 | `VERIFIER_ID not configured` | Missing configuration |

### Access Control Errors

| Status | Error | Cause |
|--------|-------|-------|
| 401 | `missing Authorization header` | No Bearer token |
| 401 | `invalid token` | Malformed or invalid JWT |
| 403 | `user is banned` | User's policy has `banned: true` |
| 403 | `KYC required` | User's policy has `kyc: false` |
| 403 | `method not allowed` | Method not in user's `allow_methods` |

---

## Code References

| File | Lines | Description |
|------|-------|-------------|
| `internal/auth/privado.go` | 21-53 | Privado verifier initialization |
| `internal/auth/privado.go` | 55-69 | Create authorization request |
| `internal/auth/privado.go` | 75-110 | JWZ verification |
| `internal/auth/jwt.go` | 66-81 | Access token issuance |
| `internal/auth/jwt.go` | 84-98 | Refresh token issuance |
| `internal/server/auth.go` | 49-86 | Auth request handler |
| `internal/server/auth.go` | 90-142 | Auth callback handler |
| `internal/server/auth.go` | 169-218 | Token issuance helper |
| `internal/identity/identity.go` | 57-91 | Billions API client |
