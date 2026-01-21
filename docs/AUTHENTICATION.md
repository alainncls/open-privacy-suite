# Authentication

## Overview

Authentication uses Privado ID zero-knowledge proofs with optional ProofOfHumanity (PoH) verification via Billions. Users prove identity without revealing private keys, and can optionally link Ethereum addresses.

## Architecture

```
┌─────────────┐     ┌───────────────┐     ┌─────────────┐
│   Client    │────▶│ Privacy Proxy │     │  Billions   │
│  (Wallet)   │     │   (Go/Gin)    │     │  (Issuer)   │
└─────────────┘     └───────────────┘     └─────────────┘
       │                    │                    │
       │  1. Auth Request   │                    │
       │   (with PoH Query) │                    │
       │◀───────────────────│                    │
       │                    │                    │
       │  2. JWZ Proof      │                    │
       │   (includes PoH)   │                    │
       │───────────────────▶│                    │
       │                    │                    │
       │  3. JWT Tokens     │                    │
       │◀───────────────────│                    │
       │                    │                    │
       │                    │  (User must have   │
       │                    │   PoH credential   │
       │                    │   issued by        │
       │                    │   Billions)        │
       │                    │                    │
```

## Key Components

| File | Purpose |
|------|---------|
| `internal/config/config.go` | Configuration including Billions issuer DID |
| `internal/auth/privado.go` | Privado ID verification with PoH ZK query |
| `internal/auth/mock_privado.go` | Mock verifier for testing |
| `internal/auth/eth_signature.go` | EIP-191 signature verification for ETH linking |
| `internal/server/auth.go` | Authentication HTTP endpoints |
| `internal/server/eth_link.go` | ETH address linking endpoints |
| `internal/db/db.go` | Database methods including ETH address links |

---

## Authentication Flow with ProofOfHumanity

### Step 1: Client Requests Auth Challenge

**Endpoint:** `POST /auth/request`

The client initiates authentication by requesting a Privado ID authorization challenge.

**Server Actions:**
1. Generate session ID
2. Create authorization request with ProofOfHumanity ZK query (if enabled)
3. Store session with auth request
4. Return session ID and auth request to client

**ZK Query Structure** (when `RequireProofOfHumanity` is enabled):
```json
{
  "id": 1,
  "circuitId": "credentialAtomicQueryMTPV2",
  "query": {
    "allowedIssuers": ["did:polygonid:polygon:amoy:..."],
    "credentialSubject": {
      "isHuman": {"$eq": 1}
    },
    "context": "https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-humanity/proof-of-humanity.jsonld",
    "type": "ProofOfHumanity"
  }
}
```

**Response:**
```json
{
  "session_id": "abc123...",
  "auth_request": {
    "id": "request-id",
    "type": "https://iden3-communication.io/authorization/1.0/request",
    "body": {
      "callbackUrl": "http://localhost:8080/auth/callback?session=abc123...",
      "reason": "Authenticate and verify humanity to access Ethereum node",
      "scope": [...]
    }
  }
}
```

### Step 2: Wallet Generates ZK Proof

The client's Privado wallet creates a JWZ (JSON Web Zero-knowledge) token:
- Proves DID ownership without revealing private keys
- Proves possession of ProofOfHumanity credential (isHuman=1)
- Cryptographically bound to the authorization request
- Cannot be replayed to other verifiers

### Step 3: Client Submits Proof

**Endpoint:** `POST /auth/callback?session={session_id}` (wallet callback)
**Endpoint:** `POST /auth/verify` (manual, development only)

**Server Actions:**
1. Retrieve session by ID
2. Extract JWZ token from request body
3. Verify JWZ against original auth request
4. If PoH query included: verify user has valid credential
5. Extract user DID from verified proof

### Step 4: JWT Tokens Issued or Rejection

**On Success:**
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

**On ProofOfHumanity Failure (403 Forbidden):**
```json
{
  "error": "humanity_verification_required",
  "message": "Please complete ProofOfHumanity verification at Billions",
  "verify_url": "https://app.billions.network"
}
```

---

## ETH Address Linking

Users can link their Ethereum addresses to their DID after authentication using EIP-191 signatures.

### Step 1: Request Challenge

**Endpoint:** `POST /eth/link/challenge` (JWT required)

**Response:**
```json
{
  "nonce": "a1b2c3d4e5f6...",
  "message": "Link Ethereum address to DID\n\nI authorize linking this Ethereum address to my decentralized identity.\n\nDID: did:privado:...\nNonce: a1b2c3d4e5f6...\n\nThis signature proves ownership of this Ethereum address."
}
```

### Step 2: Sign Message

User signs the message using their Ethereum wallet (MetaMask, etc.) with `personal_sign`.

### Step 3: Submit Signature

**Endpoint:** `POST /eth/link/verify` (JWT required)

**Request:**
```json
{
  "nonce": "a1b2c3d4e5f6...",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f...",
  "signature": "0x..."
}
```

**Response:**
```json
{
  "message": "address linked successfully",
  "address": "0x742d35cc6634c0532925a3b844bc9e7595f..."
}
```

### Step 4: View Linked Addresses

**Endpoint:** `GET /eth/addresses` (JWT required)

**Response:**
```json
{
  "addresses": [
    {
      "address": "0x742d35cc6634c0532925a3b844bc9e7595f...",
      "verified_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Step 5: Unlink Address

**Endpoint:** `DELETE /eth/addresses/:address` (JWT required)

**Response:**
```json
{
  "message": "address unlinked successfully"
}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BILLIONS_ISSUER_DID` | (none) | Billions issuer DID for PoH verification |
| `REQUIRE_PROOF_OF_HUMANITY` | `true` in prod, `false` in dev | Enable/disable PoH requirement |
| `PRIVADO_RPC_URL` | `https://rpc-mainnet.privado.id` | Privado network RPC |
| `IPFS_GATEWAY` | `https://ipfs-proxy-cache.privado.id` | IPFS gateway for schemas |
| `JWT_SECRET` | (auto-generated in dev) | Access token signing secret |
| `JWT_REFRESH_SECRET` | (auto-generated in dev) | Refresh token signing secret |
| `VERIFIER_ID` | (required in prod) | DID of the verifier service |
| `BASE_URL` | `http://localhost:8080` | Base URL for callback URLs |
| `ENVIRONMENT` | `development` | `production` or `development` |

### Production Requirements

1. Set `BILLIONS_ISSUER_DID` to the production Billions issuer DID
2. Set `REQUIRE_PROOF_OF_HUMANITY=true`
3. Configure strong, unique `JWT_SECRET` and `JWT_REFRESH_SECRET`
4. Configure `VERIFIER_ID` with your service's DID
5. Set `BASE_URL` to your public URL
6. Set `ENVIRONMENT=production` (disables `/auth/verify` endpoint)

---

## Testing Options

### Option A: Mock Implementation (Development)

Use the `MockPrivadoVerifier` for local development:

```bash
ENVIRONMENT=development
REQUIRE_PROOF_OF_HUMANITY=false
```

Features:
- Skips real ZK proof verification
- Returns configurable responses (isHuman true/false)
- Works without any external infrastructure
- Supports mock tokens: `mock.{did}` or `mock.jwz.token.{did}`

### Option B: Run Your Own Issuer Node (E2E Testing)

Run a local [Privado ID Issuer Node](https://github.com/0xPolygonID/issuer-node) on Polygon Amoy testnet:

```bash
# Clone issuer-node repo
git clone https://github.com/0xPolygonID/issuer-node
cd issuer-node

# Configure for Amoy testnet
cp .env-issuer.sample .env-issuer
# Edit .env-issuer with your RPC URL (Alchemy/Infura)

# Run with Docker
make run-all-registry

# Access UI at http://localhost:8088
# Create ProofOfHumanity credentials for test users
```

**Amoy testnet config:**
- State contract: `0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124`
- Chain ID: `80002`
- Get test MATIC from [Alchemy faucet](https://www.alchemy.com/faucets/polygon-amoy)

Configure privacy-proxy:
```bash
BILLIONS_ISSUER_DID=did:polygonid:polygon:amoy:...
REQUIRE_PROOF_OF_HUMANITY=true
```

### Option C: Billions Testnet

Billions is in early alpha. Check:
- [Billions signup](https://signup.billions.network/) for testnet access
- Their Discord for developer API access

### Testing Matrix

| Scenario | Implementation | Config |
|----------|---------------|--------|
| Unit tests | MockPrivadoVerifier | `REQUIRE_PROOF_OF_HUMANITY=false` |
| Dev local | MockPrivadoVerifier | `REQUIRE_PROOF_OF_HUMANITY=false` |
| E2E Amoy | Real verifier + own issuer | `BILLIONS_ISSUER_DID=did:polygonid:...` |
| Production | Real verifier + Billions | `BILLIONS_ISSUER_DID=<billions-prod-did>` |

---

## Error Handling

### Authentication Errors

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `session parameter required` | Missing session ID in callback |
| 400 | `jwz_token required` | Missing proof token |
| 401 | `session not found or expired` | Invalid/expired session (10 min TTL) |
| 401 | `JWZ verification failed` | Invalid ZK proof |
| 403 | `humanity_verification_required` | User lacks PoH credential |
| 500 | `VERIFIER_ID not configured` | Missing configuration |

### ETH Linking Errors

| Status | Error | Cause |
|--------|-------|-------|
| 400 | `invalid or expired nonce` | Challenge expired (5 min TTL) |
| 400 | `signature verification failed` | Signature doesn't match address |
| 403 | `challenge does not belong to this user` | Wrong user for challenge |
| 404 | `address not found` | Address not linked to user |

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

| File | Function | Description |
|------|----------|-------------|
| `internal/auth/privado.go:75-110` | `CreateHumanityAuthRequest` | Creates auth request with PoH ZK query |
| `internal/auth/mock_privado.go` | `MockPrivadoVerifier` | Mock verifier for testing |
| `internal/auth/eth_signature.go` | `VerifyAddressOwnership` | EIP-191 signature verification |
| `internal/server/auth.go:50-88` | `handleAuthRequest` | Auth request handler with PoH support |
| `internal/server/auth.go:185-250` | `verifyAndIssueTokens` | Token issuance with PoH failure handling |
| `internal/server/eth_link.go` | `handleEthLinkChallenge` | ETH linking challenge endpoint |
| `internal/server/eth_link.go` | `handleEthLinkVerify` | ETH linking verification endpoint |
| `internal/db/db.go:440-550` | ETH link methods | Database operations for ETH links |

---

## Migration

### New Migration: 002_eth_address_linking.sql

Creates the `eth_address_links` table for storing verified ETH address links:

```sql
CREATE TABLE eth_address_links (
    id SERIAL PRIMARY KEY,
    did VARCHAR(255) NOT NULL,
    eth_address VARCHAR(42) NOT NULL,
    signature VARCHAR(512) NOT NULL,
    message_hash VARCHAR(66) NOT NULL,
    verified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP,
    UNIQUE(eth_address)
);
```

The migration runs automatically on server startup.
