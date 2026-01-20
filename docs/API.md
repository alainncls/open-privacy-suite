# API Reference

## Authentication Endpoints

### POST /auth/request
Initiates Privado ID authentication flow.

**Response:**
```json
{
  "session_id": "uuid",
  "auth_request": { /* Privado authorization request */ }
}
```

### POST /auth/callback?session={session_id}
Wallet callback endpoint for ZK proof submission.

**Body:** JWZ token (raw)

**Response:**
```json
{
  "access_token": "jwt",
  "refresh_token": "jwt",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

### POST /auth/verify
Manual proof submission (development only).

**Body:**
```json
{
  "session_id": "uuid",
  "jwz_token": "token"
}
```

### POST /refresh
Refresh access token.

**Body:**
```json
{
  "refresh_token": "jwt"
}
```

### POST /revoke
Revoke refresh token.

**Body:**
```json
{
  "refresh_token": "jwt"
}
```

### GET /health
Health check. Returns `{"status": "ok"}`.

---

## JSON-RPC Proxy

### POST /
Forward JSON-RPC request to Ethereum node.

**Headers:** `Authorization: Bearer <access_token>`

**Body:**
```json
{
  "jsonrpc": "2.0",
  "method": "eth_call",
  "params": [...],
  "id": 1
}
```

**Access Control:**
- Validates JWT
- Checks user KYC status and ban flag
- Validates method against allowlist
- Validates contract address (if applicable)
- Enforces rate limits

---

## ETH Address Linking (JWT Required)

### POST /eth/link/challenge
Request signing challenge.

**Response:**
```json
{
  "nonce": "hex",
  "message": "message to sign"
}
```

### POST /eth/link/verify
Submit signed challenge.

**Body:**
```json
{
  "nonce": "hex",
  "address": "0x...",
  "signature": "0x..."
}
```

### GET /eth/addresses
List linked addresses.

**Response:**
```json
{
  "addresses": [
    {"address": "0x...", "verified_at": "timestamp"}
  ]
}
```

### DELETE /eth/addresses/:address
Unlink address.

---

## Admin API (Localhost Only)

### GET /api/logs?limit=N
Retrieve access logs.

### GET /api/status
Proxy and node health status.

### POST /api/test-request
Test method access for a user.

**Body:**
```json
{
  "user_id": "did:...",
  "method": "eth_call"
}
```

---

## RBAC Admin API (Localhost Only)

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs | List organizations |
| POST | /api/orgs | Create organization |
| GET | /api/orgs/:id | Get organization |
| PUT | /api/orgs/:id | Update organization |

**Create/Update Body:**
```json
{
  "slug": "myorg",
  "name": "My Organization",
  "settings": {}
}
```

### Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/groups | List groups |
| POST | /api/orgs/:org_id/groups | Create group |
| GET | /api/orgs/:org_id/groups/:id | Get group |
| PUT | /api/orgs/:org_id/groups/:id | Update group |
| DELETE | /api/orgs/:org_id/groups/:id | Delete group |
| GET | /api/orgs/:org_id/groups/:id/permissions | Get permissions |
| PUT | /api/orgs/:org_id/groups/:id/permissions | Set permissions |

**Create Group:**
```json
{
  "slug": "engineering",
  "name": "Engineering",
  "parent_id": "uuid"  // optional
}
```

**Set Permissions:**
```json
{
  "allow_methods": ["eth_call", "eth_getBalance"],
  "allow_contracts": ["0x..."],
  "owned_contracts": ["0x..."],
  "rate_limit_rps": 100,
  "rate_limit_daily": 10000
}
```

### Roles

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/roles | List roles |
| POST | /api/orgs/:org_id/roles | Create role |
| GET | /api/orgs/:org_id/roles/:id | Get role |
| PUT | /api/orgs/:org_id/roles/:id | Update role |
| DELETE | /api/orgs/:org_id/roles/:id | Delete role |

**Body:**
```json
{
  "name": "deployer",
  "claims": ["reader", "writer", "deployer"]
}
```

**Available Claims:** `reader`, `writer`, `deployer`, `admin`, `upgrade`

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/users | List users |
| GET | /api/users/:id | Get user |
| PUT | /api/users/:id | Update user |
| GET | /api/users/:id/memberships | List memberships |
| POST | /api/users/:id/memberships | Create membership |
| DELETE | /api/users/:id/memberships/:mid | Delete membership |

**Update User:**
```json
{
  "kyc": true,
  "banned": false
}
```

**Create Membership:**
```json
{
  "group_id": "uuid",
  "role_id": "uuid",
  "expires_at": "timestamp"  // optional
}
```

### Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/contracts | List contracts |
| POST | /api/orgs/:org_id/contracts | Create contract |
| PUT | /api/orgs/:org_id/contracts/:addr | Update contract |
| DELETE | /api/orgs/:org_id/contracts/:addr | Delete contract |

**Body:**
```json
{
  "contract_address": "0x...",
  "owner_group_id": "uuid",
  "owner_abilities": ["upgrade", "pause", "admin"]
}
```

### Debugging

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/users/:id/effective-permissions | Computed permissions |
| POST | /api/access/check | Test access decision |
| GET | /api/cache/stats | Cache statistics |

**Access Check Body:**
```json
{
  "user_id": "did:...",
  "method": "eth_call",
  "contract_address": "0x..."
}
```

---

## Error Responses

All errors return:
```json
{
  "error": "error_code",
  "message": "Human readable message"
}
```

**Common Status Codes:**
- `400` - Bad request / validation error
- `401` - Missing or invalid authentication
- `403` - Forbidden (banned, no KYC, method not allowed)
- `404` - Resource not found
- `429` - Rate limit exceeded
- `500` - Internal server error
