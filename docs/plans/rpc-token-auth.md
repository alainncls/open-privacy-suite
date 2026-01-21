# Plan: URL Token RPC Authentication for MetaMask

## Goal
Allow MetaMask users to use the privacy proxy without bearer tokens, while maintaining security for sensitive on-chain data.

## Why URL Tokens (Not Address-Based Auth)

**Security requirement:** Sensitive data is stored on-chain - unauthorized reads must be blocked.

**Problem with address-based auth:** The `from` field in `eth_call` is trivially spoofable. Anyone could send `eth_call(from: "0xVictim")` and gain victim's read permissions. This is unacceptable for sensitive data.

**Solution:** URL-embedded tokens provide cryptographic authentication for ALL requests (reads and writes).

## User Flow

1. User logs in via Privado ID (existing)
2. User navigates to "RPC Settings" page
3. Portal displays: **"Your RPC URL: `https://proxy.example.com/rpc/abc123...`"**
4. User copies URL into MetaMask as custom RPC network
5. All requests authenticated via token in URL path
6. User gets privacy features - secure and relatively transparent

## Implementation

### 1. New RPC Token Type
**File:** `internal/auth/jwt.go`

Create a dedicated "RPC token" with longer TTL (standard JWTs expire in 30 min - too short for MetaMask):

```go
const (
    RPCTokenTTL = 7 * 24 * time.Hour // 7 days
)

type RPCTokenClaims struct {
    jwt.RegisteredClaims
    Subject string `json:"sub"` // User's DID
    Type    string `json:"type"` // "rpc" to distinguish from access tokens
}

func (s *JWTService) GenerateRPCToken(subject string) (string, error) {
    claims := RPCTokenClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(RPCTokenTTL)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            ID:        uuid.New().String(),
        },
        Subject: subject,
        Type:    "rpc",
    }
    // Sign with dedicated RPC secret (separate from access/refresh secrets)
    return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.rpcSecret)
}
```

### 2. RPC Token Management Endpoints
**File:** `internal/server/rpc_tokens.go` (new file)

```go
// POST /rpc-tokens - Generate new RPC token
func (s *Server) handleCreateRPCToken(c *gin.Context) {
    subject := c.GetString("subject") // From JWT middleware

    token, err := s.jwt.GenerateRPCToken(subject)
    if err != nil {
        c.JSON(500, gin.H{"error": "failed to generate token"})
        return
    }

    // Store token hash for revocation tracking
    s.db.StoreRPCToken(subject, hashToken(token), time.Now().Add(RPCTokenTTL))

    c.JSON(200, gin.H{
        "token": token,
        "rpc_url": fmt.Sprintf("%s/rpc/%s", s.config.BaseURL, token),
        "expires_at": time.Now().Add(RPCTokenTTL),
    })
}

// GET /rpc-tokens - List user's RPC tokens
func (s *Server) handleListRPCTokens(c *gin.Context) {
    subject := c.GetString("subject")
    tokens, _ := s.db.GetRPCTokensByDID(subject)
    c.JSON(200, gin.H{"tokens": tokens})
}

// DELETE /rpc-tokens/:id - Revoke an RPC token
func (s *Server) handleRevokeRPCToken(c *gin.Context) {
    subject := c.GetString("subject")
    tokenID := c.Param("id")
    s.db.RevokeRPCToken(subject, tokenID)
    c.JSON(200, gin.H{"message": "token revoked"})
}
```

### 3. URL-Based RPC Endpoint
**File:** `internal/server/server.go`

```go
// Public RPC endpoint with token in URL path
r.POST("/rpc/:token", s.handleTokenRPC)

func (s *Server) handleTokenRPC(c *gin.Context) {
    token := c.Param("token")

    // Validate RPC token
    claims, err := s.jwt.ValidateRPCToken(token)
    if err != nil {
        c.JSON(401, jsonRPCError(-32000, "Invalid or expired RPC token"))
        return
    }

    // Check revocation
    if s.db.IsRPCTokenRevoked(hashToken(token)) {
        c.JSON(401, jsonRPCError(-32000, "RPC token has been revoked"))
        return
    }

    // Continue with standard RPC handling
    s.handleRPCWithAuth(c, claims.Subject)
}

// Shared RPC handler (used by both bearer auth and URL token auth)
func (s *Server) handleRPCWithAuth(c *gin.Context, userDID string) {
    // Read body, parse JSON-RPC, apply RBAC, forward to node
    // (extracted from existing handleJSONRPC logic)
}
```

### 4. Database Schema for RPC Tokens
**File:** `internal/db/migrations/XXX_rpc_tokens.sql`

```sql
CREATE TABLE rpc_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    did VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hash
    name VARCHAR(255),                        -- Optional friendly name
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX idx_rpc_tokens_did ON rpc_tokens(did);
CREATE INDEX idx_rpc_tokens_hash ON rpc_tokens(token_hash);
```

### 5. Frontend: RPC Settings Page
**File:** `frontend/src/pages/RPCSettingsPage.tsx` (new file)

```tsx
export function RPCSettingsPage() {
    const [tokens, setTokens] = useState<RPCToken[]>([]);
    const [rpcUrl, setRpcUrl] = useState<string>("");

    const generateToken = async () => {
        const response = await api.post('/rpc-tokens');
        setRpcUrl(response.data.rpc_url);
        // Show copy-to-clipboard UI
    };

    return (
        <div>
            <h1>RPC Settings</h1>
            <p>Use this URL to connect MetaMask to the privacy proxy:</p>

            {rpcUrl ? (
                <CopyableInput value={rpcUrl} />
            ) : (
                <Button onClick={generateToken}>Generate RPC URL</Button>
            )}

            <h2>Active Tokens</h2>
            <TokenList tokens={tokens} onRevoke={handleRevoke} />
        </div>
    );
}
```

### 6. Config Updates
**File:** `internal/config/config.go`

```go
type Config struct {
    // ... existing fields ...
    RPCTokenSecret string        `env:"RPC_TOKEN_SECRET"`
    RPCTokenTTL    time.Duration `env:"RPC_TOKEN_TTL" envDefault:"168h"` // 7 days
    BaseURL        string        `env:"BASE_URL"` // For generating full RPC URLs
}
```

## Files to Modify/Create

| File | Action | Purpose |
|------|--------|---------|
| `internal/auth/jwt.go` | Modify | Add RPC token generation/validation |
| `internal/server/server.go` | Modify | Add `/rpc/:token` endpoint, refactor shared handler |
| `internal/server/rpc_tokens.go` | Create | RPC token management endpoints |
| `internal/db/migrations/XXX_rpc_tokens.sql` | Create | RPC tokens table |
| `internal/db/db.go` | Modify | Add RPC token DB operations |
| `internal/config/config.go` | Modify | Add RPC token config fields |
| `frontend/src/pages/RPCSettingsPage.tsx` | Create | Token management UI |
| `frontend/src/api/rpc.ts` | Create | RPC token API client |

## Testing Plan

1. **Unit tests:**
   - `GenerateRPCToken()` / `ValidateRPCToken()`
   - Token hash generation
   - Token expiry validation

2. **Integration tests:**
   - `POST /rpc-tokens` → generates valid token
   - `GET /rpc-tokens` → lists user's tokens
   - `DELETE /rpc-tokens/:id` → revokes token
   - `POST /rpc/{valid_token}` with `eth_call` → returns data
   - `POST /rpc/{invalid_token}` → returns 401
   - `POST /rpc/{revoked_token}` → returns 401
   - `POST /rpc/{expired_token}` → returns 401

3. **E2E test with MetaMask:**
   - Login via Privado ID
   - Generate RPC token from settings page
   - Configure MetaMask with generated URL
   - Execute `eth_call` → verify it works
   - Execute transaction → verify it works
   - Revoke token → verify MetaMask gets 401

## Security Considerations

- ✅ All requests (reads AND writes) authenticated via cryptographic token
- ✅ No address spoofing possible - token proves identity
- ✅ RPC tokens use separate secret from access/refresh tokens
- ✅ Token revocation supported (check hash against DB)
- ✅ Existing RBAC checks still apply (KYC, contract allowlists, rate limits)
- ✅ Batch requests already blocked
- ⚠️ Tokens in URLs can be logged - use HTTPS only
- ✅ 7-day TTL balances security with usability - weekly regeneration

## Optional Future Enhancements

1. **Token naming** - Let users name tokens (e.g., "MetaMask Desktop", "Mobile Wallet")
2. **Last used tracking** - Show when each token was last used
3. **Configurable TTL** - Let users choose shorter TTL for higher security
4. **IP binding** - Optionally bind token to IP range
5. **Usage analytics** - Show requests made per token
