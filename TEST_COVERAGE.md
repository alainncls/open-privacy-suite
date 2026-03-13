# Test Coverage Summary

## Unit Tests

### ✅ Database Layer (`internal/db`)
- `TestSetAndGetPolicy` - Create and retrieve policies
- `TestGetPolicy_NotFound` - Handle missing policies
- `TestListPolicies` - List all policies
- `TestLogAccess` - Log access attempts and retrieve logs
- `TestSaveRefreshToken` - Save refresh tokens
- `TestGetRefreshToken_NotFound` - Handle missing refresh tokens
- `TestRevokeRefreshToken` - Revoke refresh tokens
- `TestRevokeAccessToken` - Revoke access tokens
- `TestIsAccessTokenRevoked_NotRevoked` - Check token revocation status
- `TestCleanupExpiredTokens` - Cleanup expired tokens

**Coverage**: CRUD operations, JSON handling, error cases, token management
**Note**: Uses real PostgreSQL via testcontainers (tests database layer)

### ✅ Access Control (`internal/access`)
- `TestCheckAccess` - Method whitelisting
  - Allowed methods pass
  - Disallowed methods fail
  - Non-existent users fail
- `TestCheckAccess_Banned` - Ban enforcement
- `TestCheckAccess_KYCRequired` - KYC enforcement
- `TestCheckAccess_DatabaseError` - Error handling

**Coverage**: All access control logic, KYC, bans, method whitelisting
**Note**: Uses mock PolicyStore (no PostgreSQL required for business logic tests)

### ✅ Proxy (`internal/proxy`)
- `TestParseMethod` - JSON-RPC method extraction
  - Valid requests
  - Invalid JSON
  - Missing method
- `TestForward` - Request forwarding to node

**Coverage**: JSON-RPC parsing, request forwarding

### ✅ Authentication (`internal/auth`)
- `TestJWTService_IssueAccessToken` - JWT token issuance
- `TestJWTService_ValidateAccessToken` - Token validation
- `TestJWTService_ValidateAccessToken_Expired` - Expired token handling
- `TestJWTService_ValidateAccessToken_Invalid` - Invalid token handling
- `TestJWTService_IssueRefreshToken` - Refresh token issuance
- `TestJWTService_ValidateRefreshToken` - Refresh token validation
- `TestJWTAuthMiddleware_ValidToken` - Middleware with valid token
- `TestJWTAuthMiddleware_MissingToken` - Missing token handling
- `TestJWTAuthMiddleware_InvalidToken` - Invalid token handling
- `TestJWTAuthMiddleware_ExpiredToken` - Expired token handling
- `TestJWTAuthMiddleware_RevokedToken` - Revoked token handling
- `TestPrivadoVerifier_NewPrivadoVerifier` - Verifier initialization
- `TestPrivadoVerifier_VerifyJWZ_InvalidToken` - Invalid token handling
- **Note**: Unit tests use mocks, but production code uses real Privado ID verification via `go-iden3-auth`

**Coverage**: JWT issuance/validation, refresh tokens, middleware, Privado ID verification

### ✅ Server (`internal/server`)
- `TestLocalhostOnlyMiddleware` - Management API protection
  - Localhost IPv4 allowed
  - Localhost IPv6 allowed
  - External IPs blocked
- `TestListPolicies_LocalhostOnly` - Policy listing protection
- `TestCreatePolicy_LocalhostOnly` - Policy creation protection
- `TestHandleAuth_Success` - Authentication endpoint (JWZ → JWT)
- `TestHandleAuth_InvalidRequest` - Invalid auth request handling
- `TestHandleAuth_VerificationFailure` - JWZ verification failure
- `TestHandleRefresh_Success` - Token refresh with rotation
- `TestHandleRefresh_InvalidToken` - Invalid refresh token
- `TestHandleRefresh_RevokedToken` - Revoked refresh token
- `TestHandleRevoke` - Token revocation

**Coverage**: Localhost-only middleware, API protection, authentication endpoints

## E2E Tests

### ✅ Full Request Flow (`e2e/`)
- `TestE2E_AuthorizedRequest` - Successful authorized request
- `TestE2E_UnauthorizedRequest_NoToken` - Missing token (401)
- `TestE2E_ForbiddenRequest_DisallowedMethod` - Method not allowed (403)
- `TestE2E_BannedUser` - Banned user (403)
- `TestE2E_NoKYC` - Non-KYC user (403)

**Coverage**: Complete request flow from client to node, all error cases

## Test Execution

### Prerequisites
- **For database layer tests**: PostgreSQL (via testcontainers - automatic) or external PostgreSQL
- **For business logic tests**: No database required (uses mocks)
- **For E2E tests**: PostgreSQL and mock Erigon node running on port 8545

### Running Tests

```bash
# All unit tests
go test ./internal/... -v

# All E2E tests (requires mock node)
cd e2e/mock-node && npm start &
go test ./e2e/... -v

# Specific package
go test ./internal/access/... -v

# With coverage
go test ./internal/... -cover
```

### Test Database Setup

Tests use separate databases:
- Unit tests: `privacy_proxy_test`
- E2E tests: `privacy_proxy_e2e_test`

Set `TEST_DATABASE_URL` environment variable to override:
```bash
export TEST_DATABASE_URL="postgres://user:pass@localhost:5432/custom_test_db?sslmode=disable"
```

## Coverage by Feature

### ✅ Core Features
- [x] Identity resolution (mocked)
- [x] Policy lookup
- [x] KYC enforcement
- [x] Method whitelisting
- [x] Ban/unban
- [x] Access logging
- [x] Request forwarding
- [x] Management API (localhost-only)

### ✅ Error Handling
- [x] Missing Authorization header
- [x] Invalid token format
- [x] Non-existent user
- [x] Banned user
- [x] Non-KYC user
- [x] Disallowed method
- [x] External access to management API

### ✅ Edge Cases
- [x] Empty token
- [x] Invalid JSON-RPC
- [x] Missing method in JSON-RPC
- [x] Policy not found
- [x] Database errors

## Test Quality

- **Isolation**: Each test uses fresh database state
- **Reproducibility**: Tests can run in any order
- **Coverage**: All critical paths tested
- **E2E**: Full integration tests verify end-to-end flow

## Test Architecture

### Business Logic Tests (No Database)
- `internal/access` - Uses mock `PolicyStore` interface
- Fast execution, no Docker required
- Tests pure business logic (KYC checks, method whitelisting, bans)

### Database Layer Tests (Real PostgreSQL)
- `internal/db` - Uses testcontainers or external PostgreSQL
- Tests actual SQL queries, schema, data persistence
- Verifies PostgreSQL-specific features (JSONB, indexes, etc.)

### Integration Tests
- `internal/server` - Tests HTTP endpoints with real database
- `e2e/` - Full stack tests with mock services

## Next Steps

For Privado ID testing improvements:
1. Add integration tests with real Privado ID JWZ proofs (currently only unit tests with mocks)
2. Test error cases (network failures, invalid proofs, expired proofs)
3. Add circuit breaker and retry logic tests
4. Test with different Privado network configurations
