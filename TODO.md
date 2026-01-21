# TODO

## In Progress

## Blocked

## Backlog

### Architecture Concerns (Non-Critical)
- [ ] **Distributed Deployment** - In-memory stores won't work across multiple instances:
  - `SessionStore` - Auth sessions won't be shared
  - `RateLimiter` - Rate limits won't be enforced across instances
  - `ChallengeStore` - Link challenges won't be shared
  - `rbac.Cache` - Each instance has its own cache (DB cache helps but adds latency)
  - Recommendation: Document single-instance limitation or add Redis support

### Review Needed
- [ ] **Demo creation system** - Review `demos/` folder and `make demo-*` targets for completeness and usefulness
- [ ] **Bridge testing** - review the bridge and ensure that e2e tests and manual testing show that it is fully functional with post-verification on-chain of the bridging activity

## Done (Recent)
- [x] **Default Org bypass verification** - Confirmed intentional behavior (`rbac/access.go:311-315`), added clarifying comment
- [x] **Frontend test coverage** - Added comprehensive tests for SuccessPage and LinkWalletPage (113 total tests now passing)
- [x] **ENS resolution tests** - Added unit tests for namehash algorithm in `internal/ens/resolver_test.go`
- [x] **Concurrent access tests** - Added `TestCacheConcurrency` and `TestCacheConcurrentEviction` to `internal/rbac/cache_test.go`
- [x] **Error response formats** - Reviewed and confirmed consistent pattern:
  - Standard errors: `gin.H{"error": message}`
  - Humanity verification: Structured `HumanityVerificationError` with `verify_url` (intentional for frontend redirect)
  - Success messages: `gin.H{"message": message}` for delete/revoke operations
- [x] **Auth race condition fix** - Fixed SuccessPage and LinkWalletPage to check `isLoading` before redirecting
- [x] **Graceful shutdown** - Added signal handling to main.go, Stop() methods to all cleanup goroutines
- [x] **HTTP client timeouts** - Added 30s timeout to proxy HTTP client
- [x] **CORS configuration** - Made CORS origins configurable via CORS_ALLOWED_ORIGINS env var
- [x] **IPv6 hostname parsing** - Added clarifying comments (logic was correct)
- [x] **Rate limiter stats** - Fixed RPSWindowEntries to count total timestamps, not users
- [x] **Silent error handling** - Added logging for all `_ = err` patterns
- [x] **Hardcoded UUIDs** - Extracted to DefaultOrgID/DefaultGroupID constants in rbac/models.go
- [x] **SessionStore limits** - Added max sessions limit (10000) with capacity error handling
- [x] **Address validation** - Added IsValidAddress() function and validation in endpoints
- [x] **Duplicate ETH endpoints** - Documented purpose (/api/eth/* for proxy, /eth/* for direct access)
- [x] RBAC system redesigned to contract-centric model with claims (read, write, admin, upgrade, deploy)
- [x] Hierarchical group permissions with materialized paths
- [x] Org admin groups get all claims on all contracts
- [x] Rate limiting with per-user RPS and daily limits
- [x] ETH address linking with EIP-191 signature verification
- [x] ENS name resolution and caching
- [x] Comprehensive E2E test suite (21 test files, 131+ tests)
- [x] Multicall detection and blocking for security
- [x] Global blocked methods list (debug, admin, personal, miner, txpool namespaces)
- [x] LRU eviction for RBAC cache when at capacity

## Notes

### Code Quality Standards Met
- Unit tests exist for critical paths (JWT, auth, RBAC, rate limiting, sessions, ENS)
- Frontend tests cover LoginPage, SuccessPage, LinkWalletPage, AuthContext, API methods
- E2E tests cover RBAC scenarios comprehensively
- Interfaces used appropriately (PrivadoVerifier, Store)
- Clean separation of concerns (auth, rbac, proxy, db packages)
- All cleanup goroutines have Stop() methods and are called on shutdown
- Proper error logging instead of silent suppression
- Thread-safe concurrent access for caches and stores (verified with race detector tests)

### Areas That Look Good
- RBAC permission resolution algorithm is well-documented
- Cache stampede prevention with single-flight pattern
- Token rotation on refresh (security best practice)
- Request body size limits on JSON-RPC endpoint
- Batch request blocking for security
- Graceful shutdown with 10s timeout for in-flight requests
