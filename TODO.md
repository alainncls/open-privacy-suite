# TODO

## In Progress

## Blocked

## Backlog

### Critical Priority

- [ ] **Implement database transactions** - No transaction support exists; multi-operation scenarios (contract + grant creation) can leave orphaned data

### High Priority - Architecture

- [ ] **Split oversized files** (violate 300-line CLAUDE.md standard):
  - `rbac_store.go` (1,294 lines) → Split into user_store.go, contract_store.go, group_store.go, cache_store.go
  - `admin_rbac.go` (896 lines) → Split by resource type (handler_users.go, handler_groups.go, etc.)
  - `auth.go` (501 lines) → Separate request/callback handlers from token issuance
  - `server.go` (595 lines) → Extract router setup, middleware configuration
- [ ] **Replace panics with error propagation** - `server.go:75-98` panics on DB/JWT/Privado init errors instead of returning errors
- [ ] **Fix context leakage** - `auth.go:281,302` uses `context.Background()` instead of request context; no timeout propagation
- [ ] **Extract business logic from HTTP handlers** - `handleJSONRPC` (server.go:248-337) has 50+ lines of business logic; untestable without HTTP context
- [ ] **Add missing interface abstractions** - SessionStore, RateLimiter not behind interfaces; tight coupling

### High Priority - Database

- [ ] **Fix token operations context usage** - `db.go:154-309` uses `Exec()`/`Query()` instead of `*Context()` variants; no cancellation support
- [ ] **Add batch contract loading** - `resolver.go:336-354` fetches contracts individually in loop (N+1 pattern)
- [ ] **Add database close to graceful shutdown** - `server.Stop()` manages other components but not DB connection

### High Priority - Security

- [ ] **Add rate limiting to auth endpoints** - `/auth/request`, `/auth/callback`, `/auth/verify` have no rate limiting (brute force vector)
- [ ] **Implement API versioning** - No version prefix exists; impossible to deprecate endpoints gracefully
- [ ] **Add access token revocation checking** - Only refresh tokens checked against revocation; access tokens valid 30 min after logout
- [ ] **Validate production config strictly** - JWT secrets auto-generate if empty; should error in production

### High Priority - Frontend

- [ ] **Consolidate API client configuration** - Three separate axios instances; no interceptors for auth/error handling
- [ ] **Migrate to React Query** - Dashboard/AccessLogs use raw fetch instead of React Query; no request deduplication
- [ ] **Add global error handling UI** - Components use `alert()` or `console.error()`; no toast notification system
- [ ] **Extract repeated component patterns** - DataTable, FormDialog, EmptyState patterns duplicated 5+ times

### Medium Priority - Code Quality

- [ ] **Extract HTTP error response helpers** - 47 repeated `c.JSON(http.StatusX, gin.H{"error": ...})` patterns in admin_rbac.go
- [ ] **Extract magic numbers to constants** - TTLs (30min, 7day, 5min, 10min, 10sec) hardcoded in server.go
- [ ] **Standardize error message format** - Mix of generic, specific, and contextless error messages
- [ ] **Add pagination to ListGroups/ListContracts** - Currently return ALL records; no limit/offset support

### Medium Priority - Testing

- [ ] **Create shared `internal/testutil` package** - 4 files duplicate ~150 lines of DB setup logic
- [ ] **Add missing unit tests** - No tests for `eth_link.go`, incomplete `admin_rbac_test.go`, minimal `proxy_test.go`
- [ ] **Add coverage enforcement in CI** - Coverage generated but no failure threshold
- [ ] **Refactor pre-commit hooks** - Runs full test suite (slow); switch to husky + lint-staged

### Low Priority

- [ ] **Replace manual LRU with proper data structure** - `cache.go:235-241` uses O(n) slice removal for access order
- [ ] **Optimize RPS window check** - `ratelimit.go:84-91` iterates all timestamps (O(60) per request)
- [ ] **Add request tracing/correlation IDs** - No X-Request-ID middleware for log correlation
- [ ] **Lazy load Wagmi in frontend** - Heavy Ethereum library (~200KB) loaded for all routes
- [ ] **Add godoc comments to handlers** - Most handlers lack documentation
- [ ] **Remove alias methods in rbac_store.go** - `SetGroupAccess`, `ListContractGrants`, `ListContractGrantsForGroup` are unnecessary wrappers

## Done (Recent)
- [x] **Fix query parameter parsing bug** - Fixed `admin_rbac.go:680-683`; now uses strconv.Atoi to parse limit/offset query params
- [x] **Add rows.Err() checks** - Added error checks after all 9 row iteration loops in `rbac_store.go`
- [x] **Fix unlimited body read in auth.go** - Added 1MB limit using io.LimitReader to prevent DoS
- [x] **Configure connection pool** - Added SetMaxOpenConns(25), SetMaxIdleConns(5), SetConnMaxLifetime(5min) to db.go
- [x] **Backend mock mode for demos** - Added `MOCK_SIGNATURES=true` env var to skip wallet signature verification. Also added mock auth session support when `VERIFIER_ID` is not configured. Both are development-only with prominent warnings. Demo recording now works end-to-end.
- [x] **Demo creation system** - Reviewed and fixed. Added missing `__init__.py` files, fixed PYTHONPATH in Makefile, added comprehensive README, updated auth-flow.yaml config for robustness.
- [x] **Frontend accessibility & polish overhaul** - Comprehensive UI/UX improvements:
  - Improved color contrast (WCAG AA compliance): `--text-secondary` 75%→85%, `--text-muted` 60%→70%
  - Fixed focus states: Changed `focus:` to `focus-visible:` across input, select, and glass components
  - Added `prefers-reduced-motion` support to disable animations for users who prefer reduced motion
  - Added ARIA labels and attributes: QR code, loading spinners, collapsible sections, live status indicators
  - Added screen reader support: `role="status"`, `aria-live="polite"`, `sr-only` text for color-only information
  - Fixed scope dropdown truncation: Widened from 220px to 280px
  - Improved text contrast consistency across card, tabs, and status components
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
