# TODO Now

Work through these items one at a time.

## High Priority

- [x] Extract business logic from HTTP handlers - Created `jsonrpc_processor.go` with `JSONRPCProcessor` struct, `AccessLogger` interface, and separated parsing/validation from RBAC/rate-limiting/forwarding logic
- [x] Add missing interface abstractions - Added `SessionManager` and `RateLimiterInterface` in `interfaces.go`
- [x] Add batch contract loading - Added `GetContractsByIDs` to store interface and refactored resolver to batch load contracts
- [x] Add rate limiting to auth endpoints - Added `AuthRateLimiter` with IP-based sliding window (10 req/min default)

## Medium Priority

- [x] Extract HTTP error response helpers - Added `http_responses.go` with helper functions, refactored `admin_rbac_org.go` as example
- [x] Add pagination to ListGroups/ListContracts - Added `ListGroupsPaginated` and `ListContractsPaginated` with limit/offset/total
- [x] Create shared `internal/testutil` package - Added `SetupTestDB` and `SetupTestDBWithMigrations` helpers
