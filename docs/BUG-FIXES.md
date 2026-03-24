# Resilience Audit — Bug Fix Prompt

## Context

The resilience audit (PR #64, branch `test/resilience-audit`) found 4 bugs documented as skipped tests. These fixes should be applied to the privacy-proxy main codebase. After fixing, unskip the corresponding tests in `internal/server/resilience_test.go` and `resilience_tier2_test.go` to verify.

---

## Bug 1: Empty ADMIN_API_TOKEN bypasses admin auth

**Severity:** Critical
**File:** `internal/server/server.go` lines 805-809
**Skipped tests:** `TestResilience_EmptyAdminToken_RejectsRequests`, `TestResilience_EmptyAdminToken_EmptyHeaderDenied`

### Current behavior

```go
// Path 3: No credentials supplied
if expectedToken == "" {
    // Dev mode: no token configured, allow through
    c.Next()
    return
}
```

When `ADMIN_API_TOKEN` is empty, the middleware allows unauthenticated requests through to all admin endpoints. There is no environment check — this applies in production too.

### Required fix

Add an environment guard. In production, reject if no token is configured. In development, the current pass-through is acceptable but should log a warning.

```go
if expectedToken == "" {
    if s.config.IsProduction() {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
        c.Abort()
        return
    }
    // Dev mode: allow through but warn
    slog.Warn("admin API request allowed without token — ADMIN_API_TOKEN not configured")
    c.Next()
    return
}
```

Also consider adding `ADMIN_API_TOKEN` to `config.Validate()` as required in production.

---

## Bug 2: Session delete with nil sessionStore → panic

**Severity:** High
**File:** `internal/server/admin_rbac_session.go` lines 23-24 and 52
**Skipped test:** `TestResilience_AdminHandlers_NoErrorLeakage` case "delete nonexistent session"

### Current behavior

`listSessions` and `deleteSession` call `s.sessionStore.ListSessions()` and `s.sessionStore.GetSession()` without nil-checking `sessionStore`. When the server starts without Privado auth configured, `sessionStore` is nil, and any request to the session admin endpoints causes a nil pointer dereference panic.

### Required fix

Nil-check at the top of both handlers:

```go
func (s *Server) listSessions(c *gin.Context) {
    if s.sessionStore == nil {
        respondOK(c, SessionListResponse{Sessions: []*sessionInfoResponse{}, Total: 0})
        return
    }
    // ... existing code
}

func (s *Server) deleteSession(c *gin.Context) {
    if s.sessionStore == nil {
        respondNotFound(c, "session management not available")
        return
    }
    // ... existing code
}
```

---

## Bug 3: Group creation with nonexistent org leaks PostgreSQL SQLSTATE

**Severity:** Medium
**File:** `internal/server/admin_rbac_group.go` line 77 (and similar in other admin handlers)
**Skipped test:** `TestResilience_AdminHandlers_NoErrorLeakage` case "create group missing org"

### Current behavior

```go
if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
    return
}
```

When a group is created referencing a nonexistent `org_id`, the DB returns a foreign key constraint violation. `err.Error()` contains `SQLSTATE 23503`, constraint names, and table structure — all leaked in the HTTP response.

### Required fix

Detect FK/unique constraint violations and return appropriate status codes with generic messages. Apply this pattern across admin handlers:

```go
if err != nil {
    if isNotFoundError(err) {
        respondNotFound(c, "organization not found")
        return
    }
    if isForeignKeyViolation(err) {
        respondBadRequest(c, "referenced resource does not exist")
        return
    }
    if isUniqueViolation(err) {
        respondConflict(c, "resource already exists")
        return
    }
    slog.Error("failed to create group", "error", err, "org_id", orgID)
    respondInternalError(c, "request failed")
    return
}
```

Helper using pgx error codes:

```go
import "github.com/jackc/pgx/v5/pgconn"

func isForeignKeyViolation(err error) bool {
    var pgErr *pgconn.PgError
    return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func isUniqueViolation(err error) bool {
    var pgErr *pgconn.PgError
    return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
```

Scan all admin handlers for `err.Error()` in HTTP responses — there are approximately 10 instances beyond the group handler.

---

## Bug 4: ~60 explorer endpoints leak err.Error() in HTTP responses

**Severity:** Medium
**File:** `internal/server/explorer_api.go` — 63 instances
**Related test:** `TestResilience_ExplorerErrors_NoInternalLeakage` (documents the gap)

### Current behavior

Throughout `explorer_api.go`:

```go
respondInternalError(c, "failed to look up DID: "+err.Error())
respondInternalError(c, err.Error())
respondInternalError(c, "redaction failed: "+err.Error())
```

These leak DB driver names (pgx), connection details, SQL state codes, file paths, and internal function names.

### Required fix

Systematic replacement across `explorer_api.go`:

1. Log the real error server-side:
   ```go
   slog.Error("failed to look up DID", "error", err, "request_id", correlation.GetRequestID(c))
   ```

2. Return a generic message to the client:
   ```go
   respondInternalError(c, "request failed")
   ```

For `respondBadRequest` calls that include `err.Error()` (e.g. JSON parse errors), these are usually safe but should still be reviewed — replace with specific validation messages where the error comes from user input.

### Scope

Search for this pattern across all handler files, not just `explorer_api.go`:

```
grep -n 'err\.Error()' internal/server/*.go | grep -E 'respond|JSON.*error'
```

Estimated: ~63 in explorer_api.go, ~10 in admin handlers, ~5 in auth handlers.

---

## Verification

After applying fixes, run the resilience tests:

```bash
go test ./internal/server/... -run "TestResilience_" -v -count=1
```

The 4 skipped tests should now be unskipped and passing. The `assertNoInternalErrorLeakage` helper in `resilience_test.go` checks for: `sql:`, `pq:`, `pgx:`, `connection refused`, `dial tcp`, `no rows`, `sqlstate`, `stack trace`, `goroutine`, `runtime error`, `panic:`, `open /`, `/home/`, `/usr/`.
