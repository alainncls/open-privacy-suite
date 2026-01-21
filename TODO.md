# Code Review Findings

## Security Issues

### 1. Overly Permissive CORS (`server/server.go:129`)
Allows any origin to access the API. Consider restricting to specific origins in production.

### 2. No HTTP Client Timeouts (`proxy/proxy.go:17-21`)
The proxy's HTTP client has no timeout, which could lead to hanging requests.

### 3. Mock Token Bypass in Production (`server/auth.go:245`)
The mock token check is only in one place - verify all mock paths are protected.

---

## Bugs

### 1. IPv6 Hostname Parsing Bug (`server/auth.go:47`)
Logic is inverted. Should be `&& !strings.HasSuffix(host, "]")` to properly detect IPv6 addresses.

### 2. Rate Limiter Stats Incorrect (`server/ratelimit.go:206-209`)
`RPSWindowEntries` counts users instead of actual window timestamps.

### 3. Session Store Goroutine Leak (`auth/session.go:44`)
The cleanup goroutine is started but `Stop()` is never called.

### 4. Rate Limiter Goroutine Leak (`server/ratelimit.go:41`)
Cleanup goroutine started but never stopped.

### 5. Unused Variable Silencing (`rbac/access.go:399-400`)
Workaround for unused variable instead of removing it.

---

## Confusing Things

### 1. Inconsistent maxIntPtr Logic (`rbac/resolver.go:310-318`)
Returns `nil` (unlimited) when either arg is nil, even when the other has a value.

### 2. Silent Error Handling
Multiple places errors are silently ignored with `_ = err`.

### 3. Hardcoded UUIDs (`rbac/access.go:521-523`)
Default org/group/role IDs are hardcoded strings rather than constants.

### 4. Mixed Case Sensitivity
Address comparisons inconsistent - some use `strings.ToLower()`, others case-sensitive.

### 5. Duplicate ETH Endpoints (`server/server.go:174-195`)
ETH endpoints registered twice at `/eth` and `/api/eth`.

---

## Potential Issues

### 1. Memory Growth Risk
No limits on session store, rate limiter entries, or RBAC cache size.

### 2. Distributed Deployment Issues
Rate limiter and session store are in-memory only - won't work across multiple instances.

### 3. No Cleanup on Shutdown
Goroutines may not clean up properly on application shutdown.

### 4. Authorization Bypass via Default Org (`rbac/access.go:312-315`)
Empty `OrgSlug` defaults to "default" org.

---

## Minor Issues

- Typo in README: "2. **API Requests**" should be numbered correctly
- No Ethereum address format validation in some endpoints
- Inconsistent error response formats
