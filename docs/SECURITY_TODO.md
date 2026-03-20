# Security TODOs

Open security items for the privacy proxy. Pick any item, create a branch, fix, test, PR.

Last updated: 2026-03-18

---

## HIGH Priority

### 1. Orphaned pre-registration cleanup job

**Files:** `internal/db/rbac_store_preregistered.go`, new background worker
**Context:** When the proxy crashes between pre-registering a deployment address and finalizing it post-mining, the `preregistered_addresses` row stays forever. Affects plain CREATE, CREATE3, and runtime CREATE2 flows equally.
**Fix:** Add a periodic cleanup job (e.g., every 5 minutes) that deletes `preregistered_addresses` rows older than 1 hour with no matching `contracts` entry. Could live in the existing `RetentionCleaner` or as a new goroutine.
**Test:** Create pre-reg row, wait for cleanup interval, assert deleted.

### 2. Historical state query check breaks MetaMask

**File:** `internal/rbac/access.go:344-350` (`IsHistoricalStateQuery`)
**Context:** MetaMask sends `eth_call` / `eth_getBalance` with specific hex block numbers (e.g., `"0x1a2b"`) for read consistency. The proxy blocks these as "historical state queries" for privacy protection. This breaks normal wallet operation.
**Boss's workaround:** Commented out the check entirely for demo.
**Proper fix options:**
- Make it opt-in per org (config flag `block_historical_queries`)
- Allow authenticated users to query any block (only block anonymous historical queries)
- Allow "recent" blocks (within last N blocks) and only block deep historical queries
**Test:** `eth_call` with a specific block number should succeed for authenticated users.

---

## MEDIUM Priority

### 3. Trace parser recursion depth — add a test

**File:** `internal/tracer/tracer.go:186-195`
**Context:** We added a max depth (256) that fails closed (returns error). But there's no test for it. Add a unit test that constructs a deeply nested `callFrame` and verifies the error is returned.

### 4. Response size limit on non-tracer RPC calls

**File:** `internal/proxy/proxy.go` (`Forward` method)
**Context:** The tracer now has a 64MB response limit, but the main proxy forward path (`proxy.Forward()`) reads the entire node response into memory without a size cap. A malicious/broken node could OOM the proxy.
**Fix:** Add `io.LimitReader` (e.g., 128MB) to the forward path.

### 5. Error message audit — remaining leaks

**Files:** `internal/rbac/access.go`, `internal/rbac/deploy_validator.go`
**Context:** Most user-facing errors are now generic ("access denied", "contract access denied"). But some paths still leak operational details:
- `deploy_validator.go` — deployment denial reasons reveal bytecode analysis details (dynamic calls, proxy patterns). These are helpful for deployers but could be abused.
- `access.go:513` — `"method X not allowed"` reveals the permission structure.
- Factory/upgrade validator passthrough reasons.
**Decision needed:** These may be acceptable since deployers are trusted (have deploy claim). Document the decision either way.

### 6. `ensureMockUserIsAdmin` — consider disabling entirely for scripted setups

**File:** `internal/server/auth_dev_admin.go`
**Context:** Currently skips `did:test:*` users. Boss disabled it entirely because RBAC is seeded externally via `demo-seed-rbac.sh`. Consider adding a config flag `DISABLE_DEV_ADMIN_PROVISIONING` to turn it off without code changes, so both workflows (auto-provision for quick dev, external seed for demo) work.

---

## LOW Priority

### 7. CREATE2 address determinism validation

**File:** `internal/rbac/trace_validator.go:103-130`
**Context:** We trust the tracer's reported CREATE2 addresses without validating them mathematically (`keccak256(0xff + deployer + salt + keccak256(initcode))`). If the node were compromised, it could report false addresses. On a private network this is low risk since we control the node.
**Deferred:** Would require extracting salt + initcode from the trace, which the `callTracer` doesn't provide.

### 8. Pre-registration simulation divergence monitoring

**File:** `internal/server/jsonrpc_processor.go` (`pollAndFinalizeRuntimeCreates`)
**Context:** When simulated CREATE2 addresses differ from actual mined addresses, the reconciliation logic handles it (cleans up stale, registers actual). But we only log at INFO level. Consider emitting a Prometheus metric (`runtime_create_divergences_total`) so operators can monitor frequency.

### 9. `userHasDeployClaim` doesn't check org-level admin

**File:** `internal/server/jsonrpc_processor.go` (`userHasDeployClaim`)
**Context:** Only checks group-level claims via `GetGroupAccess`. If a user is an org-level admin without an explicit group deploy claim, `userHasDeployClaim` returns false. In practice, `ExpandClaims()` normalizes admin → deploy before group access is stored, so this is likely a non-issue. Verify and document.

---

## Completed (this session)

- [x] Contract existence oracle — unified all denial messages (`ErrContractAccessDenied`)
- [x] User/org/membership existence oracles — genericized all denial messages
- [x] Token transfer value "0" for participants — added participant visibility override
- [x] Trace validator cross-org message leak — genericized
- [x] Trace parser depth limit — fails closed with error
- [x] Trace response size limit — 64MB cap via `io.LimitReader`
- [x] Runtime CREATE2 support — conditional on tracing + deploy claim
- [x] Deploy validator CREATE2 exception — conditional on runtime tracing
- [x] Dev-admin re-provisioning — skips `did:test:*` users
- [x] Historical state queries — only block for anonymous, allow authenticated (RBAC gates access)
- [x] Deployer access restricted to explicit grants — removed all 3 implicit access paths (deploy-claim blanket, default_claims bypass, deployed_by_user_id fallback). Auto-grants created at deploy time via `CreateDeployerAutoGrants`.
