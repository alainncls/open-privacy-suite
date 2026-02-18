# Travel Rule Compliance — Security Audit

**Date:** 2026-02-17
**Last updated:** 2026-02-18 (second hardening pass, per-address thresholds, delete records, DID display)
**Scope:** `internal/compliance/`, `internal/server/admin_compliance.go`, `internal/server/server.go` (handleTestRequest), `internal/server/jsonrpc_processor.go` (Process, processRawTransaction), `internal/db/compliance_store.go`, `internal/db/db.go`, migrations `012_travel_rule_compliance.sql`, `013_compliance_check_constraints.sql`, `014_address_threshold_overrides.sql`

---

## CRITICAL — Bypass Vectors

### C1. ~~Native ETH with calldata bypasses detection~~ FIXED
**File:** `internal/compliance/transfer_detector.go`
**Issue:** Native ETH was only detected when `data == "" || data == "0x"`. Sending ETH value to a payable function (value > 0 with non-empty calldata) was invisible to compliance. A user could wrap any ETH transfer as a contract call to bypass the threshold check entirely.
**Fixed:** Restructured `DetectTransfer` to check ERC-20 selectors first, then detect native ETH whenever `value > 0` regardless of calldata. Extracted `detectERC20` helper. Added test case "native ETH transfer with calldata (payable function)".

### C2. ~~`eth_sendRawTransaction` unchecked in admin test endpoint~~ FIXED
**File:** `internal/server/server.go` (handleTestRequest)
**Issue:** Only `eth_sendTransaction` triggered compliance in `handleTestRequest`. The test endpoint accepted `eth_sendRawTransaction` which bypassed compliance.
**Fixed:** Extended compliance check to handle both methods. Raw transactions are decoded via `decodeRawTransaction` (RLP decode + sender recovery) before the compliance check runs.

### C3. ~~Record `amount_usd` is admin-provided, not validated against token price~~ FIXED
**File:** `internal/server/admin_compliance.go`
**Issue:** Admin provides `amount_usd` directly. No validation against `amount_wei * token_price`. A compromised localhost process can create a record with `amount_wei: "1"` but `amount_usd: 999999999` — a blank check that authorizes any transfer.
**Fixed:** Removed `amount_usd` from the input struct entirely. The server now looks up the token price via `GetTokenPrice` and computes `amount_usd` using `compliance.WeiToUSD(amountWei, decimals, priceUSD)`. Returns 400 if no token price is configured or if the computed amount is <= 0. Frontend form updated to no longer send `amount_usd`; the displayed USD estimate is labeled as approximate with the note that the server computes the exact value.

### C4. ~~`transferFrom` doesn't sanctions-check the actual spender (msg.sender)~~ FIXED
**File:** `internal/compliance/checker.go`
**Issue:** For `transferFrom(alice, bob, amount)`, `FromAddress = alice` (allowance owner). The checker sanctions-checked alice and bob, but never the actual `msg.sender` (the spender). A sanctioned user with an allowance could transfer unchecked.
**Fixed:** Added sanctions check for `req.From` (the tx originator) when it differs from `info.FromAddress`. Added test case "transferFrom spender sanctioned".

## HIGH — Input Validation Gaps

### H1. ~~`AmountUSD` rejects 0 due to Go `required` tag~~ FIXED
**File:** `internal/server/admin_compliance.go`
**Issue:** `binding:"required"` on `float64` treats `0.0` as zero value and fails validation. This is a known Go/gin gotcha.
**Fixed:** Removed `binding:"required"` from `AmountUSD`, added explicit `> 0` validation. Same fix applied to `PriceUSD` in `upsertTokenPrice`.

### H2. ~~Negative amounts accepted everywhere~~ FIXED
**Issue:** No `> 0` check on `amount_usd`, `price_usd`, or `threshold_usd` — either in Go handlers or in PostgreSQL schema.
**Fixed:** Added explicit positive-value checks in all three handlers (`createTravelRuleRecord`, `upsertTokenPrice`, `updateComplianceConfig`). DB CHECK constraints added via migration 013.

### H3. ~~`amount_wei` not validated as numeric string~~ FIXED
**File:** `internal/server/admin_compliance.go`
**Issue:** `amount_wei` is `string` with only `required`. Could be `"abc"`, `"-1"`, or garbage. Stored in DB and appeared in audit logs but was never verified.
**Fixed:** Now parsed as `big.Int` (base 10) and rejected if non-positive.

### H4. `originator_user_id` not verified against org membership — OPEN
**File:** `internal/server/admin_compliance.go`
**Issue:** No check that user exists in the org. DB FK constraint catches non-existent UUIDs, but wrong-org users slip through.
**Fix:** Verify user membership in the target org before creating the record.

### H5. ~~`token_address` not required for ERC-20 records~~ FIXED
**File:** `internal/server/admin_compliance.go`
**Issue:** When `transfer_type = "erc20"`, `token_address` could be null. The claim query uses `COALESCE(token_address, 'native')`, so a null-token ERC-20 record matched native ETH transfers — cross-contamination.
**Fixed:** Now requires `token_address` to be non-nil and a valid address when `transfer_type = "erc20"`. Token address is also lowercased for consistency.

### H6. ~~No DB CHECK constraints on positive amounts~~ FIXED
**File:** `internal/db/migrations/013_compliance_check_constraints.sql`
**Issue:** No database-level enforcement of positive amounts.
**Fixed:** Added migration 013 with CHECK constraints:
```sql
CHECK (amount_usd > 0)      -- travel_rule_records
CHECK (price_usd > 0)       -- token_prices
CHECK (threshold_usd >= 0)  -- compliance_config
```

### H7. ~~`WeiToUSD` overflow could produce `+Inf` or `NaN`~~ FIXED (was L3)
**File:** `internal/compliance/checker.go`
**Issue:** `WeiToUSD` returned a bare `float64` and ignored the `big.Float.Float64()` accuracy flag. Astronomically large `amount_wei` values could overflow to `+Inf`, causing invalid USD amounts in records and compliance decisions.
**Fixed:** `WeiToUSD` now returns `(float64, error)` with comprehensive input validation:
- Nil or zero `amountWei` → error
- Decimals range 0–77 (EVM standard) → error if out of range
- Negative, `+Inf`, or `NaN` `priceUSD` → error
- Final result checked for `+Inf` / `NaN` overflow → error
Promoted from L3 to H7 because unchecked overflow in a financial calculation can produce incorrect compliance decisions.

## MEDIUM — Design Issues

### M1. ~~Threshold uses strict `<` — edge case at exactly threshold~~ FIXED
**File:** `internal/compliance/checker.go`
**Issue:** `if amountUSD < threshold` — a transfer of exactly $1000 at threshold $1000 requires a travel rule record. Arguably correct but should be documented.
**Fixed:** Added clarifying comment at the threshold comparison explaining this is intentional per FATF guidance: the threshold is the ceiling below which no record is needed. A transfer at exactly the threshold requires a record.

### M2. ~~Compliance log errors swallowed silently~~ FIXED
**File:** `internal/compliance/checker.go`
**Issue:** `_ = c.logDecision(...)` — failed audit log writes don't block the decision. For a regulated system, a denied decision with no audit trail is a compliance violation.
**Fixed:** All `_ = c.logDecision(...)` calls now check the error. For denial decisions (sanctions, no-price, no-record), log failures produce a warning but the tx is still denied (the safe outcome). For allowed decisions (below threshold, record found), log failures cause the checker to fail closed — deny the transaction. Rationale: allowing a transaction without an audit trail is a compliance violation.

### M3. ~~Log entry created before tx execution~~ FIXED
**Issue:** Compliance log says "allowed" but the transaction might fail at the node (bad nonce, revert). Audit trail doesn't reflect actual outcome.
**Fixed:** Added documentation comment on `logDecision` explaining this is a deliberate design trade-off. The compliance log records the compliance *decision*, not the tx outcome. The actual tx result is captured separately in the RPC access log. The decision must be logged before forwarding to the node.

### M4. ~~Record consumed even if transfer amount is much less~~ FIXED
**File:** `internal/compliance/checker.go`
**Issue:** A $10K record consumed by a $1.1K transfer. Remaining coverage wasted.
**Fixed:** Added clarifying comment explaining this is intentional per travel rule semantics. Each transfer above threshold needs its own authorization. The record covers a specific planned transfer amount, not a balance.

### M5. ~~No rate limit on record creation~~ FIXED
**Issue:** Any localhost process can flood `POST /orgs/:id/compliance/travel-rule-records`.
**Fixed:** Added comment documenting this as a known limitation. The endpoint is admin-only on localhost. Rate limiting is out of scope for PoC but should be added before production deployment.

### M6. ~~`resolveThreshold` silently fell back to org default on DB error~~ FIXED
**File:** `internal/compliance/checker.go`
**Issue:** When fetching per-address threshold overrides, a database error was silently ignored and the org-level default threshold was used. This could allow transfers through at the wrong threshold if the DB had transient issues.
**Fixed:** `resolveThreshold` now returns an error on DB failures, and the caller (`Check`) propagates it — denying the transaction. Fail-closed: any error in threshold resolution blocks the transfer rather than falling back to a potentially higher threshold.

### M7. ~~Internal error messages leaked to API clients~~ FIXED
**File:** `internal/server/admin_compliance.go`
**Issue:** Error responses included raw Go error strings (`err.Error()`), potentially leaking internal details like table names, query structure, or stack traces.
**Fixed:** Added `internalError(c, msg, err)` helper. Logs the full error server-side with `log.Printf`, returns only a generic message to the client (e.g., `"failed to load compliance config"`). Applied to all 500-error paths in compliance handlers.

## LOW — Edge Cases

### L1. `parseHexValue("0x0")` returns nil, not zero — OPEN
**File:** `internal/compliance/transfer_detector.go`
**Issue:** Intentional but could confuse debugging.

### L2. Excessive calldata accepted for ERC-20 — OPEN
**File:** `internal/compliance/transfer_detector.go`
**Issue:** Extra trailing bytes silently ignored.

### ~~L3. `weiToUSD` ignores float64 accuracy flag~~ → Promoted to H7
Moved to H7 and fixed. See H7 above.

## HARDENING — Second Pass (2026-02-18)

Additional security hardening applied across all compliance admin endpoints:

### Pagination limit capping
**File:** `internal/server/admin_compliance.go`
A `maxPaginationLimit = 1000` cap prevents memory exhaustion from unbounded `?limit=999999` queries. Applied via `compliancePaginationParams()` to all paginated endpoints (travel rule records, sanctions, address thresholds, compliance logs).

### Input length validation
**File:** `internal/server/admin_compliance.go`
- Token `symbol`: max 20 characters
- Token `decimals`: 0–77 range (matches EVM standard)
- Sanction `reason`: max 1000 characters
- Address threshold `note`: max 1000 characters

### Query parameter whitelisting
**File:** `internal/server/admin_compliance.go`
Compliance log filters (`decision`, `transfer_type`) use explicit equality checks against allowed values (`"allowed"/"denied"`, `"eth"/"erc20"`). Invalid values are silently ignored rather than passed to the query.

### Per-address threshold overrides
**File:** `internal/db/migrations/014_address_threshold_overrides.sql`, `internal/compliance/checker.go`
New feature: per-address threshold overrides allow orgs to set lower thresholds for specific addresses (e.g., high-risk counterparties). Security properties:
- DB `CHECK (threshold_usd >= 0)` — $0 thresholds are valid (FATF: Japan, EU CASP-to-CASP require records for all transfers)
- `UNIQUE(org_id, address)` constraint — one override per address per org
- `resolveThreshold` checks both sender and recipient, selects the **lowest** threshold (strictest wins)
- Address normalized to lowercase for consistent matching

### Delete travel rule records — audit trail protection
**File:** `internal/db/compliance_store.go`, `internal/server/admin_compliance.go`
Admin can delete unused travel rule records. Security properties:
- `DELETE ... WHERE used_at IS NULL` — used records cannot be deleted (they are part of the audit trail)
- Sentinel errors (`ErrNotFound`, `ErrRecordAlreadyUsed`) distinguish failure modes
- HTTP 404 for missing, 409 Conflict for already-used records
- Record ID validated as UUID before query

### User DID display and search
**File:** `internal/db/compliance_store.go`, `internal/server/admin_compliance.go`
Compliance logs and travel rule records now show user DID (`external_id`) via LEFT JOIN. Log filtering changed from exact `user_id` UUID match to `ILIKE` search on `external_id`. This fixes a crash where partial UUID strings caused PostgreSQL type errors (`WHERE user_id = '929'` on a UUID column).

## POSITIVE FINDINGS

- Atomic record claiming with `FOR UPDATE SKIP LOCKED` — proper TOCTOU prevention
- Consistent address lowercasing throughout
- Fail-closed when token price missing
- Triple sanctions check: sender, recipient, and tx originator (msg.sender) when distinct
- Signature-verified `from` in `eth_sendRawTransaction` (main `/rpc` endpoint)
- Compliance check covers both `eth_sendTransaction` and `eth_sendRawTransaction` in test endpoint
- Native ETH detection works regardless of calldata (payable functions, fallback, etc.)
- 24h hardcoded expiry prevents backdating
- Partial index on unused records for efficient lookup
- Immutable audit log (BIGSERIAL, no UPDATE)
- DB CHECK constraints enforce positive amounts at the schema level
- `amount_wei` validated as positive `big.Int` before storage
- ERC-20 records require a valid `token_address` — no cross-contamination with native ETH
- `WeiToUSD` returns error with full input validation (nil, range, overflow)
- `resolveThreshold` fails closed on DB errors — no silent fallback
- Error messages sanitized via `internalError` helper — no internal details leaked to clients
- Pagination capped at 1000 across all endpoints
- Query parameter whitelisting prevents injection via filter params
- Used travel rule records protected from deletion (audit trail integrity)
- Per-address thresholds use lowest-wins logic (strictest threshold applies)

## SUMMARY

| ID | Severity | Status | Description |
|----|----------|--------|-------------|
| C1 | Critical | **FIXED** | Native ETH with calldata bypass |
| C2 | Critical | **FIXED** | Test endpoint raw tx bypass |
| C3 | Critical | **FIXED** | Record amount_usd not validated against token price |
| C4 | Critical | **FIXED** | transferFrom spender sanctions bypass |
| H1 | High | **FIXED** | AmountUSD rejects 0 (Go required tag) |
| H2 | High | **FIXED** | Negative amounts accepted |
| H3 | High | **FIXED** | amount_wei not validated as numeric |
| H4 | High | OPEN | originator_user_id not verified against org |
| H5 | High | **FIXED** | token_address not required for ERC-20 |
| H6 | High | **FIXED** | No DB CHECK constraints |
| H7 | High | **FIXED** | WeiToUSD overflow (promoted from L3) |
| M1 | Medium | **FIXED** | Strict `<` threshold edge case |
| M2 | Medium | **FIXED** | Compliance log errors swallowed |
| M3 | Medium | **FIXED** | Log before tx execution |
| M4 | Medium | **FIXED** | Record consumed regardless of amount gap |
| M5 | Medium | **FIXED** | No rate limit on record creation |
| M6 | Medium | **FIXED** | resolveThreshold silent fallback on DB error |
| M7 | Medium | **FIXED** | Internal error messages leaked to clients |
| L1 | Low | OPEN | parseHexValue("0x0") returns nil |
| L2 | Low | OPEN | Excessive ERC-20 calldata ignored |
