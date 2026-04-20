# Open Items

Last updated: 2026-04-20

---

## 1. Bugs

| # | Bug | Location | Priority |
|---|-----|----------|----------|
| — | _(none currently)_ | | |

---

## 2. Legacy Code / Docs to Clean Up

| # | What | Location | Notes |
|---|------|----------|-------|
| A | `ClaimRead` / `ClaimWrite` constants + test usage | `internal/rbac/models.go:18-19`, ~30 test files | Marked "retained for DB compatibility." Removing requires a migration to strip read/write from all existing `group_access.claims` arrays in the DB. Not just a code change. |

### Already cleaned up (this PR)

- ~~"read claim" / "write claim" references in docs site~~ — replaced with "non-admin" / AllowedMethods language
- ~~"reader" / "writer" in API docs claims list~~ — removed
- ~~Deprecated `GenerateAddressPool` / `GenerateAddressPoolFromHex`~~ — removed
- ~~Entire `internal/evm/create3/` package~~ — removed (redundant with runtime tracing)
- ~~CREATE3 factory infrastructure~~ — factory_call_validator, per-org factory config API, dev endpoints, CLI compute-address command, factory trace skip, TRUSTED_FACTORY_HASHES config (~3,700 lines removed)
- ~~SIEM `Start()` never called~~ — fixed

---

## 3. TODOs (Features Not Yet Built)

| # | TODO | Notes | Priority |
|---|------|-------|----------|
| 4a | Multi-party event stakeholder whitelists | Events using business identifiers need per-event-ID stakeholder model. `visibleTo` partially covers sender-initiated sharing but not admin-configured stakeholders. | Medium |
| 4b | eth_call response ABI decoding | Responses returned unfiltered to any user with contract access. `visibleTo` doesn't apply. Requires ABI registration + per-function redaction rules. | Medium |
| 4c | Traffic analysis via block tx counts | `eth_getBlockTransactionCountByHash/Number` reveals tx counts per block — coarse traffic analysis. | Low |
| G4 | InternalTransaction.error not stripped | Error strings from `debug_traceCall` can contain raw revert messages with embedded addresses. Should be nil when either side is Hidden/Redacted. | High |
| G5 | Log.data not scanned when no ABI | Without ABI, non-indexed address params in event data are not redacted. **Accepted limitation** — no fix planned until heuristic ABI scanning is feasible. | Accepted |
| G6 | Block.logsBloom not zeroed | Bloom filter allows probabilistic address activity probing. Zeroing requires expensive per-block scanning. **Accepted limitation.** | Accepted |
| KYC | Auto-set KYC from ProofOfHumanity | `auth.go:510` hardcodes `kyc := false`. Manual dashboard override still required after successful verification. | Short-term |

---

## 4. Decisions to Be Made

| # | Decision | Context |
|---|----------|---------|
| 1 | **Anonymous explorer UX** | Should the block explorer have a public redacted view (all addresses as `[PRIVATE]`) for unauthenticated users, or require login to see anything? |
| G4 | **InternalTransaction.error leak** | Fix before MVP or accept as limitation? |
| G5/G6 | **Accepted gaps confirmation** | Team confirms G5 (no-ABI log data) and G6 (logsBloom) are accepted limitations? |
| 4a | **Multi-party events** | Blocking for MVP? Currently nobody can see business-identifier events without `visibleTo`. |
| 4b | **eth_call unfiltered** | Blocking for MVP? Any user with contract access sees full return values. |
| KYC | **KYC auto-set** | Auto-set from ProofOfHumanity, or keep manual approval step? |
| JWT | **JWTs in localStorage** | Accept (standard SPA tradeoff, mitigated by CSP) or rework to httpOnly cookies? |
| 10 | **Default group contract access** | Users without operational claims (deploy/admin) can't access own-org contracts without explicit grant. Intended UX, or should default group get implicit contract access? |
| SIEM | **SIEM privacy** | Acceptable to send raw DIDs, IPs, ETH addresses to external webhook? Hash/anonymize? Is SIEM needed for MVP? |
| 13a | **View functions** | Document for contract authors that public view functions return unfiltered data? |
| 13g | **Pseudonymous amounts** | Amounts preserved for pseudonymous addresses by design. Confirm this is the right call. |
