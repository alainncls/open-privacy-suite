# Track 1: Log Access Control — Test Matrix

## Reference Constants

- **Transfer(address,address,uint256)**: `topic0 = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef`
- **Approval(address,address,uint256)**: `topic0 = 0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c20b9b`
- **CustomEvent(uint256,address)** (non-indexed address in data): `topic0 = keccak256("CustomEvent(uint256,address)")`
- Anonymous event (e.g. Deposit): no topic0

Addresses: User A = `0xaaaa...aaaa`, User B = `0xbbbb...bbbb`, Contract X = `0x5555...5555` (Org Alpha), Contract Y = `0x6666...6666` (Org Beta)

---

## 1. Unit Tests (`internal/rbac/`)

### 1.1 EventRule Validation (U01–U08)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U01 | ValidTopic0 | `EventRule{Topic0: "0x"+64hex, Name: "Transfer"}` | nil error |
| U02 | InvalidTopic0_TooShort | `Topic0: "0xddf252"` | error |
| U03 | InvalidTopic0_NotHex | `Topic0: "0xZZZ..."` | error |
| U04 | EmptyTopic0 | `Topic0: ""` | error |
| U05 | EmptyName_Allowed | `Name: ""` with valid Topic0 | nil error |
| U06 | ParamRule_ValidSelf | `ParamRules: [{Index: 0, MustBe: "self"}]` | nil error |
| U07 | ParamRule_NegativeIndex | `ParamRules: [{Index: -1, MustBe: "self"}]` | error |
| U08 | ParamRule_UnknownConstraint | `ParamRules: [{Index: 0, MustBe: "admin"}]` | error |

### 1.2 ABI Event Extraction (U09–U15)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U09 | ERC20_ABI | Standard ERC20 ABI | Transfer + Approval events with correct topic0 |
| U10 | Empty_ABI | `"[]"` | empty slice, nil error |
| U11 | NoEvents | ABI with only functions | empty slice, nil error |
| U12 | MalformedABI | `"not json"` | nil, error |
| U13 | AnonymousEvent | ABI with anonymous event | Event with `Anonymous: true`, `Topic0: ""` |
| U14 | OverloadedNames | Two Transfer events with different params | Two entries, different topic0 |
| U15 | Topic0Computation | Transfer(address,address,uint256) | topic0 == keccak256 of canonical signature |

### 1.3 Log Filtering Logic (U16–U25)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U16 | NoRules_Fallback | Logs + `EventRules: nil` | All logs pass (backward compat) |
| U17 | NilRules_NotEmptySlice | `EventRules: nil` vs `EventRules: []` | nil = unrestricted, [] = deny all |
| U18 | Allowlist_Match | Transfer log + rules allow Transfer | Log kept |
| U19 | Allowlist_NoMatch | Approval log + rules allow Transfer only | Log removed |
| U20 | MultipleRules_Union | Transfer + Approval logs, both in rules | Both kept |
| U21 | Allowlist_MixedLogs | 3 logs, 1 allowed | Only 1 returned |
| U22 | Anonymous_Denied | Anonymous log + rules configured, AllowAnonymous=false | Removed |
| U23 | Anonymous_Allowed | Anonymous log + AllowAnonymous=true | Kept |
| U24 | EmptyTopics | Log with `topics: []` | Removed |
| U25 | MalformedData | Log with truncated data + param_rules | Removed (fail-closed) |

### 1.4 ParamRule "self" Matching (U26–U34)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U26 | Indexed_Match | topics[1] = padded user A, rule: index 0 self, user A | Visible |
| U27 | Indexed_NoMatch | topics[1] = padded user B, rule: index 0 self, user A | Hidden |
| U28 | NonIndexed_Match | data has user A at param 1, rule: index 1 self, ABI present | Visible |
| U29 | NonIndexed_NoMatch | data has user B at param 1, rule: index 1 self, user A | Hidden |
| U30 | NonIndexed_NoABI | No ABI, rule on non-indexed param | Hidden (fail-closed) |
| U31 | MultipleRules_OR | user A in param 0 but not 1, rules on both | Visible (OR) |
| U32 | MultipleRules_NeitherMatch | user A in neither param 0 nor 1 | Hidden |
| U33 | IndexOutOfRange | ParamRule index 5, event has 2 params | Hidden |
| U34 | CaseInsensitive | Mixed-case address in topics vs lowercase user | Visible |

### 1.5 Union Across Grants (U35–U40)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U35 | DifferentEvents | Grant A: Transfer, Grant B: Approval | Union = both visible |
| U36 | OneNil_OneRestricted | Grant A: [Transfer], Grant B: nil | nil (unrestricted wins) |
| U37 | BothNil | Both nil | nil |
| U38 | SameEvent_OneNoParams | Grant A: Transfer+self, Grant B: Transfer (no params) | Transfer with no params (less restrictive) |
| U39 | SameEvent_BothParams | Grant A: param 0 self, Grant B: param 1 self | Both param rules (OR across all) |
| U40 | EmptySlice_vs_Rules | Grant A: [], Grant B: [Transfer] | Transfer visible |

### 1.6 HasEventAccess Helper (U41–U45)

| # | Name | Input | Expected |
|---|------|-------|----------|
| U41 | Nil_Unrestricted | `EventRules == nil` | true for any topic0 |
| U42 | Empty_DenyAll | `EventRules == []` | false for any topic0 |
| U43 | Populated_Allowlist | Rules has Transfer | true for Transfer, false for Approval |
| U44 | GetEventRule_Found | Rules has Transfer | Returns rule with ParamRules |
| U45 | GetEventRule_NotFound | Rules has Transfer only | nil for Approval topic0 |

---

## 2. Go Integration Tests (`e2e/event_rules_test.go`)

### 2.1 Admin API: CRUD (I01–I08)

| # | Name | Action | Assert |
|---|------|--------|--------|
| I01 | CreateGrant_WithEventRules | POST grant with event_rules | 201, rules persisted |
| I02 | CreateGrant_InvalidTopic0 | POST grant with bad topic0 | 400 |
| I03 | UpdateGrant_AddEventRules | PATCH grant, add rules | 200, rules present |
| I04 | UpdateGrant_ClearRules | PATCH with event_rules: null | 200, unrestricted |
| I05 | UpdateGrant_EmptyRules | PATCH with event_rules: [] | 200, deny-all |
| I06 | UpdateGrant_WithParamRules | PATCH with param_rules | 200, persisted |
| I07 | ListGrants_IncludesRules | GET grants | Both grants show correct rules |
| I08 | LookupContract_IncludesRules | GET by-address | Rules in response |

### 2.2 ABI Event Endpoint (I09–I13)

| # | Name | Action | Assert |
|---|------|--------|--------|
| I09 | ParsesABI | GET events, contract has ERC20 ABI | Returns Transfer + Approval with topic0 |
| I10 | NoABI | GET events, no ABI stored | Empty array |
| I11 | InvalidABI | GET events, ABI is garbage | 400 or empty |
| I12 | ContractNotFound | GET events for nonexistent addr | 404 |
| I13 | AnonymousEvents | ABI has anonymous event | Returns with anonymous=true |

### 2.3 eth_getLogs Filtering (I14–I20)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I14 | NoRules_Fallback | event_rules: nil, mock 3 logs | Topic-address filtering (backward compat) |
| I15 | AllowTransferOnly | rules: [Transfer], mock Transfer+Approval | Only Transfer returned |
| I16 | ParamRule_SelfMatch | rule: Transfer, param 0 self, topics[1]=userA | Transfer visible |
| I17 | ParamRule_SelfNoMatch | Same but topics[1]=userB | Transfer hidden |
| I18 | EmptyRules_DenyAll | event_rules: [] | All logs filtered |
| I19 | NoGrant_NoLogs | No grant on contract | Empty/denied |
| I20 | MixedContracts | Contract X: [Transfer], Contract Z: nil | X filtered, Z uses fallback |

### 2.4 Receipt Filtering (I21–I24)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I21 | FiltersReceiptLogs | Participant, rules: [Transfer] | Only Transfer in receipt.logs |
| I22 | NonParticipant_Null | Not participant | Null result |
| I23 | NoRules_CurrentBehavior | event_rules: nil | Topic-address filtering |
| I24 | MixedContracts | Tx touches X (rules) and Z (no rules) | Each filtered appropriately |

### 2.5 Cross-Org Isolation (I25–I27)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I25 | OrgB_Invisible | User A (Org Alpha), contract Y (Org Beta) | Empty/denied |
| I26 | NoAddressFilter_Scoped | Logs from X, Y, Z; user has grants on X, Z | Only X, Z logs |
| I27 | Receipt_MixedOrgs | Tx has logs from both orgs | Only own-org logs visible |

### 2.6 Admin Bypass (I28–I30) — RD-751 IMPLEMENTED

| # | Name | Setup | Assert | Status |
|---|------|-------|--------|--------|
| I28 | AdminClaim_Bypasses | Admin on contract X, restrictive rules | All logs visible | PASS (unit + server) |
| I29 | OrgAdmin_Bypasses | is_org_admin user | All logs visible | PASS (unit + server) |
| I30 | ReadClaim_NoByppass | read claim only, rules: [Transfer] | Only Transfer | PASS (unit + server) |

### 2.7 Multiple Grants Union (I31–I33)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I31 | UnionRules | Group1: [Transfer], Group2: [Approval] | Transfer + Approval visible |
| I32 | OneUnrestricted | Group1: [Transfer], Group2: nil | All visible |
| I33 | UnionParamRules | Group1: param 0 self, Group2: param 1 self | Either position matches |

### 2.8 ParamRule Integration (I34–I36)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I34 | NonIndexed_Self_Match | CustomEvent, data has userA at param 1 | Visible |
| I35 | NonIndexed_Self_NoMatch | CustomEvent, data has userB | Hidden |
| I36 | NoABI_FailClosed | No ABI, param_rules on non-indexed | Hidden |

### 2.9 Cache (I37)

| # | Name | Setup | Assert |
|---|------|-------|--------|
| I37 | CacheInvalidation | Fetch logs, update rules, fetch again | New rules applied |

---

## 3. E2E Playwright Tests (`e2e/playwright/tests/ui/08-event-rules.spec.ts`)

### 3.1 Grant Event Rule Config (P01–P04)

| # | Name | Flow | Assert |
|---|------|------|--------|
| P01 | AddRulesToNewGrant | Create grant → toggle "Restrict events" → add rule → save | Grant has event_rules |
| P02 | EditExistingRules | Edit grant → add second rule → save | Both rules shown |
| P03 | RemoveAllRules | Edit → toggle restrict off → save | event_rules: null |
| P04 | EmptyRules_DenyAll | Toggle on, add no rules, save | event_rules: [], warning shown |

### 3.2 Event Picker (P05–P08)

| # | Name | Flow | Assert |
|---|------|------|--------|
| P05 | ListsFromABI | Open picker on ERC20 contract | Shows Transfer + Approval |
| P06 | NoABI_ManualEntry | Open picker, no ABI | Shows manual topic0 input |
| P07 | AutoFillsFields | Select Transfer from picker | topic0 and name auto-filled |
| P08 | ShowsParams | Select Transfer → expand constraints | Shows from/to/value with types |

### 3.3 Presets (P09–P12)

| # | Name | Flow | Assert |
|---|------|------|--------|
| P09 | AllTransfers | Select "All Transfer events" preset | Rules: [Transfer] |
| P10 | AllEvents | Select "All events" | Restrict toggle off |
| P11 | NoEvents | Select "No events" | event_rules: [] |
| P12 | ConfirmOverwrite | Has rules → click preset | Confirmation dialog |

### 3.4 Persistence & Validation (P13–P16)

| # | Name | Flow | Assert |
|---|------|------|--------|
| P13 | PersistsAfterReload | Save → navigate away → return | Rules displayed |
| P14 | InvalidTopic0 | Enter "0xZZZZ" → save | Validation error |
| P15 | AddParamRules | Check "self" on from param → save | param_rules persisted |
| P16 | RemoveIndividualRule | Delete 1 of 2 rules → save | 1 rule remains |

### 3.5 Explorer Integration (P17–P18)

| # | Name | Flow | Assert |
|---|------|------|--------|
| P17 | FilteredInExplorer | View tx receipt as restricted user | Only allowed events shown |
| P18 | AdminSeesAll | View same receipt as admin | All events visible |

---

## Summary: 100 tests total (45 unit + 37 integration + 18 Playwright)

## Priority Order
1. U01–U08, U41–U45 (model validation) — drives data model
2. U09–U15 (ABI extraction) — core utility
3. U16–U25 (filtering logic) — main engine
4. U26–U34 (param rule matching) — extends param_validator pattern
5. U35–U40 (union semantics) — before multi-grant integration tests
6. I01–I13 (admin API) — validates persistence and API surface
7. I14–I37 (proxy filtering + security) — core correctness
8. P01–P18 (Playwright) — UI tests last
