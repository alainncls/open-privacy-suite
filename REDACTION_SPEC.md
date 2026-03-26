# Redaction Engine — Developer Specification

**Status:** Living document. Update when adding new entity types, fixing gaps, or changing visibility semantics.

---

## 1. Overview

The redaction engine enforces the privacy promise at two independent layers:

### Layer 1 — RPC Filter (`internal/rbac/response_filter.go`)

Runs on every JSON-RPC response **before** it is returned to the calling client. The caller is a raw JSON-RPC user (wallet, script, block explorer backend). Redaction here is binary: a non-participant receives `null` or has their entry removed entirely. There is no `[PRIVATE]` placeholder at this layer — the client simply sees no data.

Called by: `proxy.go` → `responseFilter.Filter(method, response, callerLinkedAddresses)`

### Layer 2 — Explorer API Redactor (`internal/explorer/redaction/`)

Runs on structured data objects before they are serialised and returned by the Explorer REST API (`/api/explorer/...`). The caller is a user with an authenticated session and a known visibility level for each address. At this layer redaction is graduated: addresses can be replaced with `[PRIVATE]`, values zeroed, or entries dropped, depending on their visibility level.

Called by: Explorer API handlers → `RedactionEngine.RedactTransaction(tx, viewerOrgID)` etc.

### Layer 2a — SQL-Level Visibility Filtering (`internal/explorer/visibility_filter.go`)

Runs **before** data is fetched from the explorer database. Where Layer 2 redacts individual fields on already-fetched rows, this layer prevents invisible rows from being fetched at all. This is critical for correct pagination and count totals — without it, a page of 25 items might contain only 3 visible rows after post-fetch redaction.

The filter is built by `buildVisibilityFilter()`:

1. `GetAllRegisteredAddresses()` loads every contract address from the RBAC database.
2. `GetBatchVisibility(addresses, viewerOrgID)` classifies each address as Full, Redacted, or Hidden for the current viewer.
3. Addresses classified as Hidden are collected into a set.
4. A `VisibilityFilter` struct is constructed containing the hidden address set.

The SQL `WHERE NOT(...)` clause excludes:

- **Contract creation transactions from hidden deployers**: `to_address IS NULL AND from_address IN (hidden set)` — deployment activity from other orgs is completely invisible.
- **Transactions where both from AND to are hidden**: neither party is visible to the viewer, so the transaction is dropped entirely.

**Count/Total Security:** All paginated endpoints return only the count of rows that pass the visibility filter, never the raw database total. This prevents information disclosure about private transaction volume. A viewer cannot determine how many transactions exist that they are not allowed to see.

**Block Transaction Counts:** Per-block transaction counts returned by the explorer API are adjusted per-viewer via `GetBlockTransactionCountFiltered`, which applies the same visibility filter. The `transaction_count` in block list responses reflects only the transactions visible to the current viewer.

**Chain Stats:** `TotalTransactions` and `TotalAddresses` in the `/api/explorer/stats` response are filtered for viewer visibility. The raw database totals are never exposed.

**Transaction History:** Daily and hourly transaction count charts (`/api/explorer/stats/charts/txs`) are filtered to exclude hidden transactions. A viewer's chart data reflects only transaction volume they are permitted to see.

**Contract Creation Redaction:** Contract deployments from non-identifiable deployers (Hidden visibility) are completely dropped at the SQL level, not just field-redacted. This is stronger than Layer 2's field-level redaction: the transaction never appears in any list, and is not counted in any total.

**Interaction with Layer 2:** SQL-level filtering handles row-level drops (entire transactions removed). Layer 2 (`RedactTransactions`) still runs on the surviving rows for field-level redaction: replacing addresses with `[PRIVATE]`, zeroing values, and applying the participant visibility override. The two layers are complementary and both are required.

---

## 2. Visibility Levels

These levels are computed per-address by the redaction engine based on the viewer's RBAC grants and the address's org membership.

| Level | Meaning | Viewer relationship |
|-------|---------|---------------------|
| **Full** | Address and all associated data shown without modification | Viewer owns the address, or holds an explicit grant to it |
| **Pseudonymous** | Address replaced with a stable, deterministic pseudonym (e.g. `0xPSEUDO…`) | Address is redacted but viewer holds a partial grant; not yet implemented for most entity types |
| **Redacted** | Address replaced with `[PRIVATE]`; value and calldata zeroed | Address belongs to another org; viewer has no grant |
| **Hidden** | Entry dropped entirely (address not disclosed even as `[PRIVATE]`) | Address belongs to another org and viewer has no right to see the tx at all |

**Drop rule:** A transaction/transfer/log is dropped if **both** sides are Hidden. If one side is Hidden or Redacted and the other is Full, the entry is kept with the private side masked.

**Nonce rule:** Nonce is tied to the sender. Strip nonce when `from` is Hidden or Redacted. Preserve nonce when only `to` is Hidden or Redacted (nonce belongs to the sender, who is visible).

### 2.1 Visibility Resolution by Address Type

`GetBatchVisibility` resolves each address independently based on what kind of address it is and the viewer's relationship to it:

| Address type | How identified | Anonymous viewer | Org admin viewer | Standard org member | Address owner |
|---|---|---|---|---|---|
| **Org contract** | In `contracts` table | Redacted | **Full** (if admin of owning org) | Redacted | N/A |
| **User EOA** | In `eth_address_links` | Hidden | **Hidden** | Hidden | **Full** |
| **Public address** | Not in contracts or eth_address_links | Full | Full | Full | Full |

**Key implication for org admins:** An org admin has `VisibilityFull` on their org's **contracts** but NOT on individual **user EOAs**. User EOAs are personal wallets — they remain `VisibilityHidden` to everyone except the owner (and recipients of disclosure grants). This means:

- Contract calls (EOA → contract) are **visible** to org admin — the contract side is Full, so the tx survives the SQL filter. The EOA side is redacted as `[PRIVATE]`.
- Contract-to-contract interactions are **fully visible** to org admin.
- EOA-to-EOA transfers (e.g., ETH sent between two users) are **dropped** — both sides are Hidden.
- Contract deployments from user EOAs (`from=EOA, to=NULL`) are **dropped** — the deployer EOA is Hidden.

To see user EOA activity, an org admin would need a **disclosure grant** from each user, or the visibility model would need to be changed to treat user EOAs differently for org admins (design decision, see G11 below).

### 2.2 Admin Access Criteria

`VisibilityFull` for org contracts is granted only to viewers who are members of a group that meets one of:
1. `is_org_admin = true` on the group (org-wide admin flag)
2. `'admin' = ANY(contract_grants.claims)` on a contract_grant linking the group to the specific contract

Standard claims (`read`, `write`, `deploy`) do **not** grant `VisibilityFull`. The `admin` claim in `group_access.claims` (RPC method access) is also not checked — only `is_org_admin` and `contract_grants.claims` matter for visibility. See G11 for the alignment TODO.

---

## 3. Entity Field Matrix

### 3.1 Transaction (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | Both-sides-hidden → drop entire tx |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | Contract address if deploy; nil if null |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted |
| `inputData` | nil | nil | nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted |
| `error` | nil | nil | nil | unchanged | Yes | Partial | Zeroed when either side hidden/redacted |
| `revertReason` | nil | nil | nil | unchanged | Yes | Partial | Zeroed when either side hidden/redacted |
| `nonce` | nil | nil | nil | unchanged | Yes | Yes | Nil only when FROM is hidden/redacted; not when only TO is |
| `gasUsed` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: gas params are not identity-revealing in isolation; visible to all RPC participants |
| `gasPrice` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `maxFeePerGas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `maxPriorityFeePerGas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `gasLimit` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `contractAddress` | — (tx dropped)* | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | *Dropped by SQL visibility filter when deployer is hidden |
| `txCategories` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: derived labels, not raw addresses |

### 3.2 InternalTransaction (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | Zeroed when either side hidden/redacted |
| `input` | nil | nil | nil | unchanged | Yes | Yes | |
| `output` | nil | nil | nil | unchanged | Yes | Yes | |
| `error` | **unchanged** | **unchanged** | **unchanged** | unchanged | **No** | No | **GAP G4** — error strings may contain embedded addresses or revert reasons exposing private data |
| `gas` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |
| `gasUsed` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted |

### 3.3 TokenTransfer (Explorer API)

| Field | Hidden | Redacted | Pseudonymous | Full | Implemented | Tested | Notes |
|-------|--------|----------|--------------|------|-------------|--------|-------|
| `from` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `to` | `[PRIVATE]` | `[PRIVATE]` | pseudonym | unchanged | Yes | Yes | |
| `value` | 0 / nil | 0 / nil | 0 / nil | unchanged | Yes | Yes | |
| `tokenAddress` | unchanged | unchanged | unchanged | unchanged | N/A | N/A | Accepted: the token contract is public infrastructure |

### 3.4 Log (Explorer API)

Log redaction depends on the visibility of the **emitting contract address**, not the transaction parties.

| Field | Emitter Hidden | Emitter Redacted | Emitter Full | Implemented | Tested | Notes |
|-------|---------------|-----------------|--------------|-------------|--------|-------|
| Entry | Dropped | Kept | Kept | Yes | Yes | When emitter is hidden, the entire log entry is removed |
| `address` (emitter) | — (entry dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `topics[0..3]` (when emitter hidden) | — (entry dropped) | all nil | — | Yes | Partial | |
| `topics[0..3]` (when emitter redacted) | — | all nil | — | Yes | Partial | |
| `topics[1..3]` (when emitter full) | — | — | Scanned for zero-padded embedded addresses; private ones zeroed | Yes | Yes | topics[0] is event signature hash for non-anonymous events; address pattern check skips it naturally |
| `data` (when emitter hidden) | — (entry dropped) | — | — | Yes | Partial | |
| `data` (when emitter redacted) | — | zeroed | — | Yes | Partial | |
| `data` (when emitter full + ABI registered) | — | — | Non-indexed address params decoded, private ones zeroed | Yes | Partial | |
| `data` (when emitter full + NO ABI) | — | — | **Not scanned — returned unmodified** | **No** | No | **GAP G5** — private addresses in non-indexed params of unverified contracts leak through |

### 3.5 TokenHolder (Explorer API)

| Field | Hidden | Redacted | Full | Implemented | Tested | Notes |
|-------|--------|----------|------|-------------|--------|-------|
| Entry | Dropped | Kept | Kept | Yes | Yes | When address is hidden, the entire holder entry is removed from the list |
| `address` | — (entry dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `balance` | — (entry dropped) | 0 / nil | unchanged | Yes | Partial | Zeroed when redacted |
| `percentage` | — (entry dropped) | 0 / nil | unchanged | Yes | Partial | Zeroed when redacted |

### 3.6 Block (Explorer API / RPC Layer)

| Field | Behavior | Implemented | Tested | Notes |
|-------|----------|-------------|--------|-------|
| `miner` | Not redacted | N/A | N/A | Accepted: block producer is consensus-layer infrastructure metadata, not user identity; no grant/visibility mechanism for blocks |
| `logsBloom` | **Not zeroed** | **No** | No | **GAP G6** — bloom filter contains address/topic hashes; zeroing would require per-block address scanning which is expensive; low practical risk (lookups are probabilistic and require knowing the target address) |
| `number`, `hash`, `timestamp`, `gasUsed`, `gasLimit`, `difficulty`, `size`, `parentHash`, `nonce`, `extraData`, `baseFeePerGas`, `withdrawalsRoot` | Public; not redacted | N/A | N/A | Block header fields are consensus-layer public data |
| `transactions` (full objects, `fullTxObjects=true`) | Non-participant txs removed from array | Yes | Yes | Per-tx participant check; block-level fields preserved |
| `transactions` (hashes only, `fullTxObjects=false`) | Passed through | Yes | Yes | Tx hashes alone are not sensitive |

### 3.7 Explorer API — Participant Visibility Override

The visibility map (`GetBatchVisibility`) resolves each address independently: own address → Full, disclosure grant → grant level, org contract member → Full, everything else → Hidden.

However, **transaction participants must always see their counterparty** in their own transactions. A sender already knows the recipient (it's in their wallet history) and vice versa. Hiding it from them adds no privacy, only confusion.

This is implemented as a **per-transaction override** in `RedactTransactions` (`internal/explorer/redactor.go`):

1. The viewer's linked ETH addresses are fetched via `GetLinkedAddresses(ctx, viewerDID)`.
2. For each transaction, if any viewer address matches `from` or `to`, both sides are overridden to `VisibilityFull` for that transaction only.
3. The shared visibility map is **never mutated** — the override uses local variables scoped to the current transaction.

| Scenario | Viewer is participant? | Counterparty visibility | Override |
|----------|----------------------|------------------------|----------|
| Viewer is sender | Yes | Hidden → Full | Per-tx only |
| Viewer is receiver | Yes | Hidden → Full | Per-tx only |
| Viewer is not involved | No | No override | Normal rules apply |
| Same tx, different viewer | — | Independent | Each viewer gets their own override |

**Log participant override:** `RedactLogs` accepts optional `participantAddrs` (the parent tx's `from` and `to`). When the viewer's linked address matches a participant address, Redacted emitting contracts are upgraded to Full for that log context — topics and data are preserved instead of stripped. Hidden emitting contracts remain dropped even with participant override. The API handler (`getExplorerTransactionLogs`) fetches the parent transaction and passes its `from`/`to` as participant context.

**Security invariant:** The override ONLY applies within `RedactTransactions`/`RedactLogs`/`RedactTransfers`/`RedactInternalTransactions`, which process a specific transaction's data. It does NOT affect `GetBatchVisibility` or `GetBatchVisibilityDetailed` (used by the address visibility check endpoint). A counterparty address visible via participant override in a transaction list will still show as Hidden when queried individually via `/check-address`.

### 3.8 RPC Layer (`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`, `eth_getBlockByNumber`, `eth_getBlockReceipts`)

At the RPC layer, visibility is binary: the caller either is or is not a participant (one of their linked addresses matches `from` or `to`).

| Method | Participant behavior | Non-participant behavior | Implemented | Tested |
|--------|---------------------|--------------------------|-------------|--------|
| `eth_getTransactionByHash` | Full transaction returned | `null` | Yes | Yes |
| `eth_getTransactionReceipt` | Full receipt with logs | `null` | Yes | Yes |
| `eth_getLogs` | Entries where a topic address matches a linked address | Entry removed from array | Yes | Yes |
| `eth_getLogs` topics[0..3] | All 4 slots scanned for private addresses | Non-matching entries removed | Yes | Yes |
| `eth_getLogs` data field | **Not scanned** | — | **No** | No | **Same ABI gap as Explorer API (G5)** |
| `eth_getBlockByNumber` (`fullTxObjects=true`) | Full block; all txs | Non-participant txs removed | Yes | Yes |
| `eth_getBlockByNumber` (`fullTxObjects=false`) | Passes through | Passes through | Yes | Yes |
| `eth_getBlockReceipts` | All receipts in block | Non-participant receipts removed | Yes | Yes |
| `logsBloom` in blocks | **Not zeroed** | — | **No** | No | **GAP G6** |

### 3.9 Token (Explorer API)

Token visibility is determined by the token's contract address. If the address is registered as an org contract in the RBAC database, the token inherits that contract's visibility. Unregistered addresses default to `VisibilityFull`.

| Field | Hidden | Redacted | Full | Implemented | Tested | Notes |
|-------|--------|----------|------|-------------|--------|-------|
| Entry | Dropped from list | Kept | Kept | Yes | Yes | Hidden tokens never appear in `/tokens` list |
| `address` | — (dropped) | `[PRIVATE]` | unchanged | Yes | Yes | |
| `symbol` | — | empty string | unchanged | Yes | Yes | |
| `name` | — | nil | unchanged | Yes | Yes | |
| `decimals` | — | unchanged | unchanged | Yes | Yes | Non-identifying metadata |
| `tokenType` | — | unchanged | unchanged | Yes | Yes | Non-identifying metadata |
| `totalSupply` | — | nil | unchanged | Yes | Yes | |
| `holderCount` | — | 0 | unchanged | Yes | Yes | |
| `transferCount` | — | 0 | unchanged | Yes | Yes | |
| `creationTx` | — | nil | unchanged | Yes | Yes | |
| `l1Address` | — | nil | unchanged | Yes | Yes | |
| `usdPrice` | — | nil | unchanged | Yes | Yes | |
| `iconUrl` | — | nil | unchanged | Yes | Yes | |

**Single token endpoint** (`/tokens/:address`): Hidden returns 404. Redacted returns masked fields. Full returns as-is.

**Sub-endpoints** (`/tokens/:address/holders`, `/tokens/:address/transfers`): Hidden or Redacted returns 404. Full proceeds normally (holder/transfer redaction still applies to individual entries).

**List total:** The `total` field in `/tokens` reflects the count after filtering, never the raw database count.

---

## 4. Known Gaps

The following gaps are numbered. G1, G2, G3, G8, G9, G14 are resolved. G4–G7, G15–G16 are outstanding.

### Resolved

- **G1 (resolved):** Nonce not stripped when sender was hidden — now nil when `from` is Hidden/Redacted.
- **G2 (resolved):** `value` and `inputData` not zeroed for mixed-party txs (one side hidden) — now zeroed when either side is Hidden or Redacted.
- **G3 (resolved):** Log topics[1..3] not scanned for embedded address parameters — now scanned for all logs where emitter is Full; private addresses zeroed.
- **G7 (resolved):** Transaction.contractAddress leaks deployed address — contract deployment transactions from hidden deployers are now dropped entirely via SQL-level visibility filtering.
- **G8 (resolved):** TokenHolder entries not dropped when address is Hidden — now dropped.
- **G9 (resolved):** Log entries not dropped when emitter is Hidden — now dropped entirely.
- **G14 (resolved):** Token endpoints (`/tokens`, `/tokens/:address`, `/tokens/:address/holders`, `/tokens/:address/transfers`) returned raw unredacted token data without any visibility checks. Now: Hidden tokens are dropped from lists and return 404 from single-token endpoints. Redacted tokens have sensitive fields masked (`[PRIVATE]`, nil names/symbols, zeroed counts). Sub-endpoints (holders, transfers) return 404 for Hidden or Redacted token addresses. List total reflects filtered count only.

### Outstanding

- **G4: InternalTransaction.error not stripped**
  Error strings returned from trace calls can contain raw revert messages or embedded addresses (e.g. `execution reverted: caller 0xABCD... not authorized`). When either side of the internal call is Hidden or Redacted, the `error` field must be set to nil before the response is returned. Currently returned unmodified.

- **G5: Log.data not scanned when no ABI registered (partial)**
  When an event log's emitting contract has a registered ABI, non-indexed `address`-typed parameters in `data` are decoded and private addresses zeroed. When no ABI is registered, the raw ABI-encoded `data` blob is returned unmodified. A private address embedded as a non-indexed parameter in an unverified contract's log will not be redacted. This applies to both the Explorer API and `eth_getLogs` at the RPC layer. Accepted as a limitation — no fix planned until ABI scanning can be done heuristically.

- **G6: Block.logsBloom not zeroed**
  The `logsBloom` field in block headers is a Bloom filter over the addresses and topics of all logs in the block. It contains hashed (not raw) representations of addresses. A viewer who already knows a target address can probe whether that address has activity in a given block in O(1). Zeroing the bloom field for all blocks would require per-block address scanning against the private address registry, which is expensive. Risk is low — probabilistic membership test only, requires knowing the target address. Accepted for now; track as a future hardening item.

- **G10: One-side-hidden transactions leak activity metadata**
  When only one party in a transaction/transfer is hidden and the other is public, the entry survives the SQL visibility filter. The hidden side is masked (`[PRIVATE]`), but the viewer still learns that *some* private party interacted with the visible address — including timing, block number, gas used, and transfer amounts. For example, a non-participant can see "someone private called [public contract]." On a private network this metadata may be sensitive. The stricter alternative — drop if ANY side is hidden unless viewer is a participant — would eliminate this leak but significantly reduce explorer utility for public addresses. **Decision pending**: track as a design tradeoff. If tightened, the participant override in `RedactTransactions`/`RedactTransfers`/`RedactInternalTransactions` ensures participants still see their own activity.

- **G11: Visibility admin check not aligned with group_access.claims**
  `GetBatchVisibility` grants `VisibilityFull` based on `is_org_admin = true` or `'admin' = ANY(contract_grants.claims)`. It does NOT check `group_access.claims`, which is where the admin claim is typically set via the API and admin dashboard. A group with `claims: [admin]` in group_access and contract_grants with `claims: {}` will NOT grant explorer visibility. This is confusing: users expect "admin claim" to mean admin everywhere. **Fix:** either check `group_access.claims` in the visibility query, or auto-set `is_org_admin` when admin claim is granted. **Workaround:** manually set `is_org_admin = true` on admin groups.

- **G12: Org admin cannot see user EOA activity (contract deployments, EOA transfers)**
  Org admins have `VisibilityFull` on org contracts but user EOAs remain `VisibilityHidden`. This means: EOA-to-EOA transfers are dropped, contract deployments from user EOAs are dropped, and the deployer's address shows as `[PRIVATE]` in surviving contract call txs. For an org admin auditing their network, not seeing who deployed which contract or who transferred ETH to whom is a significant gap. **Options:** (a) org admins automatically get visibility on all EOAs of users who are members of any group in that org, (b) require explicit disclosure grants from users, (c) add a new "audit" role that unlocks EOA visibility. **Decision pending.**

- **G13: Minting from zero address to private recipient visible to non-participants**
  Token mints (`from=0x0000...0000, to=private_address`) survive the SQL filter because the zero address is public (not in contracts or eth_address_links). Non-participants can see "someone private received a mint from [token contract]" — revealing that a private user received tokens, when they did, and from which contract. This is a specific case of G10 but worth calling out separately because mint events are particularly sensitive (they reveal token distribution to specific parties). **Options:** (a) treat zero address as neutral rather than public for visibility purposes, (b) handled by G10 if the stricter drop rule is adopted. **Decision pending.**

- **G15: Address parameters in URL paths leak real addresses**
  All `/addresses/:address/...` endpoints embed real addresses in URLs visible in server logs, network intermediaries, and browser history. An untrusted block explorer client that knows a private address can confirm its existence by requesting its sub-endpoints (even if the response is 404, the address appears in access logs). This is a design-level issue requiring API redesign (e.g., opaque address IDs instead of raw hex addresses in URL paths).

- **G16: `checkAddressVisibility` enables address enumeration**
  The `/check-address/:address` endpoint allows an untrusted client to probe arbitrary addresses to discover which are private (returns different visibility levels). An attacker can enumerate addresses to build a map of private contracts and user EOAs. Rate limiting mitigates but does not prevent this. A redesign (e.g., returning only the visibility for addresses the viewer already knows about) would close this gap.

- **G17 (resolved): Disclosure grants leaked into regular explorer views (RD-774)**
  `GetBatchVisibility` checked disclosure grants and upgraded address visibility for the grant recipient across all explorer views. Fixed: grants removed from `GetBatchVisibility`. `GetBatchVisibilityDetailed` retains grant metadata (for privacy dashboard) but no longer upgrades visibility level.

- **G18: Disclosure grant label/visibility consistency across explorer views**
  When a viewer has a disclosure grant AND is a participant in a transaction, the participant override reveals the real address. The "Disclosed" label should NOT appear on regular explorer pages (tx detail, block page) — only on the grant page and privacy dashboard. Current `check-addresses` API returns `reason: disclosure_grant` which causes the explorer to show "Disclosed" label everywhere. **Fix:** the explorer frontend should only show "Disclosed" label on the grant page. On regular pages, participant-revealed addresses show with no label. See visibility matrix in this section.

- **G19: Grant page should show viewer's own address as "Mine" not External-XXXX**
  On the pseudonymous grant page, the viewer's own address is pseudonymized as `External-XXXX` like any other external address. The proxy should detect when an external address in a grant transaction matches the viewer's linked address and label it as "You" or "Mine" instead of generating a pseudonym.

- **G20: Redacted disclosure level — use case undefined**
  `DisclosureRedacted` is documented as "hides all addresses — for minimal disclosure" but the business use case is not specified. Currently shows an empty transaction list on the grant page. **Decision needed from product/team lead:** What scenario requires a grant that reveals no data? Is it a placeholder, a compliance checkbox ("yes this user exists"), or something else? Implementation should wait for clarification.

- **G21: Inbound transaction visibility — should recipient see sender?**
  When someone sends a transaction TO a user, the participant override reveals the sender's address to the recipient. This is currently correct (the recipient knows who sent them funds). However, the reverse case needs consideration: if someone receives an unsolicited transaction, should the sender's identity be revealed? On a public chain this is a non-issue, but on a private network where identity is protected, receiving a tx could be used to probe someone's explorer view. **Decision needed:** Is the current behavior (always reveal counterparty to participants) correct, or should inbound-only participants have restricted visibility?

---

## 5. Adding a New Entity Type

When adding a new entity to the Explorer API, a developer **must**:

1. **Identify all address fields** in the entity struct. Map each to a `from`/`to`/`emitter` role.
2. **Determine the drop condition**: define when an entry must be removed entirely (typically: all address fields are Hidden).
3. **Implement the redaction method** in `internal/explorer/redaction/` following the existing pattern (`RedactTransaction`, `RedactLog`, etc.). The method must:
   - Accept the entity and the viewer's org ID.
   - Call `resolveVisibility(address, viewerOrgID)` for each address field.
   - Apply the correct behavior per visibility level for every field in the entity.
4. **Handle cascading value fields**: any field whose value is only meaningful in combination with a private address (e.g. `value`, `input`, `nonce`) must be zeroed/nil when the associated address is Hidden or Redacted.
5. **Update this spec**: add the new entity to Section 3 with a complete field matrix.
6. **Write unit tests** covering all conditions listed in Section 6.
7. **Wire the redaction method** into the relevant API handler. Verify the handler calls the method before serialisation.
8. **Check for error/reason fields**: if the entity has any free-text error or reason field, treat it as potentially containing addresses and zero it when either party is hidden.

---

## 6. Test Coverage Requirements

Every redaction method must have unit tests covering the following scenarios. Tests that are missing are a bug.

### Required test cases per entity

| Scenario | Expected result |
|----------|----------------|
| Both sides Full | All fields unchanged |
| `from` Hidden, `to` Full | `from` → `[PRIVATE]`; value/input/nonce (if applicable) → nil; `to` unchanged |
| `from` Full, `to` Hidden | `to` → `[PRIVATE]`; value/input → nil; nonce preserved (belongs to sender) |
| Both sides Hidden | Entry dropped entirely |
| Both sides Redacted | `from` and `to` → `[PRIVATE]`; value/input/nonce → nil |
| Emitter Hidden (logs) | Entire log entry dropped |
| Emitter Redacted (logs) | Address → `[PRIVATE]`; all topics → nil; data → nil |
| Emitter Full, topic address is private | Topic address zeroed; other topics unchanged |
| Emitter Full, ABI registered, data has private address | Private address slot in data → zeroed |
| Deploy tx, sender Hidden | Entry dropped entirely (SQL-level) |
| Viewer is sender, counterparty Hidden | Counterparty → Full (participant override) |
| Viewer is receiver, counterparty Hidden | Counterparty → Full (participant override) |
| Viewer not a participant, both sides Hidden | Entry dropped (no override) |
| Two txs, viewer participates in one only | Override applies only to the participated tx |

### Gap behavior must be explicitly asserted

Do not allow a gap to become invisible through test omission. For each known gap (G4–G7), write a test that:
1. Sets up the exact scenario that triggers the gap.
2. Asserts the **current (broken) behavior** with a comment: `// GAP G<N>: expected nil, returns actual value — fix before release`.

This makes gaps visible in CI output and prevents accidental regression to worse behavior.

### Test structure

Follow the existing table-driven test pattern:

```go
tests := []struct {
    name     string
    from     VisibilityLevel
    to       VisibilityLevel
    wantDrop bool
    wantFrom string
    wantNonce *int
    // ...
}{
    // cases here
}
for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // ...
    })
}
```

Tests live alongside the redaction code in `internal/explorer/redaction/*_test.go`.
