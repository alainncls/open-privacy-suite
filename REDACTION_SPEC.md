# Redaction Engine — Developer Specification

**Status:** Living document. Update when adding new entity types, fixing gaps, or changing visibility semantics.

---

## Invariant: RPC access and explorer visibility must agree

For every (viewer, address) pair, the RPC access layer (`rbac.AccessController.CheckAccess`) and the explorer visibility layer (`db.GetBatchVisibility`) must return consistent outcomes. If CheckAccess allows a viewer to interact with an address, `GetBatchVisibility` must return `VisibilityFull` for that address for the same viewer. If CheckAccess denies, visibility must be `Hidden` or `Redacted` — never `Full`.

Any asymmetry is a bug. The historical failure mode (RD-849) was tier 3 admin-claim users getting RPC access to every contract in their org while the explorer correctly treated the same contracts as `[PRIVATE]`. The symmetry is enforced by `e2e/access_visibility_symmetry_test.go` — every change to either layer must keep that test green.

The rule also drives how admin and deploy claims are scoped: they grant bypass on **explicitly granted contracts only**, not org-wide access. Org-wide access is the exclusive privilege of `is_org_admin` groups (tier 2), materialized as explicit `ContractAccess` for every org contract.

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

**Unregistered addresses (private by default):** Addresses not present in the `contracts` or `preregistered_addresses` tables and not linked via `eth_address_links` are treated as **private** (`VisibilityHidden`). The only exception is EVM precompile addresses (0x01-0x09), which are always `VisibilityFull` since they are native EVM functions. Contracts deployed through the proxy are **never unregistered** — they are pre-registered to the deployer's org before the transaction is forwarded to the node.

### 2.1 Visibility Resolution by Address Type

`GetBatchVisibility` resolves each address independently based on what kind of address it is and the viewer's relationship to it:

| Address type | How identified | Anonymous viewer | Org admin viewer | Grant holder (any claim) | Standard org member (no grant) | Address owner |
|---|---|---|---|---|---|---|
| **Org contract** | In `contracts` table | Redacted | **Full** (if admin of owning org) | **Full** (group has contract_grant) | Redacted | N/A |
| **User EOA** | In `eth_address_links` | Hidden | **Hidden** | Hidden | Hidden | **Full** |
| **EVM Precompile** | Address 0x01-0x09 | Full | Full | Full | Full | Full |
| **Unregistered** | Not in contracts, eth_address_links, or precompiles | **Hidden** | **Hidden** | **Hidden** | **Hidden** | **Hidden** |

**Key implication for org admins:** An org admin has `VisibilityFull` on their org's **contracts** but NOT on individual **user EOAs**. User EOAs are personal wallets — they remain `VisibilityHidden` to everyone except the owner (and recipients of disclosure grants). This means:

- Contract calls (EOA → contract) are **visible** to org admin — the contract side is Full, so the tx survives the SQL filter. The EOA side is redacted as `[PRIVATE]`.
- Contract-to-contract interactions are **fully visible** to org admin.
- EOA-to-EOA transfers (e.g., ETH sent between two users) are **dropped** — both sides are Hidden.
- Contract deployments from user EOAs (`from=EOA, to=NULL`) are **dropped** — the deployer EOA is Hidden.

To see user EOA activity, an org admin would need a **disclosure grant** from each user, or the visibility model would need to be changed to treat user EOAs differently for org admins (design decision, see G11 below).

### 2.2 Full Access Criteria (3-Tier Admin Model)

`VisibilityFull` for org contracts is granted to viewers who are members of a group that meets one of:
1. `is_org_admin = true` on the group (**tier 2 — org admin** — sees ALL contracts in the org)
2. The group has a `contract_grant` linking it to the specific contract (any claims — `read`, `write`, `deploy`, `admin`)

**Tier 3 (contract admin):** Having `'admin' = ANY(group_access.claims)` without `is_org_admin = true` does **not** grant org-wide contract visibility. Contract admins see only contracts explicitly granted to their group via `contract_grant`. Their `admin` claim gives them RBAC bypass (event rule bypass, all functions allowed) on those granted contracts only — not org-wide visibility.

Path 1 grants visibility on ALL contracts in the org without needing explicit per-contract grants. This is the org admin (tier 2) privilege. Path 2 is for all grant holders (including contract admins): if a user can access a contract via their group's grant, the contract should not appear as `[PRIVATE]` in the explorer.

Users in the same org but in a group **without** a `contract_grant` and **without** `is_org_admin` still see `VisibilityRedacted`.

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
| `data` (when emitter full + NO ABI) | Entire log denied at both layers (RPC and Explorer) | — | — | Yes | Yes | **G5 closed (RD-875 RPC + RD-889 explorer).** Without an ABI we can't decode non-indexed `address` params; both layers fail closed (drop the log) when no ABI is resolvable for the emitting contract. Admin bypass on the RPC layer (RD-751) still applies. Operator must register a custom ABI or set `metadata.token_type` to a built-in registry value (ERC-20 / ERC-721) before any event becomes visible. Grant save handler also rejects up-front. |

### 3.4.1 RPC-Layer Log Filtering (Event Access Control)

In addition to Explorer API redaction, logs returned by `eth_getLogs` and `eth_getTransactionReceipt` are filtered at the RPC layer by `FilterEventLogs` (`internal/rbac/event_filter.go`). This is a separate layer from Explorer API redaction — it controls which log entries are visible at all, before any field-level redaction occurs.

**Admin bypass (RD-751):** Users with the `admin` claim on a contract see ALL logs from that contract, regardless of event rules or address-in-topic checks. This applies to:
- Per-contract admin (group has `admin` in `group_access.claims` + `contract_grant`)
- Org admin (`is_org_admin = true` group — resolver grants `admin` on all org contracts)

The bypass does NOT apply to users with `deploy`, `write`, `read`, or `upgrade` claims only.

| Viewer | Event rules configured | Address in topics | Log visible? |
|--------|----------------------|-------------------|-------------|
| Admin on contract | Any | Any | **Yes** (bypass) |
| Org admin | Any | Any | **Yes** (bypass via admin claim) |
| Read user | `null` (default) | Yes | Yes |
| Read user | `null` (default) | No | No |
| Read user | `[Transfer]` | N/A | Only Transfer logs |
| Read user | `[]` (deny all) | Any | No |
| No access to contract | Any | Any | No |
| `perms == nil` | N/A | N/A | No (fail-closed) |

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
| `logsBloom` | All-zero (256 bytes) on every response, every viewer | Yes | Yes | **G6 closed (RD-873).** Bloom previously leaked address/topic membership in O(1) to anyone who already knew the target address. Now overwritten unconditionally on the way out — no per-block address scanning needed because the field carries no useful information for clients of a privacy proxy. |
| `number`, `hash`, `timestamp`, `gasUsed`, `gasLimit`, `difficulty`, `size`, `parentHash`, `nonce`, `extraData`, `baseFeePerGas`, `withdrawalsRoot` | Public; not redacted | N/A | N/A | Block header fields are consensus-layer public data |
| `transactions` (full objects, `fullTxObjects=true`) | Non-participant txs removed from array | Yes | Yes | Per-tx participant check; block-level fields preserved |
| `transactions` (hashes only, `fullTxObjects=false`) | Passed through | Yes | Yes | Tx hashes alone are not sensitive |

### 3.7 Explorer API — Participant Visibility Override

The visibility map (`GetBatchVisibility`) resolves each address independently: own address → Full, org contract grant holder → Full, org admin → Full (all org contracts), everything else → Hidden/Redacted.

However, **transaction participants must always see their counterparty** in their own transactions. A sender already knows the recipient (it's in their wallet history) and vice versa. Hiding it from them adds no privacy, only confusion.

This is implemented as a **per-transaction override** in `RedactTransactions` (`internal/explorer/redactor.go`):

1. The viewer's linked ETH addresses are fetched via `GetLinkedAddresses(ctx, viewerDID)`.
2. For each transaction, if any viewer address matches `from`, `to`, **or appears in calldata as an address parameter** (e.g., ERC20 `transfer(address,uint256)` recipient), both sides are overridden to `VisibilityFull` for that transaction only.
3. The shared visibility map is **never mutated** — the override uses local variables scoped to the current transaction.

**Calldata-level participant detection:** For contract calls, the tx-level `to` is the contract address, not the actual counterparty. The redactor also parses `inputData` for common function selectors to detect participants encoded in calldata:
- `0xa9059cbb` — `transfer(address to, uint256 amount)`: param 0 is recipient
- `0x23b872dd` — `transferFrom(address from, address to, uint256 amount)`: params 0 and 1
- `0x095ea7b3` — `approve(address spender, uint256 amount)`: param 0 is spender

| Scenario | Viewer is participant? | Counterparty visibility | Override |
|----------|----------------------|------------------------|----------|
| Viewer is sender (`from`) | Yes | Hidden → Full | Per-tx only |
| Viewer is receiver (`to`) | Yes | Hidden → Full | Per-tx only |
| Viewer is ERC20 transfer recipient (in calldata) | Yes | Hidden → Full | Per-tx only |
| Viewer is not involved | No | No override | Normal rules apply |
| Same tx, different viewer | — | Independent | Each viewer gets their own override |

**Log participant override:** `RedactLogs` accepts optional `participantAddrs` (the parent tx's `from` and `to`). When the viewer's linked address matches a participant address, Redacted emitting contracts are upgraded to Full for that log context — topics and data are preserved instead of stripped. Hidden emitting contracts remain dropped even with participant override. The API handler (`getExplorerTransactionLogs`) fetches the parent transaction and passes its `from`/`to` as participant context.

**Security invariant:** The override ONLY applies within `RedactTransactions`/`RedactLogs`/`RedactTransfers`/`RedactInternalTransactions`, which process a specific transaction's data. It does NOT affect `GetBatchVisibility` or `GetBatchVisibilityDetailed`. A counterparty address visible via participant override in a transaction list will still show as Hidden when queried via other visibility resolution paths.

### 3.7.1 Per-contract visibleTo unlock (RD-874)

By default `visibleTo` is **additive** — it widens an already-permitted viewer's response (e.g. param-rule fallback) but never grants new event-level access. The settlement-bank pattern (many participants, shifting per-event visibility) is awkward to express that way, so contracts can opt in to the **unlock semantic**: per-tx visibleTo lists become per-event opt-in unlocks.

**Opt-in switch:** `contracts.allow_visibleto_unlock` (boolean, default false). Flipped via the admin API:

```
PUT /api/orgs/:org_id/contracts/:address/visibleto-unlock
{"allow_visibleto_unlock": true}
```

Admin-only on the contract's owning org. Migration **045**.

**When the flag is true and a viewer is listed in a transaction's `visibleTo`, the viewer sees ALL event logs of that transaction** (per-tx, all-events) — bypassing the contract grant's `event_rules` allowlist, any `param_rules`, and the deny-when-no-ABI gate (RD-875/889). Field-level redaction of embedded private addresses in topics/data is also bypassed for that one tx — the contract owner has explicitly authorised tx senders to share full event payloads with their listed recipients.

**Eligibility gate** (`rbac.IsViewerEligibleForVisibleToUnlock`) — both must hold for any unlock:

1. The viewer resolves to a real `users` row (anonymous viewers — no DID account — are denied here).
2. The viewer is a member of at least one **non-system** group whose `org_id` equals the contract's owning `org_id`, AND that group has a `contract_grant` on this contract. The grant's `event_rules` may be deny-all — the unlock works *because of* the grant link, not its rule set.

Cross-org isolation: `GetEffectivePermissionsByIDs` resolves grants per-org, so a viewer who has access only in another org gets `HasContractAccess(addr) == false` here. Anonymous / system groups are excluded explicitly.

**Per-tx blast-radius cap:** `visibleTo` lists at `eth_sendTransaction` time are capped at **32 entries** (`server.visibleToMaxSize`). Larger lists are rejected with HTTP 400. Operators with legitimate >32-recipient flows should use a dedicated group + grant instead.

**Matrix:**

| Viewer in eligible group on contract? | Listed in tx's `visibleTo`? | `allow_visibleto_unlock` flag | Outcome on that tx's events |
|---------------------------------------|-----------------------------|-------------------------------|------------------------------|
| Yes | Yes | true | **All events visible**, no field redaction (unlock fires) |
| Yes | No | true | Existing event_rules apply (unchanged) |
| Yes | Yes | false | Existing additive widening (unchanged — RD-842 / param-rule fallback) |
| No (cross-org or no group) | Yes | true | Denied (eligibility gate fails) |
| Anonymous viewer | Yes | true | Denied (no `users` row) |
| Eligible but membership later revoked | Was previously listed | true | Denied at next request — eligibility is checked at request-time (`RedactionEngine.RedactLogs` runs per-request; cache invalidated on grant change via `InvalidateOrg`) |

**RPC and explorer use the same eligibility gate** — `rbac.IsViewerEligibleForVisibleToUnlock` is the single source of truth. RPC layer pre-resolves it via `processor_event_rules.go::buildVisibleToUnlockableMap`; explorer pre-resolves via `dbVisibleToUnlockResolver` wired through `wireExplorerRedactor`. Both feed an `UnlockableContracts map[string]bool` into the per-log decision so it stays O(1) per log.

**Auditability note:** with the flag on, the set of users who can see a contract's events grows beyond what `groups + grants` enumeration alone shows — the active set is `(groups + grants) ∪ (every DID listed in any tx's visibleTo)`. Operators who flip the flag should plan for that surface in access-review tooling. The flag itself is a single boolean per contract; flips go through the admin API and are subject to whatever audit log the API surface uses.

### 3.8 RPC Layer (`eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getLogs`, `eth_getBlockByNumber`, `eth_getBlockReceipts`)

At the RPC layer, visibility is binary: the caller either is or is not a participant (one of their linked addresses matches `from` or `to`).

| Method | Participant behavior | Non-participant behavior | Implemented | Tested |
|--------|---------------------|--------------------------|-------------|--------|
| `eth_getTransactionByHash` | Full transaction returned | `null` | Yes | Yes |
| `eth_getTransactionReceipt` | Full receipt with logs | `null` | Yes | Yes |
| `eth_getLogs` | Entries where a topic address matches a linked address | Entry removed from array | Yes | Yes |
| `eth_getLogs` topics[0..3] | All 4 slots scanned for private addresses | Non-matching entries removed | Yes | Yes |
| `eth_getLogs` data field (no ABI) | Whole log denied at RPC layer regardless of event_rules; explorer layer also denies via the unified ABIResolver | — | Yes | Yes | G5 closed (RD-875 RPC + RD-889 explorer) — see §3.4 row for `data (when emitter full + NO ABI)` |
| `eth_getBlockByNumber` (`fullTxObjects=true`) | Full block; all txs | Non-participant txs removed | Yes | Yes |
| `eth_getBlockByNumber` (`fullTxObjects=false`) | Passes through | Passes through | Yes | Yes |
| `eth_getBlockReceipts` | All receipts in block | Non-participant receipts removed | Yes | Yes |
| `logsBloom` in blocks | All-zero (256 bytes) for every viewer | — | Yes | Yes | G6 closed (RD-873) |

### 3.9 Token (Explorer API)

Token visibility is determined by the token's contract address. If the address is registered as an org contract in the RBAC database, the token inherits that contract's visibility. Unregistered addresses default to `VisibilityHidden` (all contracts are private by default).

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

**Grant holder visibility:** Any user whose group has a `contract_grant` on a token's contract address sees the token with `VisibilityFull` — full name, symbol, supply, and holder count are visible. This aligns with RPC access: if you can call `balanceOf()` on the contract, hiding its name in the token list is security theater.

**List total:** The `total` field in `/tokens` reflects the count after filtering, never the raw database count.

---

## 4. Known Gaps

The following gaps are numbered. G1, G2, G3, G5, G6, G7, G8, G9, G11, G14, G16, G22 are resolved. G4, G15 are outstanding.

### Resolved

- **G1 (resolved):** Nonce not stripped when sender was hidden — now nil when `from` is Hidden/Redacted.
- **G2 (resolved):** `value` and `inputData` not zeroed for mixed-party txs (one side hidden) — now zeroed when either side is Hidden or Redacted.
- **G3 (resolved):** Log topics[1..3] not scanned for embedded address parameters — now scanned for all logs where emitter is Full; private addresses zeroed.
- **G5 (resolved, RD-875 + RD-889 + RD-890):** Log.data not scanned when no ABI registered — without an ABI neither layer could decode non-indexed `address`-typed parameters in event data, leaking private addresses verbatim. Both layers now fail closed when no ABI is resolvable for the emitting contract: RPC layer in `rbac.FilterEventLogs` (RD-875) — denies regardless of `event_rules`; explorer layer in `RedactionEngine.RedactLogs` (RD-889) via the unified `explorer.ABIResolver` (wired to `rbac.Store` + `rbac.ResolveContractABI`). RD-890 closed the admin-bypass asymmetry by adding `explorer.AdminContractsResolver`, wired to `rbac.AccessController`, which mirrors the RPC layer's per-contract `isAdminByContract` map — tier-2 (`is_org_admin`) and tier-3 (per-contract `admin` claim) viewers bypass the deny gate on both layers. Resolvable means a custom upload OR `metadata.token_type` matching the built-in registry (ERC-20 / ERC-721). Grant save handlers (create + update) reject non-deny `event_rules` up-front when no ABI is resolvable, so admins get a clear 400 instead of silently saving rules that won't fire. Closes `decisions.md` §2 G5.
- **G6 (resolved, RD-873):** Block-level `logsBloom` not zeroed — bloom filter contained hashed representations of addresses and event topics from every log in the block; a viewer who knew a target address could probe activity in O(1). Now overwritten with an all-zero 256-byte value on every block-returning RPC response (`eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getBlockReceipts`) regardless of viewer or block shape. The previous "expensive per-block scanning" cost vanished once we accepted that clients of a privacy proxy can't usefully consume the bloom anyway — sanitisation is a single field overwrite.
- **G7 (resolved):** Transaction.contractAddress leaks deployed address — contract deployment transactions from hidden deployers are now dropped entirely via SQL-level visibility filtering.
- **G8 (resolved):** TokenHolder entries not dropped when address is Hidden — now dropped.
- **G9 (resolved):** Log entries not dropped when emitter is Hidden — now dropped entirely.
- **G14 (resolved):** Token endpoints (`/tokens`, `/tokens/:address`, `/tokens/:address/holders`, `/tokens/:address/transfers`) returned raw unredacted token data without any visibility checks. Now: Hidden tokens are dropped from lists and return 404 from single-token endpoints. Redacted tokens have sensitive fields masked (`[PRIVATE]`, nil names/symbols, zeroed counts). Sub-endpoints (holders, transfers) return 404 for Hidden or Redacted token addresses. List total reflects filtered count only.
- **G22 (resolved): Address page transaction count not filtered**
  The `/addresses/:address/stats` endpoint returned the pre-computed `tx_count` from the `address_stats` table without applying visibility filtering. A viewer who could only see 2 of 12 transactions still saw "Transactions: 12", leaking the total activity volume of the address. Same class of issue as RD-758 (fixed for paginated list endpoints and block counts) but missed for address summary counts. Fixed: the handler now computes a live `COUNT(*)` from the `transactions` table with the SQL-level visibility filter applied via `GetAddressTransactionCountFiltered`, overriding the stale `address_stats.tx_count`. The filter is built per-viewer using `buildVisibilityFilter`, matching the pattern used by block transaction counts.

### Outstanding

- **G4: InternalTransaction.error not stripped**
  Error strings returned from trace calls can contain raw revert messages or embedded addresses (e.g. `execution reverted: caller 0xABCD... not authorized`). When either side of the internal call is Hidden or Redacted, the `error` field must be set to nil before the response is returned. Currently returned unmodified.

- **G10: One-side-hidden transactions leak activity metadata**
  When only one party in a transaction/transfer is hidden and the other is public, the entry survives the SQL visibility filter. The hidden side is masked (`[PRIVATE]`), but the viewer still learns that *some* private party interacted with the visible address — including timing, block number, gas used, and transfer amounts. For example, a non-participant can see "someone private called [public contract]." On a private network this metadata may be sensitive. The stricter alternative — drop if ANY side is hidden unless viewer is a participant — would eliminate this leak but significantly reduce explorer utility for public addresses. **Decision pending**: track as a design tradeoff. If tightened, the participant override in `RedactTransactions`/`RedactTransfers`/`RedactInternalTransactions` ensures participants still see their own activity.

- **G11 (resolved, then redesigned): Visibility admin check — 3-tier model**
  Admin visibility on org contracts is now granted through two paths only: `is_org_admin = true` (tier 2, sees ALL org contracts) or any `contract_grant` on the specific contract (any claim including admin). The `'admin' = ANY(group_access.claims)` path was **removed** as part of the 3-tier admin model: contract admins (tier 3, admin claim without `is_org_admin`) now see only contracts explicitly granted to their group, not all org contracts. This is intentional — tier 3 is scoped to specific contracts. Any grant holder (regardless of claims) still sees their granted contracts as Full. **History:** Originally fixed in PR #84, regressed in PR #87, re-fixed, then redesigned with the 3-tier admin model.

- **G12: Org admin cannot see user EOA activity (contract deployments, EOA transfers)**
  Org admins have `VisibilityFull` on org contracts but user EOAs remain `VisibilityHidden`. This means: EOA-to-EOA transfers are dropped, contract deployments from user EOAs are dropped, and the deployer's address shows as `[PRIVATE]` in surviving contract call txs. For an org admin auditing their network, not seeing who deployed which contract or who transferred ETH to whom is a significant gap. **Options:** (a) org admins automatically get visibility on all EOAs of users who are members of any group in that org, (b) require explicit disclosure grants from users, (c) add a new "audit" role that unlocks EOA visibility. **Decision pending.**

- **G13: Minting from zero address to private recipient visible to non-participants**
  Token mints (`from=0x0000...0000, to=private_address`) survive the SQL filter because the zero address is public (not in contracts or eth_address_links). Non-participants can see "someone private received a mint from [token contract]" — revealing that a private user received tokens, when they did, and from which contract. This is a specific case of G10 but worth calling out separately because mint events are particularly sensitive (they reveal token distribution to specific parties). **Options:** (a) treat zero address as neutral rather than public for visibility purposes, (b) handled by G10 if the stricter drop rule is adopted. **Decision pending.**

- **G15: Address parameters in URL paths leak real addresses**
  All `/addresses/:address/...` endpoints embed real addresses in URLs visible in server logs, network intermediaries, and browser history. An untrusted block explorer client that knows a private address can confirm its existence by requesting its sub-endpoints (even if the response is 404, the address appears in access logs). This is a design-level issue requiring API redesign (e.g., opaque address IDs instead of raw hex addresses in URL paths).

- **G16 (resolved): `check-address` enumeration vector closed**
  The `/check-address/:address` and `/check-addresses` endpoints were removed entirely. Address visibility is now communicated inline via `addressMetadata` fields in explorer API responses (PR #96), eliminating the enumeration oracle.

- **G17 (resolved): Disclosure grants now visible in regular explorer views**
  `GetBatchVisibility` and `GetBatchVisibilityDetailed` check active full-disclosure grants for the viewer. Disclosed addresses are upgraded to `VisibilityFull` with reason `"disclosure_grant"` in `addressMetadata`. The block explorer renders this as a "Disclosed" label (purple badge). This replaces the previous design where grants were hidden from regular views.

- **G18 (resolved): "Disclosed" label appears in regular pages for disclosure grant recipients**
  Disclosure grant recipients see disclosed addresses labeled "Disclosed" in regular Transactions, Token Transfers, and address pages. The `addressMetadata` includes `"disclosure_grant"` as the reason, which the frontend renders as a purple "Disclosed" badge.

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

Do not allow a gap to become invisible through test omission. For each known gap (G4, G6), write a test that:
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

---

## 7. visibleTo — Per-Transaction Visibility Grants

The `visibleTo` parameter (renamed from `logVisibleTo`) allows a transaction sender to grant full transaction and log visibility to specific DIDs.

### Usage

When sending a transaction via `eth_sendTransaction` or `eth_sendRawTransaction`, include a `visibleTo` field with an array of DIDs:

```json
{
  "method": "eth_sendTransaction",
  "params": [{
    "from": "0x...",
    "to": "0x...",
    "data": "0x...",
    "visibleTo": ["did:privado:alice", "did:privado:bob"]
  }]
}
```

For raw transactions, pass it as a second parameter:

```json
{
  "method": "eth_sendRawTransaction",
  "params": ["0xf86c...", {"visibleTo": ["did:privado:alice"]}]
}
```

### Behavior

- The `visibleTo` field is stripped before forwarding to the node (never sent on-chain).
- The DID list is stored in `tx_visible_to` with the resulting tx hash.
- **Explorer views**: Transactions with `visibleTo` grants appear in regular Transactions and Token Transfers pages for the listed DIDs. The `buildVisibilityFilter` includes these tx hashes as an override to address-based filtering.
- **JSON-RPC filtering**: Listed DIDs can see event logs from these transactions via `eth_getLogs`, even when `must_be=self` param rules would otherwise filter them. This extends (never restricts) existing access.
- **Transaction and receipt access**: `visibleTo` overrides participant checks for both `eth_getTransactionByHash` and `eth_getTransactionReceipt`. A listed DID receives the full transaction/receipt even if they are not a from/to participant — the sender explicitly chose to share this transaction.

### Storage

Table: `tx_visible_to` (migration 040, renamed from `tx_log_visible_to`)

| Column | Type | Description |
|--------|------|-------------|
| tx_hash | TEXT | Transaction hash (lowercase) |
| visible_to_dids | TEXT[] | Array of DIDs granted visibility |
| sender_did | TEXT | DID of the transaction sender |
| org_id | TEXT | Organization ID of the sender |
| created_at | TIMESTAMPTZ | When the rule was created |


---

## 8. Admin dry-run / impersonation (RD-872)

A tier-2 org admin can ask the proxy "what would user X see if they made this RPC call?" via `POST /api/orgs/:org_id/dry-run`. The endpoint is an *ergonomics* tool — it does NOT expand the admin's data reach.

### Why it's safe at this scope

- A tier-2 org admin already holds `AllClaims()` on every contract in their own org via `computeOrgAdminPermissions`. Any data the dry-run pipeline can reveal to them is already in their reach via direct RPC/explorer calls. Net new data: **zero**.
- The endpoint does no JWT minting at any point. The "impersonated user" is a synthetic principal constructed inside the request handler from `(user.ID, :org_id)`; it is never persisted, never returned, never auth-credentialed.
- Multi-org users are **structurally invisible across orgs**: `EffectivePermissions` are resolved scoped to admin's `:org_id` via `GetEffectivePermissionsByIDs(userID, :org_id)`. A user who is also in Org B has Org B's grants resolved to nothing in this context.

### Hard gates

| Gate | Enforcement | Failure |
|---|---|---|
| Super-admin token (`X-Admin-Token`) is **rejected** | `auth_method == "admin_token"` check at the top of `handleDryRun` | 403 with explicit reason. Super-admin's design role is admin-of-admins; impersonation would invent data-layer reach they don't have today. |
| Tier-2 admin of `:org_id` only | adminAuthMiddleware + orgScopingMiddleware enforce upstream; handler trusts `admin_subject` | tier-3 admins fail at orgScoping; non-admins fail at adminAuth. |
| Self-dry-run rejected | `req.UserDID == adminDID` check | 400 — would skew audit reasoning. |
| Method allowlist | `dryRunReadMethods` ∪ `dryRunTraceMethods` | 400 with the supported set listed. |
| Cross-org user invisible | `GetUserOrgIDs(user.ID)` must include `:org_id` | generic 404 "user not found" — identical to "user does not exist." |
| Same RBAC pipeline | `CheckAccess` runs as the impersonated user with their own `EffectivePermissions` | no parallel implementation that could diverge from real-request behaviour. |

### Write-method translation (`debug_traceCall`)

Both write-method shapes are rewritten to `debug_traceCall` against the upstream node — current state, no commit. The `callTracer` preset with `withLog: true` returns nested call frames + emitted logs; the handler walks the frames, extracts logs, and runs them through `rbac.FilterEventLogs` with the impersonated user's perms so the response includes both `logs_emitted` (full trace logs) and `logs_visible_to_user` (the subset they would actually see in `eth_getTransactionReceipt`).

`eth_sendRawTransaction` is RLP-decoded via the same production helper (`decodeRawTransaction` in `internal/server/jsonrpc_processor.go`) used by the real-call path. Sender is recovered from the signature using the chain-id-aware signer; the trace then runs against `(from, to, data, value)` exactly as a real raw-tx call would. A malformed signed blob returns a clean decode error rather than a silent pass.

If the upstream node doesn't expose `debug_*`, write-method dry-run returns "node does not support debug_traceCall — dry-run for write methods unavailable." Read-method dry-run continues to work.

### Audit log (`impersonation_log`)

Migration **046** adds the dedicated table. Every dry-run writes one row with:

- `actor_did` — the calling admin's DID (from JWT)
- `impersonated_did` — the user being dry-run-as
- `org_id`, `method`, `params_hash` (sha256, never raw params), `decision`, `reason`, `correlation_id`, `created_at`

The hash means private addresses or signed-tx blobs in params never persist; reviewers correlate against external request logs. Retention is operator-side; SIEM forwarding (`internal/audit/siem.go`) handles tamper evidence.

### Out of scope

- Dashboard "View as user" / browse-as flow — Phase 2, deferred (see RD-872).
- Tier-3 admin / Read-Only Admin / super-admin dry-run — explicit NO. Each adds real attack surface that the tier-2-only argument doesn't cover.
- JWT minting / impersonation tokens — never. The synthetic principal is a per-request struct; if it leaked, it would be a bug.
