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
| `contractAddress` | **unchanged** | **unchanged** | **unchanged** | unchanged | **No** | No | **GAP G7** — deploy tx leaks deployed contract address when deployer is hidden |
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

**Security invariant:** The override ONLY applies within `RedactTransactions`, which processes a specific transaction list. It does NOT affect `GetBatchVisibility` or `GetBatchVisibilityDetailed` (used by the address visibility check endpoint). A counterparty address visible via participant override in a transaction list will still show as Hidden when queried individually via `/check-address`.

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

---

## 4. Known Gaps

The following gaps are numbered. G1, G2, G3, G8, G9 are resolved. G4–G7 are outstanding.

### Resolved

- **G1 (resolved):** Nonce not stripped when sender was hidden — now nil when `from` is Hidden/Redacted.
- **G2 (resolved):** `value` and `inputData` not zeroed for mixed-party txs (one side hidden) — now zeroed when either side is Hidden or Redacted.
- **G3 (resolved):** Log topics[1..3] not scanned for embedded address parameters — now scanned for all logs where emitter is Full; private addresses zeroed.
- **G8 (resolved):** TokenHolder entries not dropped when address is Hidden — now dropped.
- **G9 (resolved):** Log entries not dropped when emitter is Hidden — now dropped entirely.

### Outstanding

- **G4: InternalTransaction.error not stripped**
  Error strings returned from trace calls can contain raw revert messages or embedded addresses (e.g. `execution reverted: caller 0xABCD... not authorized`). When either side of the internal call is Hidden or Redacted, the `error` field must be set to nil before the response is returned. Currently returned unmodified.

- **G5: Log.data not scanned when no ABI registered (partial)**
  When an event log's emitting contract has a registered ABI, non-indexed `address`-typed parameters in `data` are decoded and private addresses zeroed. When no ABI is registered, the raw ABI-encoded `data` blob is returned unmodified. A private address embedded as a non-indexed parameter in an unverified contract's log will not be redacted. This applies to both the Explorer API and `eth_getLogs` at the RPC layer. Accepted as a limitation — no fix planned until ABI scanning can be done heuristically.

- **G6: Block.logsBloom not zeroed**
  The `logsBloom` field in block headers is a Bloom filter over the addresses and topics of all logs in the block. It contains hashed (not raw) representations of addresses. A viewer who already knows a target address can probe whether that address has activity in a given block in O(1). Zeroing the bloom field for all blocks would require per-block address scanning against the private address registry, which is expensive. Risk is low — probabilistic membership test only, requires knowing the target address. Accepted for now; track as a future hardening item.

- **G7: Transaction.contractAddress leaks deployed address when deployer is hidden**
  When a deploy transaction (`to == null`, `contractAddress != null`) is made by a Hidden or Redacted address, the resulting `contractAddress` is included in the redacted transaction object. A viewer can learn a new contract address was deployed by the private party. This is meaningful because the deployed contract may itself be discoverable via block explorer and correlatable. The `contractAddress` field should be set to nil when the sender is Hidden or Redacted. Currently not implemented.

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
| Deploy tx, sender Hidden | `contractAddress` → nil (currently failing — G7) |
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
