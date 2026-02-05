# Runtime Validation Analysis

## Overview

This document analyzes the proposed runtime validation approach using transaction tracing (`debug_traceCall`) and identifies contradictions with existing documentation, security gaps, and performance/adoption concerns.

## Proposed Approach Summary

**Current approach** (BYTECODE_VALIDATION_REQUIREMENTS.md):
- Validate at **deployment time** only
- Block dynamic calls (SLOAD-based addresses)
- Require hardcoded/immutable addresses

**Proposed enhancement** (DEPLOYMENT_WORKFLOW.md):
- Continue deploy-time validation
- Add **runtime validation** via `debug_traceCall`
- Trace every transaction to verify call targets

---

## Contradictions with Existing Documentation

### 1. `debug_*` Methods Are Globally Blocked

**SECURITY.md (line 10-11):**
```
debug_*              - Tracing/debugging (info disclosure, DoS)
```

**DEPLOYMENT_WORKFLOW.md proposes:**
```
debug_traceCall(tx) → get all internal calls
```

**Resolution Required:**
- The proxy must use `debug_traceCall` internally (server-side)
- It should remain blocked for external users
- Need to distinguish between internal proxy use and user requests
- Implementation: Call upstream node directly, bypassing the blocklist for internal operations

### 2. "Cannot Sandbox at Execution Time"

**BYTECODE_VALIDATION_REQUIREMENTS.md (line 18-20):**
> "The privacy proxy cannot sandbox contracts at **execution time** because it doesn't run the EVM. Instead, sandboxing must happen at **deployment time** through bytecode analysis."

**New approach:**
- Uses `debug_traceCall` to sandbox at runtime
- This is an architectural shift from the documented model

**Resolution Required:**
- Update BYTECODE_VALIDATION_REQUIREMENTS.md to reflect hybrid approach
- Document that runtime validation is now part of the security model
- Clarify: deploy-time validation prevents malicious bytecode, runtime validation prevents cross-org calls

### 3. eth_sendRawTransaction Blocked

**SECURITY.md (line 19):**
> "eth_sendRawTransaction - Pre-signed transactions (bypasses ALL validation)"

**Impact on proposed workflow:**
- Many dev tools (Hardhat, Foundry) use `eth_sendRawTransaction`
- The proposed Hardhat plugin would need to use `eth_sendTransaction`
- This may break compatibility with some workflows

**Resolution Options:**
1. **Accept limitation**: Document that only `eth_sendTransaction` works
2. **Decode raw transactions**: Parse the signed tx to extract sender/target/data, then validate
3. **Hybrid**: Allow raw transactions after decoding and validating (complex)

**Recommendation:** Option 2 - decode and validate raw transactions. This enables full tooling compatibility.

---

## Security Gaps

### 1. State Change Between Simulation and Execution

**The Problem:**
```
Time T0: Simulate transaction → passes validation
Time T1: Another transaction modifies state
Time T2: Execute our transaction → different behavior than simulation
```

**Scenarios:**
- A storage slot is modified between simulation and execution
- A new contract is deployed to an address we validated against
- An org's permissions change mid-flight

**Risk Level:** Medium

**Mitigations:**
1. **Accept the risk**: For most use cases, state changes are rare
2. **Post-execution audit**: Trace actual execution and flag violations (non-blocking)
3. **Locking**: Hold a mutex during simulate→execute (adds latency)
4. **Idempotent retries**: If execution differs from simulation, retry with fresh trace

**Recommendation:** Accept risk for now, implement post-execution auditing as Phase 2.

### 2. Cross-Org DELEGATECALL Not Fully Validated

**BYTECODE_VALIDATION_REQUIREMENTS.md (line 105-111):**
> "If Org B DELEGATECALLs to Org A's contract... Org B effectively interacts with Org A's contracts"

**Implementation Status (line 419):**
> "[ ] Cross-org DELEGATECALL validation at deployment"

**Gap:** A contract in Org B could DELEGATECALL to Org A's contract, which then makes static CALLs to other Org A contracts. The proxy wouldn't intercept those calls since they happen on-chain.

**How Runtime Tracing Helps:**
- Trace shows all DELEGATECALL targets
- Trace shows all subsequent CALLs made during DELEGATECALL
- Can verify the entire call tree stays within authorized addresses

**Action Required:** Runtime tracing specifically addresses this gap. Ensure the implementation validates the FULL call tree, not just top-level calls.

### 3. Custom Multicall Contracts

**SECURITY.md (line 39-44):**
> "Calls to known Multicall contracts are blocked:
> - Multicall3: 0xcA11bde05977b3631167028862bE2a173976CA11"
> ...
> "Custom multicall contracts could bypass"

**Gap:** Only 3 specific addresses are blocked. A custom multicall contract could batch arbitrary calls.

**How Runtime Tracing Helps:**
- Traces all internal calls made by any contract
- Custom multicall's batched calls would all appear in trace
- Each batched call validated against permissions

**Action Required:** Runtime tracing resolves this gap. Consider removing hardcoded multicall blocking as it becomes redundant.

### 4. Storage Slot Modification Detection

**Implementation Status (BYTECODE_VALIDATION_REQUIREMENTS.md line 418):**
> "[ ] Storage slot modification detection"

**Gap:** A contract could write to a storage slot that another contract reads as an address, enabling indirect cross-org communication.

**How Runtime Tracing Helps:**
- `debug_traceCall` shows all SSTORE operations
- Can detect writes to storage slots that might be addresses
- Can track cross-contract storage dependencies

**Action Required:** Consider whether this level of monitoring is needed. It adds complexity and may have false positives.

### 5. CREATE/CREATE2 Inside Contracts

**BYTECODE_VALIDATION_REQUIREMENTS.md (line 124):**
> "CREATE/CREATE2 | **BLOCK** | Bypasses address preregistration"

**Gap:** Currently blocked at deploy time, but if a contract somehow has CREATE, runtime validation should catch it.

**How Runtime Tracing Helps:**
- Trace shows CREATE/CREATE2 operations
- Can reject transactions that attempt contract creation
- Adds defense in depth

**Action Required:** Implement CREATE/CREATE2 detection in runtime traces as additional security layer.

---

## Performance Analysis

### Baseline: Current Approach (Deploy-Time Only)

| Operation | Latency | Notes |
|-----------|---------|-------|
| Deploy tx | +50-200ms | Bytecode analysis |
| Runtime tx | ~0ms overhead | Direct forwarding |

### Proposed: Runtime Tracing

| Operation | Latency | Notes |
|-----------|---------|-------|
| Deploy tx | +50-200ms | Bytecode analysis |
| Runtime tx | +100-500ms | Trace simulation |

### Tracing Performance Details

**`debug_traceCall` characteristics:**
- Executes transaction in EVM (full execution)
- Records every opcode execution
- Returns structured trace with all operations

**Typical latency by transaction complexity:**

| Transaction Type | Trace Time | Total Overhead |
|-----------------|------------|----------------|
| Simple transfer | 20-50ms | ~2x baseline |
| Single contract call | 50-100ms | ~2x baseline |
| Multi-hop (3-5 calls) | 100-300ms | ~2-3x baseline |
| Complex DeFi (10+ calls) | 300-1000ms | ~3-5x baseline |

### Mitigation Strategies

1. **Caching**
   - Cache trace results for identical transactions (same sender, nonce, data)
   - Short TTL (seconds) to handle state changes
   - Invalidate on block changes
   - **Estimated improvement:** 50% reduction for repeated patterns

2. **Parallel Tracing**
   - Trace while performing other validations (JWT, RBAC lookup)
   - Pipeline: start trace immediately, check results last
   - **Estimated improvement:** 20-30% latency reduction

3. **Trusted Contract Mode**
   - Skip tracing for contracts marked as "audited" by org admin
   - Org takes responsibility for those contracts' behavior
   - **Estimated improvement:** 100% for trusted contracts

4. **Tiered Validation**
   - Quick check: is target address in org's allowlist? → skip trace
   - Full trace only for calls to unregistered addresses
   - **Estimated improvement:** 70% for typical intra-org calls

5. **Batch Optimization**
   - If multiple txs in same block, trace together
   - Share state snapshots between traces
   - **Estimated improvement:** 30% for high-throughput scenarios

### Recommended Approach

**Phase 1: Tiered Validation**
```
Transaction arrives
    │
    ▼
Is target address registered to sender's org?
    │
  ┌─┴─┐
  YES  NO
  │    │
  ▼    ▼
Skip   Full trace
trace  validation
```

**Phase 2: Add Caching**
- Cache (tx_hash, trace_result) with 10-second TTL
- Invalidate on new block

**Phase 3: Trusted Contract Mode**
- Admin can mark contracts as "trusted"
- Trusted contracts skip runtime validation

---

## Adoption Concerns

### 1. Node Compatibility

**Issue:** Not all Ethereum nodes support `debug_traceCall`

| Node | `debug_traceCall` Support |
|------|---------------------------|
| Geth | ✓ (with --http.api debug) |
| Anvil | ✓ |
| Hardhat Network | ✓ |
| Erigon | ✓ |
| Nethermind | ✓ |
| Infura | ✗ (limited) |
| Alchemy | ✓ (archive) |

**Mitigation:** For private chains (the target use case), operators control the node and can enable debug APIs.

### 2. Developer Experience

**Concerns:**
- Increased latency for all transactions
- Potential for false positives (trace finds issue that wouldn't occur)
- More complex error messages when validation fails

**Mitigations:**
- Clear error messages explaining what address failed validation
- Dev mode with verbose trace output for debugging
- Option to run "dry-run" before actual submission

### 3. Tooling Requirements

**Required changes to Hardhat plugin:**
- Must use `eth_sendTransaction` (or decode raw tx)
- Should handle validation failures gracefully
- Should support "trusted contract" configuration

---

## Comparison: Deploy-Time vs Runtime Validation

| Aspect | Deploy-Time Only | With Runtime Tracing |
|--------|-----------------|---------------------|
| **Security** | Good for static patterns | Comprehensive |
| **Dynamic calls** | Blocked | Validated |
| **Cross-org DELEGATECALL** | Partial | Full |
| **Custom multicall** | Vulnerable | Protected |
| **Performance** | No runtime overhead | 2-5x latency |
| **Compatibility** | Requires contract changes | Works with more contracts |
| **Complexity** | Simpler | More complex |

---

## Recommendations

### Must Do

1. **Resolve debug API contradiction**
   - Allow internal use of `debug_traceCall`
   - Keep blocked for external user requests

2. **Implement tiered validation**
   - Skip trace for known org-owned addresses
   - Full trace only when needed

3. **Update documentation**
   - Reconcile SECURITY.md with new approach
   - Update BYTECODE_VALIDATION_REQUIREMENTS.md

### Should Do

1. **Implement trace caching**
   - Reduces repeated validation overhead

2. **Add trusted contract mode**
   - Allows orgs to opt-out for performance

3. **Decode eth_sendRawTransaction**
   - Enables full tooling compatibility

### Nice to Have

1. **Post-execution auditing**
   - Compare simulation trace to actual execution
   - Flag discrepancies for review

2. **Storage slot monitoring**
   - Detect address-like values in storage

---

## Implementation Priority

| Priority | Item | Effort | Impact |
|----------|------|--------|--------|
| P0 | Internal debug API access | Low | Blocker |
| P0 | Basic runtime trace validation | Medium | Security |
| P1 | Tiered validation (skip for known addresses) | Medium | Performance |
| P1 | Update security documentation | Low | Clarity |
| P2 | Trace caching | Medium | Performance |
| P2 | Decode raw transactions | Medium | Compatibility |
| P3 | Trusted contract mode | Low | Flexibility |
| P3 | Post-execution auditing | High | Assurance |

---

## Conclusion

Runtime tracing via `debug_traceCall` addresses several security gaps in the current deploy-time-only approach:
- Validates dynamic calls that were previously blocked
- Catches custom multicall contracts
- Enables full cross-org DELEGATECALL validation

**Trade-offs:**
- **Performance**: 2-5x latency increase (mitigatable)
- **Complexity**: More moving parts
- **Node requirements**: Must support debug APIs

**Recommendation:** Proceed with implementation using tiered validation to minimize performance impact for common cases. The security benefits outweigh the performance costs for a privacy-focused blockchain.
