# Implementation Plan: Safe Execution Tracing

## Goal Description
Safely unblock and expose `debug_traceTransaction` and `debug_traceCall` for administrators and deployers. By leveraging the existing `runtimeTracer` and `TraceValidator`, we can guarantee that an Admin can only trace a transaction if 100% of its execution tree occurs within contracts owned by their Organization, flawlessly preventing cross-org data leaks.

## Proposed Changes

### 1. Backend: Unblocking the Methods ([internal/rbac/access.go](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go))
- Remove `debug_tracecall` and `debug_tracetransaction` from the `GlobalBlockedMethods` map.
- This allows them to pass through the initial firewall and reach the RBAC validation layer.

### 2. Backend: Enforcing Claims ([internal/rbac/method_claim.go](file:///Users/blade/work/software/privacy-proxy/internal/rbac/method_claim.go))
- Update [ClassifyOperation()](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go#1028-1058) so that `debug_traceTransaction` and `debug_traceCall` explicitly return either `ClaimAdmin` or `ClaimDeploy`. Currently, methods almost exclusively return `ClaimRead` or `ClaimWrite`.

### 3. Backend: Dynamic Trace Validation ([internal/server/jsonrpc_processor.go](file:///Users/blade/work/software/privacy-proxy/internal/server/jsonrpc_processor.go))
- Intercept the requests in [Process()](file:///Users/blade/work/software/privacy-proxy/internal/server/jsonrpc_processor.go#229-464).
- If a user requests `debug_traceTransaction(txHash)`:
  1. Fetch the transaction from the node to extract `from`, [to](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go#1918-1922), [data](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go#1143-1183), and `value`.
  2. Execute `p.runtimeTracer.TraceTransaction` internally.
  3. Validate the trace using `p.traceValidator.ValidateTrace`.
  4. **The Gate**: If `validationResult.Allowed == true`, forward the actual `debug_traceTransaction` JSON-RPC request to the upstream node and return the raw output to the user. If false, return a 403 Forbidden.

### 4. Documentation & Specs ([REDACTION_SPEC.md](file:///Users/blade/work/software/privacy-proxy/REDACTION_SPEC.md) & [README.md](file:///Users/blade/work/software/privacy-proxy/README.md))
- Update [REDACTION_SPEC.md](file:///Users/blade/work/software/privacy-proxy/REDACTION_SPEC.md) under the RPC Layer section.
- **[NEW RULE]**: Document that `debug_` tracing is allowed **exclusively** when the entire trace tree resolves to addresses owned by the caller's organization.

### 5. Frontend UI Exposition ([frontend/src/types/rbac.ts](file:///Users/blade/work/software/privacy-proxy/frontend/src/types/rbac.ts) & [GroupAccessForm.tsx](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx))
- Currently, the UI only has grids for `Read` claims and `Write` claims. 
- If we tie tracing to the [Deploy](file:///Users/blade/work/software/privacy-proxy/internal/rbac/models.go#253-258) or [Admin](file:///Users/blade/work/software/privacy-proxy/internal/rbac/models.go#406-410) claim, we must update [GroupAccessForm.tsx](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx) to render a brand new accordion specifically for these claims (so an Admin must explicitly opt-in to allowing traces).
- We would add `debug_traceTransaction` and `debug_traceCall` into this new method selection grid.

---
> [!IMPORTANT]
> This is a highly complex feature that requires deep integration between the JSON-RPC processor, the Trace Validator, and the frontend method categorization grids. 
