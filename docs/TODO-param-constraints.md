# ~~TODO~~ DONE: Parameter-Level Access Control

> **Status: Implemented.** See `internal/rbac/param_validator.go`, `internal/rbac/models.go` (FunctionRule/ParamRule types), and migration `011_function_rules_jsonb.sql`.

## Problem

Users should only be able to query their own data (e.g., `balanceOf(address)` where the address must be their own). Current RBAC controls access at the method and function selector level, but not at the parameter level.

## Prerequisites

1. **ETH address linking** — User's DID must be linked to their ETH address via EIP-191 signature verification (infrastructure exists in `internal/server/auth.go`). Without this, the proxy can't know which ETH address belongs to the authenticated user.
2. **ABI upload** — Contract must have its ABI uploaded (already supported) so calldata can be decoded to extract parameters.

## Design: Parameter Constraints on ContractGrants

Extend `ContractGrant.Functions` from bare selectors (`[]string`) to a structured type with optional parameter rules:

```go
type FunctionRule struct {
    Selector   string      `json:"selector"`
    ParamRules []ParamRule `json:"param_rules,omitempty"`
}

type ParamRule struct {
    Index  int    `json:"index"`   // ABI parameter position (0-based)
    MustBe string `json:"must_be"` // constraint type: "self" for now
}
```

### Constraint Vocabulary

- `"self"` — parameter must match caller's linked ETH address
- Future: `"org_member"` (any address linked to a user in the same org), literal values

### Example

```json
{
  "group_id": "traders",
  "functions": [
    {
      "selector": "0x70a08231",
      "param_rules": [
        { "index": 0, "must_be": "self" }
      ]
    },
    {
      "selector": "0xa9059cbb"
    }
  ]
}
```

This means: members of "traders" can call `balanceOf(address)` only with their own address, but can call `transfer(address,uint256)` with any params.

### Enforcement Flow

1. User calls `balanceOf(0xAddr)` through proxy
2. Proxy matches selector `0x70a08231`, finds param rule `{index: 0, must_be: "self"}`
3. Looks up user's linked ETH address from DID
4. Decodes calldata using uploaded ABI to extract param at index 0
5. Compares: extracted address != linked address → deny
6. For `eth_sendRawTransaction`: sender address is recovered from tx signature and can also be used

### Backwards Compatibility

Grants without `param_rules` work exactly as today (selector-only restriction). The `Functions` field migration:
- Old: `["0x70a08231", "0xa9059cbb"]`
- New: `[{"selector": "0x70a08231", "param_rules": [...]}, {"selector": "0xa9059cbb"}]`

## Known Limitations

- **`eth_getStorageAt`** — A sophisticated user could read raw storage slots to get someone else's balance. Mitigation: block `eth_getStorageAt` for groups with param constraints, or accept the limitation for PoC.
- **Internal calls** — Parameter validation applies to the top-level call only. If a contract internally calls `balanceOf` on behalf of someone else, the proxy can't intercept that.
- **`eth_getLogs` with Transfer events** — Filtering logs could leak other users' transfer history. Would need separate topic filtering rules (future work).
- **Linked address required** — Users without a linked ETH address cannot access functions with param constraints. The proxy should return a clear error ("ETH address linking required").

## Files Modified

1. `internal/rbac/models.go` — `FunctionRule`, `ParamRule` types; `ContractGrant.Functions` and `ContractAccess.Functions` as `[]FunctionRule`; `GetFunctionRule()` on `EffectivePermissions`
2. `internal/rbac/param_validator.go` — `ValidateParamRules()` with ABI-based calldata decoding
3. `internal/rbac/access.go` — Parameter constraint enforcement in `CheckAccess`; `extractCalldata` extended for `eth_call`/`eth_estimateGas`
4. `internal/rbac/resolver.go` — `intersectFunctions`/`unionFunctions` rewritten for `FunctionRule` with param rule merging
5. `internal/db/migrations/011_function_rules_jsonb.sql` — `TEXT[]` → `JSONB` column migration
6. `internal/db/rbac_store_contract.go`, `internal/db/tx_rbac.go` — JSONB marshal/unmarshal
7. `internal/server/admin_rbac_contract.go` — API input types updated to `[]FunctionRule`
8. `frontend/src/types/rbac.ts` — `FunctionRule`, `ParamRule` TypeScript interfaces
9. `frontend/src/components/rbac/ContractGrantForm.tsx` — Param constraint UI with address-type checkboxes
10. `frontend/src/components/rbac/ContractGrantsManager.tsx` — Param rule badge display
