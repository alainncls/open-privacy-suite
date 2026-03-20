# Granular RBAC Checkbox Grouping

## Goal Description
Improve the [GroupAccessForm](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx#17-460) UI to display RPC methods in granular sub-categories, rather than treating "Read" and "Write" as single monolithic buckets. This solves the UX issue of having to uncheck dozens of methods to block deep state reads (like `eth_getStorageAt`), while leveraging the existing RBAC backend schemas and parent-inheritance models.

## User Review Required
> [!IMPORTANT]
> - `debug_` and `trace_` methods are **globally blocked** in the backend ([internal/rbac/access.go](file:///Users/blade/work/software/privacy-proxy/internal/rbac/access.go) inside `GlobalBlockedMethods`), regardless of claims. Because of this, they do not appear in [types/rbac.ts](file:///Users/blade/work/software/privacy-proxy/frontend/src/types/rbac.ts) at all. Therefore, we do not need to factor them into our UI!
> - As you mentioned, the **Parent Group** inheritance model perfectly replaces the need for "templates". An admin can create a root `Engineer Base` group, and then create subgroups that inherit from it, making UI sub-grouping the *only* thing we need to build.

## Proposed Changes

### 1. [frontend/src/types/rbac.ts](file:///Users/blade/work/software/privacy-proxy/frontend/src/types/rbac.ts)
We will replace the flat `RPC_METHODS_BY_CLAIM` model with a structured grouping, while preserving the array exports for backwards compatibility.

#### [MODIFY] [rbac.ts](file:///Users/blade/work/software/privacy-proxy/frontend/src/types/rbac.ts)
- Add a new `METHOD_CATEGORIES` constant that maps groups to methods:
  ```ts
  export const METHOD_CATEGORIES = {
    read: {
      "Chain & Network Info": ['eth_chainId', 'eth_blockNumber', 'net_version', 'net_listening', 'net_peerCount', 'web3_clientVersion', 'web3_sha3', 'eth_syncing', 'eth_accounts'],
      "Accounts & Blocks": ['eth_getBalance', 'eth_getTransactionCount', 'eth_getBlockByHash', 'eth_getBlockByNumber', 'eth_getBlockTransactionCountByHash', 'eth_getBlockTransactionCountByNumber'],
      "Past Activity (Explorer & Logs)": ['eth_getTransactionByHash', 'eth_getTransactionReceipt', 'eth_getTransactionByBlockHashAndIndex', 'eth_getTransactionByBlockNumberAndIndex', 'eth_getLogs'],
      "Contract Execution": ['eth_call', 'eth_estimateGas'],
      "Deep State Inspection": ['eth_getCode', 'eth_getStorageAt'],
      "Gas & Fee Data": ['eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory'],
      "Filters (Deprecated)": ['eth_newFilter', 'eth_newBlockFilter', 'eth_newPendingTransactionFilter', 'eth_getFilterChanges', 'eth_getFilterLogs', 'eth_uninstallFilter']
    },
    write: { ... (similar grouping) }
  }
  ```

### 2. [frontend/src/components/rbac/GroupAccessForm.tsx](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx)
We will update the [renderMethodSection](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx#198-289) to render nested visual groups rather than a single flat list.

#### [MODIFY] [GroupAccessForm.tsx](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx)
- Modify [renderMethodSection](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/GroupAccessForm.tsx#198-289) so that if `hasClaim && isExpanded` is true, it iterates over `METHOD_CATEGORIES[claimType]` keys.
- For each category, display a small sub-header (e.g., `<h4 className="text-xs font-semibold text-neutral-500 mt-2 mb-1">{categoryName}</h4>`) alongside its own miniature "Select All / Clear" button.
- Render the corresponding checkboxes under each sub-header.

## Verification Plan

### Automated Tests
- Run `npm run test` (or `npm run vitest`) in `frontend` to ensure imports or logic relying on `RPC_METHODS_BY_CLAIM` are not broken by the addition of the new constants, or by tweaking the UI components.
- Inspect [frontend/src/components/rbac/__tests__/GroupAccessForm.test.tsx](file:///Users/blade/work/software/privacy-proxy/frontend/src/components/rbac/__tests__/GroupAccessForm.test.tsx) and run it individually: `npx vitest run src/components/rbac/__tests__/GroupAccessForm.test.tsx`

### Manual Verification
- Render the frontend locally.
- Navigate to the RBAC Manager -> Groups tab.
- Click equivalent of "Settings/Access" on a group.
- Verify "Read Methods" correctly splits into `Chain & Network`, `Deep State Inspection`, etc.
- Verify the sub-section "Select All" correctly selects only its children checkboxes.
