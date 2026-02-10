# RBAC (Role-Based Access Control) Documentation

## Overview

The Privacy Proxy implements a multi-tenant, hierarchical Role-Based Access Control (RBAC) system that protects blockchain node access. This system allows organizations to define fine-grained permissions for users accessing JSON-RPC methods and smart contracts.

### Key Features

- **Multi-tenant**: Multiple independent organizations with isolated permission hierarchies
- **Hierarchical Groups**: Nested groups with restrictive inheritance (child groups can only narrow parent permissions)
- **Dual Membership**: Users can be assigned via admin API or ZK-attested credentials
- **Contract Ownership**: Track deployed contracts and define owner abilities
- **Caching**: In-memory and database-level caching for high-performance access checks

### Simplified Permission Model (TL;DR)

The RBAC system uses a **group-centric claim model**:

1. **Groups have claims** - Each group defines capabilities (`read`, `write`, `deploy`, `admin`, `upgrade`) via `GroupAccess.claims`. This is the single source of truth.

2. **ContractGrants link groups to contracts** - For registered contracts, a `ContractGrant` establishes which groups can access which contracts. The grant does NOT store claims; claims are inherited from the group.

3. **Unregistered contracts require deploy/admin** - If a contract isn't registered to any organization, only users with `deploy` or `admin` claims can access it. Regular `read`/`write` users must use registered contracts with explicit grants.

4. **Deploy/admin users have broad access in their org** - Users with `deploy` or `admin` claims can access any registered contract in their own org via default claims, without needing explicit `ContractGrant` entries. This means deployers can interact with contracts immediately after deployment and registration.

5. **Read/write users need explicit grants** - Users with only `read` or `write` claims must have a `ContractGrant` linking their group to each contract they need to access.

6. **Org admins bypass everything** - Groups with `is_org_admin: true` give members all claims on all contracts in the organization.

**Quick Reference:**
| Contract Type | Deploy/Admin Users | Read/Write Users |
|--------------|-------------------|-----------------|
| Unregistered | Allowed (default claims) | Denied |
| Registered (own org) | Allowed (default claims) | ContractGrant required |
| Registered (other org) | Denied (cross-org) | Denied (cross-org) |
| Self-deployed | Automatic read+write | Automatic read+write |
| Org admin member | All claims on all contracts | N/A |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Organization                              │
│  (e.g., "gateway", "acme_corp")                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────┐        ┌───────────────────┐             │
│  │      Group        │        │     Contract      │             │
│  │    (root)         │        │   (0x1234...)     │             │
│  │                   │        └───────────────────┘             │
│  │  ┌─────────────┐  │                  ▲                       │
│  │  │ GroupAccess │  │                  │                       │
│  │  │ - methods   │  │     ┌────────────┴────────────┐          │
│  │  │ - claims    │──┼────▶│    ContractGrant       │          │
│  │  │ - rate_limit│  │     │ (links group→contract) │          │
│  │  └─────────────┘  │     │ - functions (optional) │          │
│  └─────────┬─────────┘     └────────────────────────┘          │
│            │                                                     │
│            ▼                                                     │
│  ┌───────────────────┐                                          │
│  │    Group (child)  │   Child groups INHERIT parent claims     │
│  │   (engineering)   │   with INTERSECTION (can only narrow)    │
│  └─────────┬─────────┘                                          │
│            │                                                     │
│            ▼                                                     │
│  ┌───────────────────┐                                          │
│  │   UserMembership  │   User can be in multiple groups         │
│  │   user + group    │   (claims are UNION'd across memberships)│
│  └─────────┬─────────┘                                          │
│            │                                                     │
│            ▼                                                     │
│  ┌───────────────────┐                                          │
│  │       User        │                                          │
│  │   (external_id)   │                                          │
│  └───────────────────┘                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Simplified Permission Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    HOW PERMISSIONS ARE COMPUTED                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Group has claims via GroupAccess                             │
│     GroupAccess { claims: [read, write], methods: [...] }        │
│                                                                  │
│  2. For UNREGISTERED contracts:                                  │
│     → Only deploy/admin users can access                         │
│     → Read/write-only users must use registered contracts        │
│                                                                  │
│  3. For REGISTERED contracts (own org):                          │
│     → Deploy/admin users: allowed via default claims             │
│     → Read/write users: need ContractGrant to contract           │
│     → Claims come from the group's GroupAccess.claims            │
│     → ContractGrant.Functions can restrict which functions       │
│     → FunctionRule.ParamRules can constrain parameters          │
│                                                                  │
│  4. DEPLOYER AUTO-GRANT:                                         │
│     → User who deployed a contract gets read+write automatically │
│     → No explicit grant needed for contracts you deployed        │
│                                                                  │
│  5. ORG ADMIN BYPASS:                                            │
│     → Groups with is_org_admin=true get ALL claims on ALL        │
│       contracts in the organization                              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Organizations

Top-level tenants that contain all RBAC resources. Each organization has:
- Unique slug (e.g., "gateway")
- Display name
- Custom settings (JSONB)

### Groups

Hierarchical permission containers with:
- Parent/child relationships (tree structure)
- Materialized path for efficient queries (e.g., "root.engineering.devops")
- Associated permissions (methods, contracts, rate limits)

### Claims

Claims are capability tokens that grant specific actions. Groups define `claims` (via GroupAccess) that determine what their members can do. This is the **single source of truth** for permission capabilities.

| Claim | Purpose | Required For |
|-------|---------|--------------|
| `read` | Read blockchain state | `eth_call`, `eth_getBalance`, `eth_getCode`, etc. |
| `write` | Modify blockchain state | `eth_sendTransaction` (non-deployment) |
| `deploy` | Deploy new contracts | `eth_sendTransaction` with empty `to`, `eth_estimateGas` for deployment |
| `admin` | Administrative actions | CREATE3 factory deployment |
| `upgrade` | Upgrade proxy contracts | `upgradeTo()`, `upgradeToAndCall()` on managed proxies |

**Simplified Claim Model:**
- Groups have `claims` that define what capabilities members have
- For **unregistered contracts**: Only users with `deploy` or `admin` claims can access them (prevents race conditions with freshly deployed contracts)
- For **registered contracts in own org**:
  - `deploy`/`admin` users: allowed via default claims (no ContractGrant needed)
  - `read`/`write`-only users: need a `ContractGrant` linking their group to the contract, and the group must have the required claims in its `GroupAccess.claims`
- For **registered contracts in other orgs**: always denied (cross-org isolation)
- Multiple memberships combine claims via UNION (user gets all permissions from all groups)

**Deploy claim special handling:**
- Required for contract deployment (`to` field missing/empty/null)
- Also required for `eth_estimateGas` when estimating deployment gas
- Triggers bytecode validation to ensure deployed contracts don't access cross-org resources

**Deployer Auto-Grant:**
When a user deploys a contract, they automatically get `read` and `write` access to that contract, even without explicit grants. This ensures deployers can always interact with contracts they created. Note: This does NOT grant `admin` or `upgrade` claims - those must be assigned via ContractGrants.

### Org Admin Groups

Groups can be marked as "org admin" (`is_org_admin: true`). Members of org admin groups automatically get **all claims** on **all contracts** within that organization. This is useful for administrators who need unrestricted access.

**How it works:**
- When computing permissions, the resolver checks if the user is a member of any org admin group
- If yes, they get all claims (`read`, `write`, `deploy`, `admin`, `upgrade`) on all registered contracts
- Rate limits still apply from their group memberships

### ContractGrant (Simplified)

A `ContractGrant` links a group to a specific contract, enabling members of that group to access the contract with their group's claims.

**Key principle:** The `ContractGrant` no longer stores claims itself. Instead, claims are inherited from the group's `GroupAccess.claims`. The grant just establishes the link and optionally restricts which functions can be called.

```go
// ContractGrant links a group to a contract
type ContractGrant struct {
    ID         string   // Unique identifier
    ContractID string   // The contract being accessed
    GroupID    string   // The group being granted access
    // Claims field is DEPRECATED - claims come from GroupAccess.claims
    Functions  []FunctionRule // Optional: restrict to specific functions (nil = all)
}

type FunctionRule struct {
    Selector   string      // e.g. "0x70a08231"
    ParamRules []ParamRule // Optional parameter constraints
}

type ParamRule struct {
    Index  int    // ABI parameter position (0-based)
    MustBe string // Constraint type: "self" = must match caller's linked ETH address
}
```

**Example:**
```
Group "traders" has claims: [read, write]
ContractGrant links "traders" -> "TokenContract"
Result: Members of "traders" can read and write to "TokenContract"
```

### Permissions

Each group can have associated permissions:
- `allow_methods` - Whitelisted JSON-RPC methods
- `allow_contracts` - Whitelisted contract addresses
- `contract_functions` - Per-contract function selector restrictions (see below)
- `owned_contracts` - Contracts owned by this group
- `rate_limit_rps` - Requests per second limit
- `rate_limit_daily` - Daily request limit

### Contract Function Selectors

For fine-grained contract access control, you can restrict which functions users can call on specific contracts using `ContractGrant.Functions`.

**Format:**
```json
{
  "functions": [
    { "selector": "0x70a08231" },
    { "selector": "0xa9059cbb", "param_rules": [{ "index": 0, "must_be": "self" }] }
  ]
}
```

**Common ERC20 Selectors:**
- `0xa9059cbb` - `transfer(address,uint256)`
- `0x095ea7b3` - `approve(address,uint256)`
- `0x70a08231` - `balanceOf(address)`
- `0x23b872dd` - `transferFrom(address,address,uint256)`

**Behavior:**
- If `functions` is empty/null, all functions are allowed on allowed contracts
- If a contract has function rules, only the listed selectors are allowed
- Selectors are case-insensitive
- Inheritance uses INTERSECTION (child restrictions narrow parent)

### Parameter Constraints

Function rules can include `param_rules` to enforce constraints on individual call parameters. This requires:
1. **ETH address linking** — The user's DID must be linked to their ETH address via EIP-191 signature verification
2. **Contract ABI** — The contract must have its ABI uploaded so calldata can be decoded

**Constraint types:**
- `"self"` — The parameter (must be an `address` type) must match one of the caller's linked ETH addresses

**Example:** Allow `balanceOf` only for the caller's own address:
```json
{
  "selector": "0x70a08231",
  "param_rules": [{ "index": 0, "must_be": "self" }]
}
```

**Enforcement flow:**
1. User calls `balanceOf(0xAddr)` through proxy
2. Proxy matches selector `0x70a08231`, finds param rule `{index: 0, must_be: "self"}`
3. Looks up user's linked ETH addresses from DID
4. Decodes calldata using uploaded ABI to extract param at index 0
5. Compares: extracted address != linked address → deny

**Applies to:** `eth_sendTransaction`, `eth_call`, `eth_estimateGas`, and `eth_sendRawTransaction`

**Known limitations:**
- `eth_getStorageAt` can bypass param constraints by reading raw storage slots
- Internal calls within contracts cannot be intercepted
- `eth_getLogs` topic filtering is not addressed (future work)
- Users without a linked ETH address cannot access functions with param constraints

### Restrictive Inheritance

Child groups can only **narrow** parent permissions, never expand them.

**Example:**
```
Root Group: allow_methods = [eth_call, eth_sendTransaction, eth_getBalance]
  └── Child Group: allow_methods = [eth_call, eth_getBalance]
        └── Grandchild: allow_methods = [eth_call]
```

When computing effective permissions:
1. Traverse from root to leaf group
2. Apply **INTERSECTION** for methods and contracts
3. Apply **UNION** for owned contracts (ownership propagates down)
4. Apply **MINIMUM** for rate limits (most restrictive wins)

### Multiple Memberships

A user can be a member of multiple groups. When computing effective permissions:
1. Compute permissions for each membership (restrictive inheritance)
2. Apply **UNION** across all memberships (user gets combined permissions)
3. Apply **MAXIMUM** for rate limits across memberships

### Multi-Organization Users

Users can be members of groups in multiple organizations. The system handles this through **target-based organization context**:

**How it works:**
1. User sends RPC request targeting a contract
2. System looks up which organization owns the target contract
3. Verifies user is a member of that organization
4. Loads effective permissions from that organization's groups
5. Performs access check using org-specific permissions

**Example:**
```
User: Alice (member of Org A and Org B)

Org A memberships:
  - Group: engineering (allowed_methods: [eth_sendTransaction])

Org B memberships:
  - Group: readers (allowed_methods: [eth_call])

Request: eth_call to contract owned by Org B
  → Org context = Org B
  → Permissions = readers group
  → eth_call is allowed ✓

Request: eth_sendTransaction to contract owned by Org B
  → Org context = Org B
  → Permissions = readers group
  → eth_sendTransaction NOT allowed ✗
```

**Organization context determination:**

| Target | Org Context | Behavior |
|--------|-------------|----------|
| Contract owned by Org A | Org A | Use Org A memberships |
| Contract owned by Org B | Org B | Use Org B memberships |
| Unregistered contract (no owner) | User's default org | Deploy/admin only |
| Contract owned by Org C (user not member) | - | Request denied |
| No target (deployment) | User's default org | Use default org memberships |

**API for checking multi-org access:**
```bash
# Check access with explicit org context
curl -X POST http://localhost:8080/api/access/check \
  -H "Content-Type: application/json" \
  -d '{
    "user_external_id": "did:example:alice",
    "org_slug": "org-b",
    "method": "eth_call",
    "target_address": "0x1234..."
  }'
```

## Use Cases

### Example: Gateway Organization

```
Organization: gateway
├── Group: root (allow_methods: [all common methods])
│   ├── Group: admin (role: admin)
│   ├── Group: engineering
│   │   ├── Group: devops (role: deployer)
│   │   └── Group: developers (role: user)
│   └── Group: users (role: reader)
```

### Setting Up an Organization

```bash
# Create organization
curl -X POST http://localhost:8080/api/orgs \
  -H "Content-Type: application/json" \
  -d '{"slug": "myorg", "name": "My Organization"}'

# Create root group
curl -X POST http://localhost:8080/api/orgs/{org_id}/groups \
  -H "Content-Type: application/json" \
  -d '{"slug": "root", "name": "Root Group"}'

# Set group permissions (basic)
curl -X PUT http://localhost:8080/api/orgs/{org_id}/groups/{group_id}/permissions \
  -H "Content-Type: application/json" \
  -d '{
    "allow_methods": ["eth_call", "eth_getBalance", "eth_blockNumber"],
    "allow_contracts": [],
    "rate_limit_rps": 100
  }'

# Set group permissions with function selectors
# This allows users to call only transfer() and balanceOf() on the specified contract
curl -X PUT http://localhost:8080/api/orgs/{org_id}/groups/{group_id}/permissions \
  -H "Content-Type: application/json" \
  -d '{
    "allow_methods": ["eth_call", "eth_sendTransaction"],
    "allow_contracts": ["0x1234567890abcdef1234567890abcdef12345678"],
    "contract_functions": {
      "0x1234567890abcdef1234567890abcdef12345678": ["0xa9059cbb", "0x70a08231"]
    },
    "rate_limit_rps": 50
  }'

# Create child group
curl -X POST http://localhost:8080/api/orgs/{org_id}/groups \
  -H "Content-Type: application/json" \
  -d '{"slug": "engineering", "name": "Engineering", "parent_id": "{root_group_id}"}'
```

### Assigning Users

**Via Admin API:**
```bash
# Create membership
curl -X POST http://localhost:8080/api/users/{user_id}/memberships \
  -H "Content-Type: application/json" \
  -d '{"group_id": "{group_id}", "role_id": "{role_id}"}'
```

**Via ZK Credentials:**
Users with ZK-attested role credentials are automatically assigned to groups when they authenticate. The credential must contain:
```json
{
  "credentialSubject": {
    "rbac_groups": ["myorg:engineering:devops"],
    "rbac_roles": ["deployer"]
  }
}
```

### Contract Ownership

Track deployed contracts and their owner groups:
```bash
curl -X POST http://localhost:8080/api/orgs/{org_id}/contracts \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "0x1234...",
    "owner_group_id": "{group_id}"
  }'
```

Note: Permissions are determined by the user's role claims, not by contract-specific abilities.

## Group-Contract Access Workflow

The RBAC system uses a simple two-step workflow for managing contract access:

### Step 1: Configure Groups (Groups Tab)

Groups define what claims users have. Set up group access with:
- **Allowed RPC Methods**: Which JSON-RPC methods members can call (e.g., `eth_call`, `eth_sendTransaction`)
- **Claims**: The capabilities group members have (e.g., `read`, `write`, `admin`)

**Example groups:**
- **Audit Group**: `allowed_methods: [eth_call, eth_getLogs]`, `claims: [read]`
- **Trader Group**: `allowed_methods: [eth_call, eth_sendTransaction]`, `claims: [read, write]`
- **Admin Group**: `allowed_methods: [all]`, `claims: [read, write, admin, upgrade]`

```bash
# Set up an audit group with read-only access
curl -X PUT http://localhost:8080/api/orgs/{org_id}/groups/{group_id}/access \
  -H "Content-Type: application/json" \
  -d '{
    "allowed_methods": ["eth_call", "eth_getBalance", "eth_getLogs"],
    "claims": ["read"]
  }'

# Set up a trader group with read/write access
curl -X PUT http://localhost:8080/api/orgs/{org_id}/groups/{group_id}/access \
  -H "Content-Type: application/json" \
  -d '{
    "allowed_methods": ["eth_call", "eth_sendTransaction"],
    "claims": ["read", "write"]
  }'
```

**Important**: Methods must match claims. For example, `eth_sendTransaction` requires the `write` claim. The system validates this when saving group access.

### Step 2: Link Groups to Contracts (Contracts Tab)

On the Contracts tab, use the **Shield icon** to manage which groups can access a contract. Simply select the group - the group's claims automatically determine what permissions they have.

```bash
# Link a group to a contract (group's claims apply automatically)
curl -X POST http://localhost:8080/api/orgs/{org_id}/contracts/{address}/grants \
  -H "Content-Type: application/json" \
  -d '{
    "group_id": "{group_id}"
  }'
```

**Key points:**
- You don't specify claims when linking a group to a contract
- The group's claims from Step 1 determine what members can do
- Multiple groups can have access to the same contract with different permission levels

### Visual Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    RBAC PERMISSION FLOW                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  STEP 1: Groups Tab - Define Claims                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Audit Group                                                │ │
│  │  ├─ Allowed Methods: [eth_call, eth_getLogs]               │ │
│  │  └─ Claims: [read]   ← Source of truth for capabilities    │ │
│  │                                                              │ │
│  │  Trader Group                                               │ │
│  │  ├─ Allowed Methods: [eth_call, eth_sendTransaction]       │ │
│  │  └─ Claims: [read, write]                                   │ │
│  │                                                              │ │
│  │  Admin Group (is_org_admin: true)                           │ │
│  │  └─ Gets ALL claims on ALL contracts automatically          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  STEP 2: Contracts Tab - Link Groups (for registered contracts) │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Token Contract (0x1234...)                                 │ │
│  │  └─ ContractGrants:                                         │ │
│  │      ├─ Audit Group → read (inherited from group claims)    │ │
│  │      └─ Trader Group → read+write (inherited from group)    │ │
│  │                                                              │ │
│  │  Note: Deploy/admin users can access all own-org contracts   │ │
│  │  without grants. Read/write users need explicit grants.     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            │                                     │
│                            ▼                                     │
│  RESULT: User Access                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  Alice (member of Audit Group)                              │ │
│  │  └─ Token Contract: eth_call ✓, eth_sendTransaction ✗      │ │
│  │                                                              │ │
│  │  Bob (member of Trader Group)                               │ │
│  │  └─ Token Contract: eth_call ✓, eth_sendTransaction ✓      │ │
│  │                                                              │ │
│  │  Carol (deployed the contract herself)                      │ │
│  │  └─ Token Contract: eth_call ✓, eth_sendTransaction ✓      │ │
│  │     (deployer auto-grant: read+write without explicit grant)│ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Method-Claim Validation

The system enforces consistency between allowed methods and claims:

| RPC Method | Required Claim |
|------------|----------------|
| `eth_call`, `eth_getBalance`, `eth_getLogs`, etc. | `read` |
| `eth_sendTransaction`, `eth_sendRawTransaction`, `eth_sign` | `write` |

When saving group access, the backend validates that all methods have their required claims. For example, if you try to allow `eth_sendTransaction` without the `write` claim, you'll get a 400 Bad Request error.

### UI Workflow

**Groups Tab:**
1. Select a group
2. Configure "Allowed Methods" (grouped by Read Methods and Write Methods)
3. Check the claims checkboxes (Read, Write, Admin, etc.)
4. Methods are automatically disabled if their required claim is unchecked

**Contracts Tab:**
1. Click the Shield icon on a contract
2. Click "Add Group"
3. Select a group from the dropdown
4. The group's claims are displayed for reference
5. Click "Add Group Access"

That's it - no need to re-specify claims when linking groups to contracts.

## API Reference

### Organizations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs | List all organizations |
| POST | /api/orgs | Create organization |
| GET | /api/orgs/:org_id | Get organization |
| PUT | /api/orgs/:org_id | Update organization |

### Groups

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/groups | List groups |
| POST | /api/orgs/:org_id/groups | Create group |
| GET | /api/orgs/:org_id/groups/:group_id | Get group |
| PUT | /api/orgs/:org_id/groups/:group_id | Update group |
| DELETE | /api/orgs/:org_id/groups/:group_id | Delete group |
| GET | /api/orgs/:org_id/groups/:group_id/permissions | Get permissions |
| PUT | /api/orgs/:org_id/groups/:group_id/permissions | Set permissions |

### Roles

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/roles | List roles |
| POST | /api/orgs/:org_id/roles | Create role |
| GET | /api/orgs/:org_id/roles/:role_id | Get role |
| PUT | /api/orgs/:org_id/roles/:role_id | Update role |
| DELETE | /api/orgs/:org_id/roles/:role_id | Delete role |

### Users & Memberships

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/users | List users |
| GET | /api/users/:user_id | Get user |
| PUT | /api/users/:user_id | Update user |
| GET | /api/users/:user_id/memberships | List memberships |
| POST | /api/users/:user_id/memberships | Create membership |
| DELETE | /api/users/:user_id/memberships/:membership_id | Delete membership |

### Contracts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/contracts | List contracts |
| POST | /api/orgs/:org_id/contracts | Create contract ownership |
| PUT | /api/orgs/:org_id/contracts/:address | Update contract |
| DELETE | /api/orgs/:org_id/contracts/:address | Delete contract |

### Organization Config

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/config/create3 | Get org's CREATE3 factory address |
| PUT | /api/orgs/:org_id/config/create3 | Set org's CREATE3 factory address |

### Pre-registered Addresses

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/orgs/:org_id/addresses/preregistered | List pre-registered addresses |
| POST | /api/orgs/:org_id/addresses/preregister | Pre-register CREATE3 addresses |
| DELETE | /api/orgs/:org_id/addresses/preregistered/:address | Delete pre-registered address |

### Debugging

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/users/:user_id/effective-permissions | Get computed permissions |
| POST | /api/access/check | Test access check |
| GET | /api/cache/stats | Get cache statistics |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DATABASE_URL | PostgreSQL connection string | Required |
| RBAC_CACHE_TTL | Permission cache TTL | 5m |

### Cache Tuning

The RBAC system uses a two-level cache:
1. **In-memory cache**: Fast lookups, configurable TTL and max entries
2. **Database cache**: Persisted computed permissions

Default settings:
- Cache TTL: 5 minutes
- Max entries: 10,000

## Migration Guide

### Upgrading from Flat access_policies Model

The new RBAC system maintains backward compatibility with the legacy `access_policies` table:

1. Existing users in `access_policies` continue to work
2. New users are automatically added to the RBAC `users` table
3. Legacy users are assigned to the default organization and group

To migrate existing users to RBAC:
1. Create appropriate organizations and groups
2. Create memberships for users
3. Set group permissions

The legacy `access_policies` table and access controller remain functional during the transition period.

## Contract Deployment Security

The RBAC system includes bytecode analysis to sandbox deployed contracts, preventing cross-organization access via internal EVM calls.

### Validation Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      DEPLOYMENT VALIDATION FLOW                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Incoming deployment transaction                                        │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────┐                                    │
│  │ Is this a known proxy pattern?  │                                    │
│  │ (ERC-1967, Transparent, UUPS,   │                                    │
│  │  Beacon, Diamond)               │                                    │
│  └─────────────────────────────────┘                                    │
│           │                                                             │
│     ┌─────┴─────┐                                                       │
│     ▼           ▼                                                       │
│   [YES]       [NO]                                                      │
│     │           │                                                       │
│     │           ▼                                                       │
│     │    ┌────────────────────────┐                                     │
│     │    │ Standard bytecode      │                                     │
│     │    │ analysis:              │                                     │
│     │    │ - Extract call targets │                                     │
│     │    │ - Reject dynamic calls │                                     │
│     │    │ - Verify org ownership │                                     │
│     │    └────────────────────────┘                                     │
│     │                                                                   │
│     ▼                                                                   │
│  ┌────────────────────────────────────┐                                 │
│  │ Proxy-specific validation:         │                                 │
│  │ 1. Verify initial impl is org-owned│                                 │
│  │ 2. Record as "managed proxy"       │                                 │
│  │ 3. Enable upgrade interception     │                                 │
│  └────────────────────────────────────┘                                 │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      UPGRADE TRANSACTION INTERCEPTION                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Incoming transaction to managed proxy                                  │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────────────────────────┐                                │
│  │ Is this an upgrade call?            │                                │
│  │ - upgradeTo(address)                │                                │
│  │ - upgradeToAndCall(address,bytes)   │                                │
│  │ - setImplementation(address)        │                                │
│  └─────────────────────────────────────┘                                │
│           │                                                             │
│     ┌─────┴─────┐                                                       │
│     ▼           ▼                                                       │
│   [YES]       [NO]                                                      │
│     │           │                                                       │
│     │           ▼                                                       │
│     │       Allow (normal call)                                         │
│     │                                                                   │
│     ▼                                                                   │
│  ┌────────────────────────────────────┐                                 │
│  │ Extract new impl address from      │                                 │
│  │ transaction calldata               │                                 │
│  └────────────────────────────────────┘                                 │
│           │                                                             │
│           ▼                                                             │
│  ┌────────────────────────────────────┐                                 │
│  │ Is new impl address org-owned?     │──── NO ───► Reject upgrade      │
│  └────────────────────────────────────┘                                 │
│           │                                                             │
│          YES                                                            │
│           │                                                             │
│           ▼                                                             │
│       Allow upgrade                                                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Deployment Validation

When a user with the `deploy` claim deploys a contract, the bytecode is analyzed to ensure:

1. **Org ownership**: All static call targets must be owned by the deploying user's organization
2. **No nested deployments**: CREATE/CREATE2 opcodes are blocked (prevents deploying child contracts that bypass validation)
3. **Precompile whitelist**: Standard EVM precompiles (0x01-0x09) are always allowed

**With Runtime Tracing Enabled (`ENABLE_RUNTIME_TRACING=true`, default):**

Dynamic calls (address from storage, calldata, or computation) are **allowed** at deployment because they are validated at runtime via `debug_traceCall`. This enables compatibility with:
- OpenZeppelin upgradeable contracts
- UUPS proxies with dynamic DELEGATECALL
- Contracts with configurable dependencies

**Rejected bytecode patterns (always):**
- CREATE/CREATE2 opcodes (nested deployment)

**Rejected bytecode patterns (only when runtime tracing disabled):**
- Dynamic call targets (address from storage, calldata, or computation)
- DELEGATECALL to non-org-owned addresses

### Proxy Pattern Support

The system recognizes and supports standard proxy patterns:

| Pattern | Detection Method | Support Level |
|---------|-----------------|---------------|
| ERC-1967 | Storage slot signatures | Full |
| Transparent Proxy | ERC-1967 + admin slot | Full |
| UUPS | ERC-1967 + upgrade in impl | Full |
| Beacon Proxy | Beacon slot signature | Full |
| Diamond (EIP-2535) | Not supported | Manual only |

**Proxy deployment flow:**
1. Bytecode analyzed for proxy patterns
2. Initial implementation address extracted from constructor args
3. Implementation must be org-owned
4. Proxy registered as "managed" for upgrade interception

**Proxy upgrade interception:**

When calling a managed proxy, the system detects upgrade function selectors:
- `upgradeTo(address)` - 0x3659cfe6
- `upgradeToAndCall(address,bytes)` - 0x4f1ef286
- `setImplementation(address)` - 0x5a8b1a9f
- `upgrade(address,address)` - 0x99a88ec4

The new implementation address is extracted and validated for org ownership before the transaction is forwarded.

### Pre-registered Addresses (CREATE3)

For upgradeable proxies that will deploy future implementations at deterministic addresses, you can pre-register CREATE3 addresses before the code is known.

#### Per-Organization Factory Configuration

**CRITICAL SECURITY**: Each organization has its own CREATE3 factory contract. This ensures complete isolation between organizations - Org A cannot deploy contracts that could interact with Org B's addresses.

#### Org-Scoped Salt Computation

**CRITICAL SECURITY**: Address generation includes the organization ID in the salt computation to ensure cross-org isolation. Even if two organizations use the same factory address and salt prefix, they will get different addresses.

**Salt computation formula:**
```
For each i in 0..count:
  saltInput = orgID || saltPrefix || i
  salt = keccak256(saltInput)
  address = CREATE3(factory, salt)
```

This prevents address collision attacks where one org could pre-register addresses that another org might deploy to.

**Factory Address Storage:**
- Stored in `organization.settings["factory_address"]`
- Set automatically on first pre-registration, or manually via API
- All subsequent pre-registrations must use the same factory

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/orgs/:org_id/config/create3 | Get org's factory address |
| PUT | /api/v1/orgs/:org_id/config/create3 | Set org's factory address |

**Get factory configuration:**
```bash
curl http://localhost:8080/api/v1/orgs/{org_id}/config/create3
```

Response:
```json
{
  "factory": "0x9fBB3DF7C40Da2e5A0dE984fFE2CCB7C47cd0ABf",
  "configured": true
}
```

**Set factory configuration:**
```bash
curl -X PUT http://localhost:8080/api/v1/orgs/{org_id}/config/create3 \
  -H "Content-Type: application/json" \
  -d '{"factory": "0x9fBB3DF7C40Da2e5A0dE984fFE2CCB7C47cd0ABf"}'
```

**Factory Validation on Pre-registration:**

When pre-registering addresses, the factory is validated:
1. If org has a factory configured → input factory MUST match
2. If org has no factory → input factory is saved as org's factory
3. Mismatched factory → request rejected with 400 error

This prevents accidental or malicious use of a different factory that could break isolation.

**Production vs Development:**

| Environment | Factory Deployment | Configuration |
|-------------|-------------------|---------------|
| Development | Auto-deployed via UI (Anvil account 0) | Auto-configured on first use |
| Production | Deployed directly to node (outside proxy) | Set via API before first pre-registration |

#### Complete Contract Lifecycle Flow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                    CONTRACT REGISTRATION LIFECYCLE                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    PHASE 1: PRE-REGISTRATION                             │    │
│  │                    (Before deployment)                                   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│       Admin provides:                                                            │
│       • CREATE3 Factory address                                                  │
│       • Salt prefix (e.g., "myapp-v1")                                          │
│       • Count (number of addresses to pre-register)                             │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ Server calculates deterministic         │                               │
│       │ addresses using CREATE3 formula:        │                               │
│       │                                         │                               │
│       │ For each i in 0..count:                 │                               │
│       │   salt = keccak256(orgID + prefix + i)  │  ← Org ID included!          │
│       │   proxy = CREATE2(factory, salt, PROXY) │                               │
│       │   addr = CREATE(proxy, nonce=1)         │                               │
│       └─────────────────────────────────────────┘                               │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ Addresses stored in                     │                               │
│       │ preregistered_addresses table           │                               │
│       │ Status: PENDING                         │                               │
│       └─────────────────────────────────────────┘                               │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    PHASE 2: DEPLOYMENT                                   │    │
│  │                    (Via CREATE3 factory through proxy)                   │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│       Developer deploys contract via CREATE3 factory                            │
│       using same factory + salt → lands at pre-registered address               │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ Contract deployed at                    │                               │
│       │ 0x1234... (pre-registered address)      │                               │
│       └─────────────────────────────────────────┘                               │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ AUTO-REGISTRATION (automatic)           │                               │
│       │ Privacy Proxy detects successful        │                               │
│       │ factory deploy and creates contract     │                               │
│       │ entry in contracts table                │                               │
│       └─────────────────────────────────────────┘                               │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    PHASE 3: GRANT ASSIGNMENT                             │    │
│  │                    (Optional - fine-grained permissions)                 │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│       Admin optionally assigns grants for read/write users                     │
│       (Deploy/admin users already have access to own-org contracts)            │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ Contract already in contracts table     │                               │
│       │ (auto-registered after deployment)      │                               │
│       └─────────────────────────────────────────┘                               │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ Admin assigns grants (permissions)      │                               │
│       │ • Group → Contract with Claims          │                               │
│       │   (read, write, admin, upgrade)         │                               │
│       └─────────────────────────────────────────┘                               │
│                                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐    │
│  │                    PHASE 4: ACCESS CONTROL                               │    │
│  │                    (Runtime enforcement)                                 │    │
│  └─────────────────────────────────────────────────────────────────────────┘    │
│                                                                                  │
│       User sends RPC request targeting contract                                 │
│                          │                                                       │
│                          ▼                                                       │
│       ┌─────────────────────────────────────────┐                               │
│       │ RBAC checks:                            │                               │
│       │ 1. User's effective permissions         │                               │
│       │ 2. Contract ownership by user's org     │                               │
│       │ 3. User has required claims             │                               │
│       │ 4. Function selector allowed            │                               │
│       │ 5. Parameter constraints validated      │                               │
│       └─────────────────────────────────────────┘                               │
│                          │                                                       │
│                    ┌─────┴─────┐                                                │
│                    ▼           ▼                                                │
│               [ALLOWED]    [DENIED]                                             │
│                    │           │                                                │
│                    ▼           ▼                                                │
│              Forward to    Return 403                                           │
│              upstream      Forbidden                                            │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

#### Ownership Validation

When checking if an address is "org-owned", the system checks BOTH tables:

```
IsAddressOwnedByOrg(orgID, address):

    ┌──────────────────────────────────────┐
    │ Check contracts table                │
    │ SELECT EXISTS FROM contracts         │
    │ WHERE address = ? AND org_id = ?     │
    └──────────────────────────────────────┘
                    │
              ┌─────┴─────┐
              ▼           ▼
           [FOUND]    [NOT FOUND]
              │           │
              ▼           ▼
         Return TRUE   ┌──────────────────────────────────────┐
                       │ Check preregistered_addresses table  │
                       │ SELECT EXISTS FROM                   │
                       │ preregistered_addresses              │
                       │ WHERE address = ? AND org_id = ?     │
                       └──────────────────────────────────────┘
                                        │
                                  ┌─────┴─────┐
                                  ▼           ▼
                               [FOUND]    [NOT FOUND]
                                  │           │
                                  ▼           ▼
                             Return TRUE  Return FALSE
```

This enables:
- Proxy upgrades to pre-registered addresses BEFORE deployment
- Deployment validation to accept pre-registered targets
- Immediate access after deployment (no manual registration needed)

#### Immediate Access to Preregistered Addresses

**Key behavior**: Users can interact with preregistered addresses immediately after deployment, without waiting for explicit contract registration. The system grants `read`, `write`, and `deploy` claims to users in the owning organization when:

1. The target address is in the `preregistered_addresses` table for the user's org
2. OR the target address is in the `contracts` table for the user's org

This means:
- Deploy via CREATE3 factory → Contract auto-registered → Immediate access
- Even if auto-registration fails, preregistered addresses still grant access

#### Auto-Registration After Factory Deploy

When a transaction to a CREATE3 factory succeeds:

1. The privacy proxy detects it was a factory deploy call (by matching factory address and `deploy` function selector)
2. Extracts the target address from the transaction data (computed CREATE3 address)
3. Automatically creates a contract entry in the `contracts` table with:
   - `org_id`: The organization that owns the preregistered address
   - `address`: The deployed contract address
   - `name`: Auto-generated (e.g., "CREATE3 Deploy 0x1234...")
   - `metadata`: Factory address, salt, and `auto_registered: true` flag

This eliminates the need for a manual "register contract" step after deployment.

#### Admin UI Workflow

The RBAC Admin UI provides a streamlined interface for managing pre-registered addresses and contracts.

**Step 1: Pre-register Addresses**

Navigate to **Contracts** tab → Click **"Pre-register Addresses"** button

```
┌─────────────────────────────────────────────────────────────────┐
│  Pre-register CREATE3 Addresses                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Factory Address*                                                │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 0x9fBB3DF7C40Da2e5A0dE984fFE2CCB7C47cd0ABf                  ││
│  └─────────────────────────────────────────────────────────────┘│
│  ↳ In dev mode: auto-deployed if not present                    │
│                                                                  │
│  Salt Prefix*                                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ myapp-v2-impl                                                ││
│  └─────────────────────────────────────────────────────────────┘│
│  ↳ Unique identifier for this batch of addresses                │
│                                                                  │
│  Count*          Note (optional)                                 │
│  ┌────────┐      ┌─────────────────────────────────────────────┐│
│  │ 10     │      │ Implementation contracts for v2 upgrade     ││
│  └────────┘      └─────────────────────────────────────────────┘│
│                                                                  │
│  [Show address preview]  ← Click to see calculated addresses    │
│                                                                  │
│                              [Cancel]  [Pre-register 10 Addresses]│
└─────────────────────────────────────────────────────────────────┘
```

**Step 2: Register Contract (with pre-registered address selection)**

Navigate to **Contracts** tab → Click **"Register Contract"** button

```
┌─────────────────────────────────────────────────────────────────┐
│  Register Contract                                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Contract Address*                                               │
│  ┌──────────────────────────────────────────────────────────┬──┐│
│  │ 0x...                                                    │▼ ││
│  └──────────────────────────────────────────────────────────┴──┘│
│  ↳ 5 pre-registered addresses available (click ▼ to select)    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐
│  │ Pre-registered Addresses (5 available)                       │
│  ├──────────────────────────────────────────────────────────────┤
│  │ 0x1234...5678  │ Implementation contracts for v2 upgrade     │
│  │ 0x2345...6789  │ Implementation contracts for v2 upgrade     │
│  │ 0x3456...789a  │ Implementation contracts for v2 upgrade     │
│  │ ...                                                          │
│  └──────────────────────────────────────────────────────────────┘
│                                                                  │
│  Name (optional)                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ TokenV2Implementation                                        ││
│  └─────────────────────────────────────────────────────────────┘│
│  ↳ Auto-filled from pre-registered address note if selected     │
│                                                                  │
│  💡 Tip: After registering, add grants to specify which groups  │
│     can access it. Claims are inherited from the group.         │
│                                                                  │
│                                        [Cancel]  [Register Contract]│
└─────────────────────────────────────────────────────────────────┘
```

**Step 3: Assign Grants**

After registering a contract, click on it to add grants. Note that you only select the **group** - claims are automatically inherited from the group's `GroupAccess.claims`.

```
┌─────────────────────────────────────────────────────────────────┐
│  Contract: TokenV2Implementation                                 │
│  Address: 0x1234...5678                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Grants                                        [+ Add Grant]     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ Group          │ Group Claims (inherited)  │ Actions         ││
│  ├─────────────────────────────────────────────────────────────┤│
│  │ Engineering    │ read, write, upgrade      │ [Edit] [Delete] ││
│  │ Operators      │ read                      │ [Edit] [Delete] ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
│  Note: Claims shown are from each group's GroupAccess settings.  │
│  The grant just links the group to the contract; it does NOT    │
│  store separate claims.                                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**How CREATE3 works:**

| Method | Address Formula | Code-Independent? |
|--------|----------------|-------------------|
| CREATE | `keccak256(rlp([sender, nonce]))[12:]` | No (nonce increments) |
| CREATE2 | `keccak256(0xff ++ sender ++ salt ++ keccak256(initCode))[12:]` | **No** (code in hash) |
| CREATE3 | Uses CREATE2 for proxy, then CREATE for actual contract | **Yes!** |

CREATE3 achieves **code-independent deterministic addresses**:

```
Step 1: Deploy tiny proxy via CREATE2
        proxy_addr = keccak256(0xff ++ factory ++ salt ++ keccak256(FIXED_PROXY_BYTECODE))[12:]

Step 2: Proxy deploys actual contract via CREATE (nonce always = 1)
        final_addr = keccak256(rlp([proxy_addr, 1]))[12:]

Result: final_addr = f(factory, salt) only - NO dependency on contract code!
```

This allows **pre-registration of future implementation addresses** without knowing the code.

#### Development Mode: Auto-Deploy CREATE3 Factory

In development mode (when connected to Anvil or similar local node), the UI can automatically deploy a CREATE3 factory if one isn't already deployed.

```
┌─────────────────────────────────────────────────────────────────┐
│  Development Mode                                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ⚠️ No CREATE3 factory contract is deployed on the local chain. │
│  Click the button below to deploy one automatically using       │
│  Anvil's default account.                                       │
│                                                                  │
│                    [🚀 Deploy CREATE3 Factory]                   │
│                                                                  │
│  ─────────────────── or ───────────────────                     │
│                                                                  │
│  Use Existing Factory Address                                    │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ 0x...                                                        ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Dev endpoints (localhost only, non-production):**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/v1/dev/create3-factory | Check if factory is deployed |
| POST | /api/v1/dev/create3-factory | Deploy factory using Anvil account 0 |
| POST | /api/v1/dev/orgs/:org_id/create3/auto-register | Auto-register after CREATE3 deployment |

The auto-register endpoint is useful for automated testing:
```bash
# After deploying via CREATE3 factory, auto-register if pre-registered
curl -X POST http://localhost:8080/api/v1/dev/orgs/{org_id}/create3/auto-register \
  -H "Content-Type: application/json" \
  -d '{
    "factory": "0x9fBB3DF7C40Da2e5A0dE984fFE2CCB7C47cd0ABf",
    "salt": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "name": "MyContract"
  }'
```

Response:
```json
{
  "address": "0x1234...",
  "registered": true,
  "message": "Contract registered successfully"
}
```

**Pre-register addresses:**
```bash
curl -X POST http://localhost:8080/api/orgs/{org_id}/addresses/preregister \
  -H "Content-Type: application/json" \
  -d '{
    "factory": "0x...",
    "salt_prefix": "0x...",
    "count": 50,
    "note": "Implementation addresses for Project X"
  }'
```

**Response:**
```json
{
  "addresses": [
    {"address": "0x...", "salt": "0x...", "factory": "0x..."},
    ...
  ]
}
```

**List pre-registered addresses:**
```bash
curl http://localhost:8080/api/orgs/{org_id}/addresses/preregistered
```

**Delete pre-registered address:**
```bash
curl -X DELETE http://localhost:8080/api/orgs/{org_id}/addresses/preregistered/{address}
```

Pre-registered addresses are treated as org-owned for validation purposes, allowing proxy upgrades to point to them before the implementation is deployed.

## Cross-Organization Isolation

The RBAC system enforces strict isolation between organizations to prevent data leakage.

### eth_getLogs Filtering

`eth_getLogs` requires an address filter and validates all addresses:
- Requests without address filter are rejected
- Each address in the filter is checked against RBAC permissions
- Users can only query logs from contracts they have read access to

### Historical State Queries Blocked

To prevent access to historical data after permissions change:
- `eth_call` and `eth_getStorageAt` only allow `latest` or `pending` block parameters
- Historical block numbers and block hashes are rejected

### WebSocket Subscriptions Blocked

`eth_subscribe` and `eth_unsubscribe` are blocked entirely to prevent:
- Real-time log subscriptions that bypass eth_getLogs filtering
- Pending transaction monitoring across organizations

**Workaround:** Use polling with `eth_getLogs` instead of subscriptions.

### Default Claims Access Model

The system uses a tiered access model based on user claims and contract registration status:

**Unregistered contracts** (not registered to any organization) are only accessible to users with `deploy` or `admin` claims. Regular `read`/`write` users cannot access unregistered contracts — they must use registered contracts with explicit grants. This prevents race conditions where freshly deployed contracts could be interacted with before registration.

**Registered contracts in user's own org** are accessible to `deploy`/`admin` users via default claims without needing explicit `ContractGrant` entries. This means deployers can interact with contracts immediately after deployment and registration. Regular `read`/`write` users still need explicit grants.

**Cross-org isolation** is always enforced — if a contract is registered to Org A, users in Org B cannot access it via default claims, even if their group has deploy/admin permissions.

## Known Limitations

### Diamond Proxy (EIP-2535) Not Supported

The deployment validator detects Diamond patterns but does not implement:
- Route/facet registration interception (diamondCut validation)
- Facet address validation when routes are modified
- Database tracking of router→facet mappings

**Workaround:** Organizations using Diamond proxies should:
1. Pre-register all facet addresses as contracts before deployment
2. Manually ensure facet additions only use org-owned addresses

### Bytecode Analysis Limitations

- **Complex stack manipulation**: Unusual opcode sequences may not be analyzed correctly; conservative approach rejects uncertain patterns
- **Custom proxies**: Proxy patterns not matching ERC-1967 slots will be rejected
- **Gas cost**: Bytecode analysis adds latency to deployment transactions

## Security Considerations

- RBAC admin endpoints are protected by localhost-only middleware
- ZK-attested memberships require valid Privado ID credentials
- Permission cache is invalidated when permissions change
- Audit logging tracks all RBAC changes
- **Runtime transaction tracing** validates all addresses touched by transactions (when `ENABLE_RUNTIME_TRACING=true`)
- Deployment bytecode validation prevents nested deployments via CREATE/CREATE2
- Proxy upgrade interception prevents upgrading to non-org-owned implementations
- All precompile addresses (0x01-0x09) are whitelisted for standard cryptographic operations
