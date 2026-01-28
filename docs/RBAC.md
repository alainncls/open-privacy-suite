# RBAC (Role-Based Access Control) Documentation

## Overview

The Privacy Proxy implements a multi-tenant, hierarchical Role-Based Access Control (RBAC) system that protects blockchain node access. This system allows organizations to define fine-grained permissions for users accessing JSON-RPC methods and smart contracts.

### Key Features

- **Multi-tenant**: Multiple independent organizations with isolated permission hierarchies
- **Hierarchical Groups**: Nested groups with restrictive inheritance (child groups can only narrow parent permissions)
- **Dual Membership**: Users can be assigned via admin API or ZK-attested credentials
- **Contract Ownership**: Track deployed contracts and define owner abilities
- **Caching**: In-memory and database-level caching for high-performance access checks

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Organization                              │
│  (e.g., "gateway", "acme_corp")                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐       │
│  │    Group     │    │    Group     │    │    Role      │       │
│  │   (root)     │───▶│  (child)     │    │  (deployer)  │       │
│  │              │    │              │    │              │       │
│  │ permissions: │    │ permissions: │    │ claims:      │       │
│  │ - methods    │    │ - methods    │    │ - deployer   │       │
│  │ - contracts  │    │ - contracts  │    │ - writer     │       │
│  │ - rate_limit │    │ - rate_limit │    │ - reader     │       │
│  └──────────────┘    └──────────────┘    └──────────────┘       │
│         │                   │                    │               │
│         └───────────────────┼────────────────────┘               │
│                             │                                    │
│                     ┌───────▼───────┐                           │
│                     │  Membership   │                           │
│                     │ user + group  │                           │
│                     │ + role        │                           │
│                     └───────────────┘                           │
│                             │                                    │
│                     ┌───────▼───────┐                           │
│                     │     User      │                           │
│                     │ (external_id) │                           │
│                     └───────────────┘                           │
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

### Roles

Named permission sets with claims:
- `reader` - Can call read methods (eth_call, eth_getBalance, etc.)
- `writer` - Can send transactions (eth_sendTransaction)
- `deployer` - Can deploy contracts
- `admin` - Full administrative access
- `upgrade` - Can upgrade contracts

### Permissions

Each group can have associated permissions:
- `allow_methods` - Whitelisted JSON-RPC methods
- `allow_contracts` - Whitelisted contract addresses
- `contract_functions` - Per-contract function selector restrictions (see below)
- `owned_contracts` - Contracts owned by this group
- `rate_limit_rps` - Requests per second limit
- `rate_limit_daily` - Daily request limit

### Contract Function Selectors

For fine-grained contract access control, you can restrict which functions users can call on specific contracts using the `contract_functions` field.

**Format:**
```json
{
  "contract_functions": {
    "0xcontract_address": ["0xselector1", "0xselector2"]
  }
}
```

**Common ERC20 Selectors:**
- `0xa9059cbb` - `transfer(address,uint256)`
- `0x095ea7b3` - `approve(address,uint256)`
- `0x70a08231` - `balanceOf(address)`
- `0x23b872dd` - `transferFrom(address,address,uint256)`

**Behavior:**
- If `contract_functions` is empty/null, all functions are allowed on allowed contracts
- If a contract has an entry, only the listed selectors are allowed
- Selectors are case-insensitive
- Inheritance uses INTERSECTION (child restrictions narrow parent)

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

1. **No dynamic external calls**: All CALL/DELEGATECALL/STATICCALL targets must be constant addresses
2. **Org ownership**: All call targets must be owned by the deploying user's organization
3. **No nested deployments**: CREATE/CREATE2 opcodes are blocked (prevents deploying child contracts that bypass validation)
4. **Precompile whitelist**: Standard EVM precompiles (0x01-0x09) are always allowed

**Rejected bytecode patterns:**
- Dynamic call targets (address from storage, calldata, or computation)
- CREATE/CREATE2 opcodes (nested deployment)
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

### Default Claims Isolation

The `default_claims` feature only applies to contracts **not registered to any organization**. If a contract is registered to Org A, users in Org B cannot access it via default_claims, even if their group grants default read/write permissions.

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
- Deployment bytecode validation prevents cross-org calls via internal EVM execution
- Proxy upgrade interception prevents upgrading to non-org-owned implementations
- All precompile addresses (0x01-0x09) are whitelisted for standard cryptographic operations
