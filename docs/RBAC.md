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

Track deployed contracts and define special abilities:
```bash
curl -X POST http://localhost:8080/api/orgs/{org_id}/contracts \
  -H "Content-Type: application/json" \
  -d '{
    "contract_address": "0x1234...",
    "owner_group_id": "{group_id}",
    "owner_abilities": ["upgrade", "pause", "admin"]
  }'
```

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

## Security Considerations

- RBAC admin endpoints are protected by localhost-only middleware
- ZK-attested memberships require valid Privado ID credentials
- Permission cache is invalidated when permissions change
- Audit logging tracks all RBAC changes
