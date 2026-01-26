# Selective Disclosure System

The Privacy Proxy implements a selective disclosure system that allows users to share address visibility with authorized parties (auditors, regulators, compliance teams) while maintaining privacy controls.

## Overview

The disclosure system is inspired by ZkSync Prividium's architecture and provides:

- **Granular control** over what data is shared and how addresses are displayed
- **Time-limited access** with automatic expiration
- **Audit trail** of all disclosure access events
- **Multiple disclosure levels** from full transparency to complete redaction

## Key Concepts

### Disclosure Levels

| Level | Address Display | Use Case |
|-------|-----------------|----------|
| **Full** | Real addresses (`0xa32c...94cd`) | Regulatory subpoenas, law enforcement investigations |
| **Pseudonymous** | Consistent pseudonyms (`Address-KDCM`) | Financial audits - allows pattern analysis without revealing identity |
| **Redacted** | `[REDACTED]` | Minimal disclosure - proves activity exists without revealing addresses |

### Disclosure Workflow

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Requester  │     │   Target User   │     │ Privacy Proxy   │
│  (Auditor)  │     │ (Address Owner) │     │   (Backend)     │
└──────┬──────┘     └────────┬────────┘     └────────┬────────┘
       │                     │                       │
       │ 1. Create Request   │                       │
       │ ──────────────────────────────────────────> │
       │                     │                       │
       │                     │ 2. Review & Approve   │
       │                     │ <──────────────────── │
       │                     │                       │
       │                     │ 3. Approve/Reject     │
       │                     │ ──────────────────────>│
       │                     │                       │
       │ 4. Grant Created    │                       │
       │ <────────────────────────────────────────── │
       │                     │                       │
       │ 5. Access Data      │                       │
       │ ──────────────────────────────────────────> │
       │                     │                       │
       │ 6. Pseudonymized    │                       │
       │    Response         │                       │
       │ <────────────────────────────────────────── │
```

## Data Models

### Disclosure Request

A request from an authorized party to view someone's data:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "requester_did": "did:iden3:privado:main:2SaubQ6...",
  "target_user_id": "user-123",
  "org_id": "org-456",
  "scope": {
    "addresses": ["0xa32c..."],
    "date_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    },
    "disclosure_level": "pseudonymous"
  },
  "reason": "Annual financial audit",
  "legal_basis": "GDPR Article 6(1)(c)",
  "status": "pending",
  "requested_at": "2024-06-15T10:30:00Z",
  "expires_at": "2024-06-22T10:30:00Z"
}
```

### Request Status Lifecycle

```
              ┌─────────────┐
              │   PENDING   │
              └──────┬──────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
         v           v           v
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │ APPROVED │ │ REJECTED │ │ EXPIRED  │
   └────┬─────┘ └──────────┘ └──────────┘
        │
        v
   ┌──────────┐
   │  GRANT   │ ────> REVOKED (optional)
   └──────────┘
```

### Disclosure Grant

An approved disclosure with access permissions:

```json
{
  "id": "grant-789",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": {
    "addresses": ["0xa32c..."],
    "disclosure_level": "pseudonymous"
  },
  "granted_at": "2024-06-16T09:00:00Z",
  "expires_at": "2024-07-16T09:00:00Z",
  "revoked_at": null
}
```

### Scope Configuration

The scope defines what data can be accessed:

| Field | Description |
|-------|-------------|
| `methods` | Specific RPC methods allowed (e.g., `eth_call`, `eth_getLogs`) |
| `addresses` | Contract addresses to include in disclosure |
| `date_range` | Time period for transaction/log data |
| `disclosure_level` | How addresses are displayed (full/pseudonymous/redacted) |

## API Endpoints

### User Disclosure Dashboard

```bash
# List my pending disclosure requests (requests FOR my data)
GET /api/v1/disclosure/requests?status=pending

# List disclosure grants I've given
GET /api/v1/disclosure/grants?status=active

# Approve a disclosure request
POST /api/v1/disclosure/requests/{id}/approve
{
  "grant_duration_days": 30
}

# Reject a disclosure request
POST /api/v1/disclosure/requests/{id}/reject
{
  "reason": "Insufficient justification provided"
}
```

### Admin/Auditor Access

```bash
# Create a disclosure request
POST /api/v1/disclosure/requests
{
  "target_user_id": "user-123",
  "scope": {
    "addresses": ["0xa32c..."],
    "disclosure_level": "pseudonymous",
    "date_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-12-31T23:59:59Z"
    }
  },
  "reason": "Annual audit",
  "legal_basis": "GDPR Art. 6(1)(c)"
}

# List all requests (admin only)
GET /api/v1/admin/disclosure/requests?status=pending&target_user_id=user-123

# Revoke an active grant (admin only)
POST /api/v1/admin/disclosure/grants/{id}/revoke
{
  "reason": "Audit completed early"
}

# Delete a pending request (admin only)
DELETE /api/v1/admin/disclosure/requests/{id}
```

### Explorer Integration

When a user views disclosed data in the block explorer:

```bash
# Get addresses visible to the authenticated user
GET /api/v1/explorer/viewable-addresses?did=did:iden3:...

# Response includes:
{
  "viewer_did": "did:iden3:...",
  "own_addresses": [
    {"address": "0xabc..."}
  ],
  "disclosed_addresses": [
    {
      "address": "Address-KDCM",      // Pseudonym, not real address
      "address_id": "c311e533...",    // Opaque ID for routing
      "owner_did": "did:iden3:...",
      "disclosure_level": "pseudonymous",
      "grant_id": "265991a8-...",
      "expires_at": "2024-07-16T09:00:00Z"
    }
  ]
}

# View address details via grant (uses opaque address_id)
GET /api/v1/explorer/grant/{grant_id}/{address_id}

# Get pseudonymized transactions
GET /api/v1/explorer/grant/{grant_id}/{address_id}/transactions
```

## Security Model

### Address Protection

For **pseudonymous** and **redacted** disclosures:

1. **Real addresses are never sent to the frontend**
   - Backend resolves `address_id` → real address internally
   - Only pseudonyms or `[REDACTED]` are returned to clients

2. **Transaction hashes are hidden**
   - Prevents lookup on other block explorers to find real addresses
   - Only block numbers, timestamps, and values are shown

3. **Consistent pseudonyms within a grant**
   - Same address always gets the same pseudonym (e.g., `Address-KDCM`)
   - External addresses get pseudonyms like `External-7E56`
   - Allows pattern analysis without revealing identity

### Opaque Address IDs

To prevent address correlation, the system uses opaque `address_id` values:

```
address_id = SHA256(lowercase(address) + ":" + grant_id)[:16]
```

This ensures:
- Same address has different IDs across different grants
- Cannot reverse-engineer the real address from the ID
- Routes are secure: `/grant/{grant_id}/{address_id}`

### Fail-Safe Defaults

- Unknown disclosure levels default to `redacted`
- Missing viewer identity returns no disclosed addresses
- Expired/revoked grants return 403 Forbidden

## Audit Trail

Every access to disclosed data is logged:

```json
{
  "grant_id": "grant-789",
  "action": "view_transactions",
  "resource_type": "transactions",
  "viewer_ip": "192.168.1.100",
  "accessed_at": "2024-06-20T14:30:00Z",
  "data_summary": {
    "record_count": 47,
    "date_range": {
      "start": "2024-01-01",
      "end": "2024-06-20"
    }
  }
}
```

## Report Types

The system supports generating compliance reports:

| Report Type | Description |
|-------------|-------------|
| `activity_summary` | Aggregated activity statistics |
| `sanctions_check` | Check for interactions with sanctioned addresses |
| `compliance_report` | Full compliance audit report |

## Frontend Integration

### User Disclosure Dashboard

Shows three tabs:
- **Active** - Currently active disclosure grants
- **Pending** - Requests awaiting your approval
- **Inactive** - Expired or rejected requests

### Admin Disclosure Dashboard

Same tabs plus admin actions:
- **Remove** pending requests
- **Revoke** active grants
- **Filter** by target user, grantee, date, status

### Privacy Dashboard (Explorer)

Shows:
- Your own addresses
- Addresses disclosed to you (with appropriate redaction)
- Links to view disclosed address details

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCLOSURE_REQUEST_TTL` | `7d` | How long pending requests remain valid |
| `DISCLOSURE_GRANT_MAX_TTL` | `365d` | Maximum grant duration |
| `DISCLOSURE_AUDIT_RETENTION` | `7y` | How long to retain audit logs |

## Best Practices

1. **Always specify a reason and legal basis** for disclosure requests
2. **Use the minimum disclosure level needed** - prefer pseudonymous over full
3. **Set appropriate expiration dates** - don't request indefinite access
4. **Review the audit trail** regularly for compliance
5. **Revoke grants promptly** when access is no longer needed
