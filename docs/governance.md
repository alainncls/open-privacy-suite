# Multi-Party Governance Approval

The Privacy Proxy includes a native Multi-Party Governance engine that allows Organizations to enforce N-of-M approvals for sensitive Role-Based Access Control (RBAC) mutations.

## User Guide

When Governance is enabled for an Organization, any attempt to mutate an RBAC resource (e.g. updating Group Access, granting Contracts, or deleting users) will **NOT** immediately execute. Instead, the mutation is intercepted by the Governance Middleware and recorded as a pending `ApprovalRequest` in the database.

### Enabling Governance
Org Admins can enable the Multi-Party Governance system via the **Governance Settings** tab inside their Organization Dashboard in the UI. 
- **Approval Threshold**: Specify the number of independent Admin approvals required to finalize a request (between 1 and 10).
- **Webhook Integration**: Provide a Slack/Discord webhook URL to receive instant alerts whenever a new `ApprovalRequest` is submitted or threshold is met.

### Executing Actions
Requests stay pending until the required `approval_threshold` is met. Approvals can be placed manually via the UI Dashboard. Once the $N$ threshold requirement is reached, the Governance Engine securely replays the recorded JSON API payload identically against the system to mutate the destination resources natively.

---

## Developer Architecture & Implementation Details

### Database Layer
The `approval_requests` and `approval_decisions` tables track the entire lifecycle. We strictly use native Postgres `UUID` associations for all mappings instead of generic text.

**Critical Edge Case (Automated/System Approvals):**
Because the system runs API-driven automated UI verification (like E2E bots that mutate access using test/mock JWT logic), we enforce that **all** proxy system executions are tied to a real PostgreSQL `users` row.
During bootstrap, `032_governance_tables.sql` aggressively provisions a locked System User:
`00000000-0000-0000-0000-000000000000` (`system_admin`).
Any governance payload lacking a concrete external user identity falls back to this UUID to definitively bind to a non-null Requester/Approver UUID without throwing `500 Internal Server Errors` on `requester_id` table FK constraints.

### Engine Architecture
- **Transaction Rollbacks**: To prevent race conditions in highly concurrent environments (e.g., matching the exact threshold `N` without triggering execution twice), the entire Decision execution block (`RecordDecision`) is wrapped in a `SELECT ... FOR UPDATE` isolation block locking the `approval_requests` row.
- **Middleware Tamper Resistance**: The API payload intercepts happen *after* structural schema validation but *before* internal application, meaning the tracked `change_type` and `payload` JSONB are sanitized internal DTOs.
- **SSRF Notification Blocks**: Webhook URLs are rigorously scanned to prevent pinging `127.0.0.1`, `localhost`, or standard cloud metadata instances natively via `notifier.go` before dispatcher execution.

### Admin API Playwright Isolation
When running Playwright tests locally, ensure containers boot seamlessly without cached artifacts holding old database schemas. The E2E tests interact directly across multiple mocked accounts (User 1 and User 2) to demonstrate exact N-of-1 and N-of-2 multisig resolution without running afoul of the "User cannot approve their own request" physical barrier constraint enforced natively in the API engine.

---

## Approver Groups

By default, **any org admin** (a user with the `admin` claim in any group within the org) can approve governance requests. For organizations that need tighter control, you can designate specific **Approver Groups** — only members of those groups will be allowed to approve or reject requests.

### Behavior
- **No approver groups configured** (default): Any user with the `admin` claim in the org can approve. This is backward compatible with existing setups.
- **One or more approver groups configured**: Only users who are members of at least one designated approver group can approve. Having an `admin` claim alone is no longer sufficient.

### API Endpoints

```
GET    /api/v1/admin/orgs/:org_id/governance/approvers          — List approver groups
POST   /api/v1/admin/orgs/:org_id/governance/approvers          — Add approver group
DELETE /api/v1/admin/orgs/:org_id/governance/approvers/:group_id — Remove approver group
```

**Add approver group** request body:
```json
{"group_id": "uuid-of-the-group"}
```

The group must belong to the same organization. When the last approver group is removed, the system reverts to the default behavior (any org admin can approve).

### Governance Settings Response

The `GET` and `PUT` `/governance/settings` endpoints now include an `approver_groups` array:

```json
{
  "governance_enabled": true,
  "approval_threshold": 2,
  "governance_webhook_url": "https://hooks.slack.com/...",
  "governance_escalation_timeout_hours": 24,
  "approver_groups": [
    {
      "id": "uuid",
      "org_id": "uuid",
      "group_id": "uuid",
      "group_name": "Security Council",
      "group_slug": "security-council",
      "created_at": "2026-03-27T..."
    }
  ]
}
```

---

## Webhook Payload Format

When a governance webhook URL is configured, the proxy sends a POST request with the following JSON payload:

### New Approval Request (`new_approval_request`)

```json
{
  "event": "new_approval_request",
  "request": {
    "id": "uuid",
    "org_id": "uuid",
    "requester_id": "uuid",
    "change_type": "updateGroupAccess",
    "payload": { ... },
    "status": "pending",
    "approvals_needed": 2,
    "created_at": "2026-03-27T..."
  }
}
```

### Request Escalated (`request_escalated`)

Sent when the escalation timeout is reached without resolution:

```json
{
  "event": "request_escalated",
  "request": {
    "id": "uuid",
    "org_id": "uuid",
    "requester_id": "uuid",
    "change_type": "createContractGrant",
    "payload": { ... },
    "status": "pending",
    "approvals_needed": 2,
    "created_at": "2026-03-27T..."
  }
}
```

### Supported `change_type` values

| Change Type | Description |
|---|---|
| `createContractGrant` | Grant a group access to a contract |
| `updateContractGrant` | Update function-level rules on a grant |
| `deleteContractGrant` | Remove a group's access to a contract |
| `updateGroupAccess` | Change a group's claims or allowed methods |
