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
