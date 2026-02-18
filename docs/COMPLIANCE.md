# Travel Rule Compliance

## Overview

The Privacy Proxy enforces FATF Recommendation 16, known as the "travel rule," for value transfers through the network. When a transfer's USD value exceeds a configured threshold, the system requires pre-submitted documentation identifying both the originator (sender) and beneficiary (recipient) before allowing the transaction to proceed. This regulatory requirement applies to Virtual Asset Service Providers (VASPs) and similar entities moving customer funds across blockchain networks.

## How It Works

The system implements a 3-layer compliance pipeline that runs on every value transfer (`eth_sendTransaction` and `eth_sendRawTransaction`). Each layer applies in sequence, and a transfer must pass all applicable layers to be allowed.

### Layer 1: Sanctions Check

**Executed first, before any other checks.**

This layer blocks transfers to and from sanctioned addresses regardless of transfer amount or threshold configuration. It is the highest-priority compliance control.

Addresses checked:
- Sender (from address)
- Recipient (to address)
- Transaction originator (msg.sender) if different from sender (e.g., in a `transferFrom` call where delegated authority is used)

If any address matches the sanctions list, the transfer is immediately denied.

Sanctions lists:
- **Global sanctions**: maintained by the system administrator, applies to all organizations
- **Per-organization sanctions**: set by org administrator, applies only to that organization

### Layer 2: Threshold Check

**Executes if Layer 1 passes (no sanctioned addresses).**

This layer converts the transfer amount to USD and compares it against applicable thresholds. Only transfers at or exceeding the threshold proceed to Layer 3.

Conversion and threshold logic:
1. The system converts the transfer amount (denominated in wei or token units) to USD using admin-configured token prices
2. Determines the applicable threshold by checking in this order:
   - Per-address threshold overrides for the sender address
   - Per-address threshold overrides for the recipient address
   - If both overrides exist, the lowest threshold is used
   - If neither override exists, the organization-wide threshold applies
3. Compares the transfer amount in USD against the applicable threshold

Outcomes:
- Transfer amount **< threshold**: ALLOWED, no documentation required
- Transfer amount **>= threshold**: proceeds to Layer 3
- Threshold of **$0**: every transfer requires travel rule documentation (valid for strict jurisdictions like Japan or EU CASP-to-CASP transfers)
- Exact threshold amount: requires documentation (strict `<` comparison per FATF guidance; amounts equal to or greater than threshold are subject to Layer 3)

If no token price is configured, the transfer is denied (fail-closed).

### Layer 3: Travel Rule Record Check

**Executes only for transfers that meet or exceed the threshold.**

This layer searches for a matching pre-created travel rule record authorizing the specific transfer.

Search criteria:
- Same organization
- Same originator user (internal user ID)
- Same beneficiary address
- Same token type (ETH native or specific ERC-20 contract address)
- Record `amount_usd` >= transfer amount in USD
- Record not expired (24-hour time-to-live, hardcoded)
- Record not already used (unused status)

Outcomes:
- **Matching record found**: transfer ALLOWED, record is immediately claimed and marked as used (atomically)
- **No matching record found**: transfer DENIED

Record consumption:
- Each travel rule record is single-use
- On match, the record is marked as used in a single atomic database operation
- Used records remain in the database as part of the audit trail but cannot be matched again
- A new travel rule record is required for each subsequent above-threshold transfer
- Even if the transfer amount is less than the record amount, the entire record is consumed

## Concepts

### Travel Rule Record

A travel rule record is regulatory documentation created by an administrator before a high-value transfer occurs. It represents proof that an administrator has verified the identities and legitimacy of both the originating party and the beneficiary.

**Record fields:**
- **Originator**: the user initiating the transfer (internal user ID, human-readable name, and account reference)
- **Beneficiary**: the receiving party (name of the beneficiary or institution, blockchain address receiving funds)
- **Token type**: native ETH or specific ERC-20 token (identified by contract address)
- **Amount**: specified in the token's native units (wei for ETH and most ERC-20 tokens); the USD equivalent is computed server-side from the admin-configured token price at the time of transfer evaluation
- **Expiry**: 24 hours from creation (hardcoded, non-configurable)
- **Status**: unused (available for matching), used (consumed by a transfer), or expired (past TTL, automatically marked on access)

**Lifecycle:**
1. Admin creates a record with specific originator, beneficiary, token, and amount
2. Record is stored in database with creation timestamp
3. When user initiates a transfer that exceeds the threshold, the system searches for a matching record
4. If found, the record is atomically marked as used and the transfer is allowed
5. Used records remain in database as audit trail but cannot be matched again

Used records cannot be deleted (they are immutable audit records). Unused or expired records can be deleted by an administrator.

### Threshold

The dollar amount (in USD) above which a transfer requires travel rule documentation.

**Types:**
- **Organization-wide threshold**: the default threshold for all transfers in an organization, set via compliance config (default: $1,000 when compliance is first enabled)
- **Per-address threshold override**: a different threshold for specific sender or recipient addresses (e.g., $100 for a known high-risk counterparty, $50 for a frequent small vendor)

**Resolution:**
When determining which threshold applies to a transfer, the system checks in order:
1. Is there a threshold override for the sender address?
2. Is there a threshold override for the recipient address?
3. If both overrides exist, use the lower of the two
4. If neither override exists, use the organization-wide threshold

**Special values:**
- Threshold of **$0** means every transfer requires documentation (no exceptions, valid for strict regulatory regimes)
- Threshold of **null/not set** means compliance is effectively disabled (not recommended for regulated entities)

### Sanctions List

A blocklist of blockchain addresses that are completely prohibited from sending or receiving transfers through the organization.

**Characteristics:**
- Addresses on the list are rejected before any threshold or travel rule check
- Applies regardless of transfer amount
- Can be global (enforced for all organizations by system administrator)
- Can be per-organization (specific to one organization's settings)

Typical use cases:
- OFAC SDN List compliance
- Addresses associated with known fraud or theft
- Addresses from hacked accounts
- Bridges between isolated risk domains (e.g., specific mixer contracts)

### Token Prices

Since the Privacy Proxy operates on a private network without external oracle access, token prices must be manually configured by administrators. The compliance checker uses these prices to convert transfer amounts to USD for threshold comparison and travel rule record matching.

**Configuration:**
- Admin can set a price for native ETH or any ERC-20 token contract address
- Price is expressed in USD per token unit (e.g., $2,000 per ETH)
- Prices can be updated at any time; changes apply immediately to new transfers

**Behavior when price is missing:**
- If a transfer is for a token with no configured price, the transfer is denied (fail-closed)
- This prevents accidental bypassing of the travel rule due to misconfiguration
- Admin must explicitly configure prices for all tokens that will be transferred

### Compliance Logs

An immutable, append-only audit trail of every compliance decision made by the system.

**Contents of each log entry:**
- **User identification**: the originator's user DID and internal organization user ID
- **Transfer details**: from address, to address, amount in native units (wei), amount in USD, token address/type
- **Compliance evaluation**: the threshold that applied, the decision (allowed or denied), and the reason
- **Record reference**: the travel rule record ID that was consumed (if any)
- **Timestamp**: when the decision was made
- **Status**: compliance decision at evaluation time, not the transaction outcome

**Important:** Logs record the compliance decision made by the Privacy Proxy before forwarding the transaction to the Ethereum node. The transaction may later fail at the node level (invalid nonce, revert, insufficient gas, etc.) — the compliance log records the compliance gate decision, not the final transaction outcome. This separation is intentional: compliance decisions are atomic and immutable, while node transaction outcomes depend on network state.

**Immutability:**
- Logs use database BIGSERIAL IDs (append-only)
- No UPDATE or DELETE operations are permitted on logs (enforced at database level)
- Logs cannot be modified, only queried
- Provides reliable audit trail for regulatory review

## Admin API Endpoints

### Organization Compliance Endpoints

All paths under `/api/v1/admin/orgs/:org_id/compliance/`:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/config` | Retrieve compliance configuration (enabled status, threshold) |
| PUT | `/config` | Update compliance configuration (enable/disable, set org-wide threshold USD) |
| GET | `/tokens` | List all configured token prices for this organization |
| PUT | `/tokens/:token_address` | Create or update price for a token (ETH or ERC-20) |
| DELETE | `/tokens/:token_address` | Remove token price configuration |
| GET | `/travel-rule-records` | List travel rule records (paginated, filterable by status) |
| POST | `/travel-rule-records` | Create a new travel rule record |
| DELETE | `/travel-rule-records/:id` | Delete an unused or expired travel rule record |
| GET | `/address-thresholds` | List per-address threshold overrides |
| PUT | `/address-thresholds/:address` | Create or update threshold override for an address |
| DELETE | `/address-thresholds/:address` | Delete threshold override for an address |
| GET | `/logs` | List compliance logs (paginated, filterable by decision, token, date range) |

### Global Sanctions Endpoints

Not organization-scoped (managed globally by system administrator):

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/admin/compliance/sanctions` | List all global sanctioned addresses |
| POST | `/api/v1/admin/compliance/sanctions` | Add address to global sanctions list |
| DELETE | `/api/v1/admin/compliance/sanctions/:id` | Remove address from global sanctions list |

## Admin Dashboard

The Compliance section in the admin dashboard provides visual access to all compliance management functions across 6 tabs:

### 1. Config Tab
Enable or disable compliance for the organization. Set the organization-wide threshold in USD. The default threshold when first enabled is $1,000.

### 2. Token Prices Tab
Configure USD prices for native ETH and any ERC-20 tokens that users may transfer. Prices are used to convert transfer amounts to USD for threshold comparison. All tokens must have a price configured before they can be transferred; transfers of tokens without prices are denied.

### 3. Travel Rules Tab
Create new travel rule records by specifying:
- Originator (user ID and name)
- Beneficiary (name and blockchain address)
- Token type (ETH or specific ERC-20)
- Amount in native units (wei; USD equivalent computed server-side)

View existing records with:
- Originator DID and user ID
- Beneficiary address (with copy-to-clipboard button)
- Amount (in token units and USD)
- Status (unused, used, or expired)
- Creation and expiry timestamps

Delete unused or expired records. Cannot delete used records (audit trail).

### 4. Address Thresholds Tab
Set per-address threshold overrides for specific sender or recipient addresses. Useful for known counterparties with special compliance classifications:
- High-risk addresses: lower threshold (e.g., $100 instead of $1,000)
- Low-risk partners: higher threshold (e.g., $10,000) or $0 if no restrictions
- Optional notes field for documenting why the override exists

### 5. Sanctions Tab
Manage the organization's sanctioned address blocklist. Add addresses to immediately block them from sending or receiving. Remove addresses to restore them to normal compliance status. View all sanctioned addresses and their block dates.

### 6. Logs Tab
Immutable audit trail of all compliance decisions. View each log entry:
- User DID and internal user ID
- Transfer details (from, to, amount, token)
- Applicable threshold
- Decision (allowed/denied) and reason
- Travel rule record ID consumed (if any)

Filter logs by:
- Decision type (allowed vs. denied)
- Transfer type (ETH vs. ERC-20)
- Token address
- User DID
- Date range

Logs cannot be deleted or modified.

## Example Scenario

**Setup:**
1. Organization enables compliance with organization-wide threshold of $1,000
2. ETH is configured at $2,000 per token
3. Address `0xHighRisk` gets a $100 threshold override (known counterparty with compliance restrictions)
4. Address `0xBadActor` is added to sanctions list

**Transfer scenarios:**

- **Transfer 1**: User sends $50 ETH to `0xRegular` → **ALLOWED** ($50 USD < $1,000 threshold, Layer 2 pass)

- **Transfer 2**: User sends $50 ETH to `0xHighRisk` → **ALLOWED** ($50 USD < $100 override for recipient, Layer 2 pass)

- **Transfer 3**: User sends $150 ETH to `0xHighRisk` → **DENIED** ($150 USD >= $100 override, Layer 3 reached, no travel rule record found)

- **Transfer 4**: Admin creates travel rule record for this user, $200 ETH, beneficiary `0xHighRisk`

- **Transfer 5**: User sends $150 ETH to `0xHighRisk` → **ALLOWED** ($150 USD >= $100 threshold, Layer 3 found matching record, record consumed)

- **Transfer 6**: User sends $50 ETH to `0xHighRisk` again → **DENIED** (the previous record was consumed and no new record exists)

- **Transfer 7**: User sends $5 ETH to `0xBadActor` → **DENIED** (`0xBadActor` is sanctioned, Layer 1 blocks regardless of amount)

- **Transfer 8**: Admin creates new travel rule record for the user, $500 ETH, beneficiary `0xHighRisk`

- **Transfer 9**: User sends $200 ETH to `0xHighRisk` → **ALLOWED** (new record matches, consumption threshold met, record consumed)

## Security Properties

**Fail-closed design:**
All uncertainties result in denial, protecting the organization from regulatory violations.
- Missing token price for a token being transferred: **denied**
- Database error during threshold lookup: **denied**
- Failure to create audit log: **denied** (transaction blocked rather than logged)

**Atomic record consumption:**
To prevent two concurrent transfers from claiming the same travel rule record:
- Database SELECT uses `FOR UPDATE SKIP LOCKED` locking
- Record status update from unused to used is atomic in same transaction
- Race conditions are avoided; at most one transfer can consume each record

**Single-use records:**
- Each travel rule record can only satisfy one transfer
- Even if record amount exceeds transfer amount, the entire record is consumed on first match
- New record required for each subsequent above-threshold transfer
- Prevents accidental reuse or multiple transfers against one authorization

**Immutable audit trail:**
- Compliance logs use auto-incrementing BIGSERIAL primary key
- No UPDATE or DELETE permissions on logs in application
- Database triggers enforce append-only semantics
- Logs remain even after records are deleted
- Provides immutable proof of all decisions for regulatory review

**Server-computed USD amounts:**
- `amount_usd` on travel rule records is computed server-side only
- Conversion from `amount_wei * token_price` happens at server time
- Client cannot specify or influence USD amount
- Prevents manipulation of compliance decisions through client-side values

**24-hour expiry:**
- Travel rule records are hardcoded to expire 24 hours after creation (non-configurable)
- Prevents stale authorizations from being used long after creation
- Expired records cannot satisfy Layer 3 checks
- Ensures compliance decisions reflect recent administrator review

**Address and token specificity:**
- Records must match the exact originator, beneficiary address, and token type
- Prevents cross-address or cross-token substitution
- Ensures administrator intentionality: each record authorizes one specific transfer scenario

