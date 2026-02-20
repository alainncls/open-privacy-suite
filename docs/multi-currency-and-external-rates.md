# Multi-Currency Support + External Bank Rates API

## Overview

This feature adds two capabilities to the compliance subsystem:

1. **Multi-currency base currency** -- the admin can switch the system-wide pricing currency between USD, EUR, CHF, GBP, and AED. All token prices, thresholds, and compliance amounts are denominated in the selected currency.

2. **External rates API** -- banks and other external parties can push token prices into the system via API key-authenticated HTTP endpoints, independent of CoinGecko.

Both features share a common theme: the compliance system needs to work in jurisdictions that don't use USD and needs price data from sources beyond CoinGecko.

---

## Architecture

### System-wide base currency

The base currency is stored in a `system_settings` key-value table under the key `base_currency`. This table is general-purpose and can hold other system-wide configuration in the future without new migrations.

```
system_settings
+----------------+---------+---------------------+
| key (PK)       | value   | updated_at          |
+----------------+---------+---------------------+
| base_currency  | usd     | 2026-02-19 10:00:00 |
+----------------+---------+---------------------+
```

When the admin changes the base currency:

1. All rows in `system_token_prices` have their `price_usd` set to 0.
2. The next CoinGecko fetch cycle (runs every 5 minutes) detects the new currency and re-fetches all prices denominated in it.
3. Per-org manual token prices are NOT automatically adjusted -- the admin must update them manually.

The zeroing step is intentional. CoinGecko will repopulate system prices within minutes, and zeroed prices trigger staleness warnings in the UI so the admin knows prices are stale. This is preferable to converting stored prices using a snapshot exchange rate that would immediately begin drifting from reality.

### Column naming: `_usd` columns are now currency-agnostic

The database columns `price_usd`, `amount_usd`, `threshold_usd`, etc. retain their names across all tables (token_prices, compliance_logs, address_threshold_overrides, travel_rule_records, system_token_prices, and others). Their semantic meaning has changed from "price in US dollars" to "price in the system's base currency."

Renaming these columns would require migrations across 6+ tables, updates to every SQL query and Go struct tag, and changes to every frontend field reference. Since users never see column names, this is pure infrastructure churn with zero user-facing benefit. For a PoC, the tradeoff is clearly in favor of documenting the semantic change and deferring the rename to an MVP milestone if one ever happens.

### CoinGecko integration changes

The `Fetch()` function in `internal/pricing/fetcher.go` now accepts a `currency` parameter. CoinGecko's API already supports all five currencies via the `vs_currencies` query parameter, so this was a straightforward change.

The pricing service reads `base_currency` from `system_settings` before each fetch cycle via a new `SettingsStore` interface. This interface decouples the pricing service from the database implementation, making it testable with mocks.

### External rates API

External parties (banks, market data providers) push token prices via:

```
PUT /api/v1/external/rates/:coingecko_id
Authorization: Bearer ppk_<key>
Body: { "price": 2500.50 }
```

This updates the `system_token_prices` row for the given token, setting `source = 'external'`. The price is interpreted as being in the current base currency.

### API key authentication

The external rates API uses its own authentication mechanism, completely separate from both the JWT/ZK-proof identity system and the localhost admin middleware. This separation is intentional:

- **JWT auth** is tied to the DID/ZK-proof identity system. External banks don't have DIDs and shouldn't need user accounts.
- **Localhost middleware** restricts access to requests originating from the local machine. Banks call from external networks.
- **API keys** are the standard pattern for machine-to-machine communication. They are simple to generate, distribute, and revoke.

The auth flow:

```
Request with "Authorization: Bearer ppk_..." header
    |
    v
apikey_middleware.go
    |-- Extract key from header
    |-- SHA256 hash the key
    |-- Look up hash in api_keys table
    |-- Check: not revoked, not expired
    |-- Check: has required permission (e.g., "rates:write")
    |-- Update last_used_at (async, fire-and-forget)
    |-- Set key info in request context
    |
    v
external_rates.go handler
```

---

## Database Schema

### system_settings

```sql
CREATE TABLE system_settings (
    key        VARCHAR(100) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_settings (key, value)
VALUES ('base_currency', 'usd')
ON CONFLICT (key) DO NOTHING;
```

### api_keys

```sql
CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         VARCHAR(255) NOT NULL,
    key_hash     VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hex digest
    key_prefix   VARCHAR(12) NOT NULL,          -- "ppk_" + first 8 chars, for display
    permissions  TEXT[] NOT NULL DEFAULT '{rates:write}',
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash);
```

Both tables are created in migration `017_multi_currency_support.sql`.

---

## API Reference

### External Rates (API key auth)

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/api/v1/external/rates/:coingecko_id` | Push a token price |

**Request:**
```
Authorization: Bearer ppk_a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0
Content-Type: application/json

{ "price": 2500.50 }
```

**Responses:**
- `200` -- Price updated. Returns `{ "coingecko_id": "ethereum", "symbol": "ETH", "price_usd": 2500.50, "source": "external" }`.
- `400` -- Price is negative or zero.
- `401` -- Missing, invalid, revoked, or expired API key.
- `404` -- Token not found in system prices.

### Admin Currency (localhost auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/compliance/currency` | Get current currency and all available options |
| `PUT` | `/api/v1/admin/compliance/currency` | Change base currency (zeros system prices) |

**GET response:**
```json
{
  "currency": "usd",
  "all_currencies": [
    { "code": "usd", "name": "US Dollar", "symbol": "$" },
    { "code": "eur", "name": "Euro", "symbol": "\u20ac" },
    { "code": "chf", "name": "Swiss Franc", "symbol": "CHF" },
    { "code": "gbp", "name": "British Pound", "symbol": "\u00a3" },
    { "code": "aed", "name": "UAE Dirham", "symbol": "AED" }
  ]
}
```

**PUT request:**
```json
{ "currency": "eur" }
```

**PUT response:**
```json
{ "currency": "eur", "message": "Base currency updated..." }
```

### Admin API Keys (localhost auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/admin/compliance/api-keys` | List all API keys (no plaintext) |
| `POST` | `/api/v1/admin/compliance/api-keys` | Create a new API key |
| `DELETE` | `/api/v1/admin/compliance/api-keys/:id` | Revoke an API key |

**POST request:**
```json
{ "name": "Bank A", "expires_in_days": 90 }
```

**POST response (201):**
```json
{
  "key": "ppk_a3f8b2c1d4e5f6a7...",
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Bank A",
  "key_prefix": "ppk_a3f8b2c1",
  "permissions": ["rates:write"],
  "expires_at": "2026-05-20T10:00:00Z",
  "created_at": "2026-02-19T10:00:00Z"
}
```

The `key` field is returned **only on creation**. It cannot be retrieved later because only the SHA256 hash is stored.

---

## Design Decisions

### Key-value `system_settings` vs. dedicated currency table

A dedicated `currency_config` table with typed columns would require a new migration every time we add a system-wide setting. The key-value pattern is more flexible and sufficient for this use case. The value is a simple string (`"usd"`, `"eur"`, etc.) validated at the application layer. For a PoC, this is the right level of formality.

### Zeroing prices on currency change vs. converting

Three options were considered:

1. **Zero prices and let CoinGecko re-fetch** (chosen) -- Simple, accurate within 5 minutes, triggers visible staleness warnings in the UI.
2. **Convert using a stored exchange rate** -- The converted values would begin drifting from reality immediately. We'd need to store and maintain exchange rates, adding complexity.
3. **Maintain both `price_usd` and `price_<currency>` columns** -- Massive schema change across 6+ tables for a PoC feature. Rejected.

The zeroing approach has a brief window (up to 5 minutes) where system prices are zero. During this window, compliance checks that depend on fiat amounts may behave unexpectedly. This is acceptable because currency changes are rare admin operations, not something triggered during normal transaction flow.

Per-org manual token prices are not zeroed because they were explicitly set by the admin for that organization. The admin is responsible for updating these when switching currencies.

### Separate API key auth vs. reusing existing auth

The system has two existing auth mechanisms:

- **JWT with ZK-proof identity** -- for end users with DIDs. Banks don't have DIDs.
- **Localhost middleware** -- for admin operations from the local machine. Banks call from external networks.

Neither fits the external rates use case. API keys are the standard solution for machine-to-machine auth: simple to generate, easy for banks to integrate, trivial to revoke.

OAuth2 client credentials flow was considered and rejected as overkill. HMAC request signing was considered and rejected as unnecessarily complex for the bank integration team.

### SHA256 for key hashing vs. bcrypt

API keys are 32 bytes of cryptographic randomness (256 bits of entropy). This is not a password scenario.

- **bcrypt** is designed for low-entropy, human-chosen passwords. It's intentionally slow (100ms+) and non-deterministic (different hash each time). To look up a key hashed with bcrypt, you'd need to fetch all keys from the database and compare each one. This does not scale.
- **SHA256** is fast, deterministic, and provides 256-bit preimage resistance. With 256 bits of input entropy, brute-forcing a SHA256 hash is computationally infeasible (2^256 operations). The deterministic output allows direct database lookup: `WHERE key_hash = SHA256(input)`.

SHA256 is the correct choice here. The same reasoning applies to how GitHub, Stripe, and most API key systems work.

### `ppk_` key prefix

The `ppk_` prefix (Privacy Proxy Key) serves two purposes:

1. **Visual identification** -- When a key appears in logs, config files, or code, it's immediately identifiable as a Privacy Proxy API key rather than a JWT, session token, or other credential.
2. **Secret scanning** -- Tools like GitHub's secret scanner, trufflehog, and git-secrets can be configured to flag `ppk_` patterns, catching accidental key leaks in commits.

This follows the established pattern used by Stripe (`sk_`/`pk_`), GitHub (`ghp_`/`ghs_`), and others.

### Fire-and-forget `last_used_at` updates

Every API request with a valid key triggers a `last_used_at` timestamp update. This is informational: it helps admins identify unused or potentially compromised keys.

Updating synchronously would add a database write to the critical path of every API call. Since the timestamp is best-effort, a fire-and-forget goroutine is used. If the update fails (e.g., transient DB error), the request still succeeds and the timestamp is simply not updated. This is an acceptable tradeoff for a PoC.

Alternatives considered:
- **Batch/queue updates** -- Correct for high-throughput production systems, overkill here.
- **Skip tracking entirely** -- Rejected because knowing which keys are actually in use is valuable for security hygiene.

### React `CurrencyContext` vs. prop drilling or state management

Six compliance components need access to the current currency code, symbol, and formatting function. A React context provider at the compliance subtree root makes this data available without passing props through intermediate components.

Each component calling the currency API independently would cause redundant network requests. A global state manager like Redux or Zustand would be overkill for a single piece of shared state. React context is the right tool for this scale.

The context provides:
- `currency` -- the currency code (e.g., `"eur"`)
- `currencyLabel` -- the display name (e.g., `"EUR"`)
- `formatAmount(value)` -- formats a number with the correct currency symbol (e.g., `"EUR 2,500.00"`)

---

## File Inventory

### New files

| File | Purpose |
|------|---------|
| `internal/db/migrations/017_multi_currency_support.sql` | Migration: `system_settings` and `api_keys` tables |
| `internal/server/apikey_middleware.go` | API key extraction, validation, permission checking |
| `internal/server/apikey_helpers.go` | Key generation (random bytes, SHA256, prefix extraction) |
| `internal/server/external_rates.go` | External rates endpoint + admin currency/API key endpoints |
| `internal/server/apikey_middleware_test.go` | Unit tests for middleware |
| `internal/server/external_rates_test.go` | Unit tests for endpoints |
| `frontend/src/components/compliance/CurrencyContext.tsx` | React context for currency state |
| `frontend/src/components/compliance/APIKeyManager.tsx` | API key management UI component |
| `e2e/playwright/tests/compliance/01-currency-settings.spec.ts` | E2E: currency switching |
| `e2e/playwright/tests/compliance/02-external-rates.spec.ts` | E2E: external rates push |

### Key modifications

| File | Changes |
|------|---------|
| `internal/compliance/models.go` | `SupportedCurrency` type, `ValidCurrencies`/`CurrencySymbols` maps, `APIKey` struct, `WeiToFiat` alias |
| `internal/compliance/store.go` | 8 new interface methods for settings and API key CRUD |
| `internal/db/compliance_store.go` | PostgreSQL implementations including `TEXT[]` handling |
| `internal/pricing/fetcher.go` | `Fetch()` accepts `currency` parameter |
| `internal/pricing/service.go` | `SettingsStore` interface, reads `base_currency` before each cycle |
| `internal/server/admin_compliance.go` | Route registration for new endpoints |
| `internal/server/server.go` | Wiring for new stores and route groups |
| `frontend/src/` (multiple) | All 6 compliance components updated for dynamic currency; ComplianceManager and main.tsx updated for API Keys tab |

---

## Security Considerations

- **No plaintext storage.** API keys are SHA256-hashed before insertion. The plaintext is returned exactly once at creation time.
- **Auth isolation.** The API key middleware is a separate code path from JWT auth and localhost middleware. There is no shared state or cross-contamination between auth mechanisms.
- **Revocation and expiry.** The middleware rejects revoked and expired keys before the request reaches any handler.
- **Permission scoping.** Each key has an explicit permissions array. The middleware checks that the key has the required permission for the endpoint.
- **Usage tracking.** `last_used_at` gives admins visibility into key activity, aiding in identifying unused or compromised keys.
- **Prefix for leak detection.** The `ppk_` prefix enables automated secret scanning.

---

## Known Limitations

These are accepted PoC tradeoffs, not bugs:

1. **Column names say `_usd` regardless of actual currency.** Documented semantic change; rename deferred.
2. **Per-org manual prices are not auto-adjusted on currency change.** Admin must update manually.
3. **Only `rates:write` permission exists.** No read-only API keys yet.
4. **No rate limiting on the external rates API.** A production system would need this.
5. **No audit log for API key operations.** Creation and revocation are not logged beyond standard request logs.
6. **Up to 5 minutes of zero prices after currency change.** CoinGecko fetch interval is fixed; no way to trigger immediate refresh.
7. **No key rotation workflow.** To rotate, admin must create a new key and revoke the old one manually.
