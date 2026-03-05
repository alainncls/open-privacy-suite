# PR 36: Multi-Currency, Per-Org Token Prices & Contract Grant UX

## Overview

PR 36 introduces 3 major features:
1. **Multi-Currency Support** — switch base currency between USD, EUR, CHF, GBP, AED
2. **Per-Org Custom Token Prices** — admin configures token prices per organization, with optional CoinGecko auto-fetch
3. **Contract Grant UX** — self-constraint checkboxes for function parameters

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Price Resolution Chain                    │
│                                                               │
│  1. Per-org token_prices (manual or CoinGecko-linked)        │
│     ├── CoinGecko-linked → resolve from system_token_prices  │
│     └── Manual → resolve from prices_by_currency[currency]   │
│  2. Auto-resolve: "native" → system "ethereum" price         │
│  3. Not found → FAIL CLOSED (block transaction)              │
└─────────────────────────────────────────────────────────────┘
```

### Key design decisions
- CoinGecko prices are fetched for **all 5 currencies at once** and stored in `prices_by_currency` JSONB — switching currency is instant (no re-fetch)
- Manual per-org token prices are set per currency via the `prices` map in the API (e.g. `{"usd": 42.50, "eur": 39.00}`)
- **Fail-closed**: if a token doesn't have a price for the active currency, transactions are blocked — never silently passed with a wrong price
- Currency switch returns **409 Conflict** if manual tokens lack prices for the target currency, requiring force confirmation
- A **red warning banner** appears in the Token Prices UI when manual tokens are blocking transactions due to missing prices
- Token addresses are validated: must be `"native"` or a valid 0x-prefixed 42-char Ethereum address

---

## 1. Currency Support

**Admin UI:** `/admin/compliance` → Currency selector in top bar

**Supported currencies:** USD ($), EUR (€), CHF, GBP (£), AED

### Switch currency via UI
1. Open compliance dashboard
2. Use the currency dropdown (top bar, next to org selector)
3. Select EUR — CoinGecko prices switch instantly (all currencies pre-stored)
4. All amounts across the UI update with the new currency symbol (€)
5. If manual per-org tokens lack EUR prices → warning dialog appears listing affected tokens
6. Click "Switch Anyway" to force, or cancel and configure missing prices first
7. After force-switching, a **persistent red banner** shows which tokens are blocking transactions

### Switch currency via API
```bash
# Get current currency + list of supported currencies
curl http://localhost:8080/api/v1/admin/compliance/currency \
  -H "X-Admin-Token: $ADMIN_API_TOKEN"
# Response: {"currency":"usd","all_currencies":[...],"coingecko_enabled":true}

# Change to EUR (may return 409 if manual tokens lack EUR prices)
curl -X PUT http://localhost:8080/api/v1/admin/compliance/currency \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"currency":"eur"}'
# 200: {"currency":"eur","message":"Base currency updated to EUR."}
# 409: {"error":"...","affected_tokens":[...],"currency":"eur"}

# Force switch (acknowledging affected tokens will block transactions)
curl -X PUT http://localhost:8080/api/v1/admin/compliance/currency \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"currency":"eur","force":true}'
# 200: includes "warning" and "affected_tokens" in response

# Invalid currency → 400
curl -X PUT http://localhost:8080/api/v1/admin/compliance/currency \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"currency":"xyz"}'
# 400: "unsupported currency; valid options: usd, eur, chf, gbp, aed"
```

After changing currency:
- CoinGecko prices switch instantly from pre-stored `prices_by_currency`
- Manual per-org token `price_fiat` updates from their `prices_by_currency` if available
- Manual tokens without the new currency price: `price_fiat` set to 0 → **blocks all transactions** until configured
- UI updates all amounts with the new currency symbol
- Historical compliance log records retain the currency they were created with

---

## 2. System Token Prices (CoinGecko)

**Admin UI:** `/admin/compliance/tokens` → "Auto-Fetched Prices (CoinGecko)" section

### How it works
- CoinGecko fetches prices for ETH, USDT, USDC in **all 5 currencies** in a single API call
- Prices stored in `prices_by_currency` JSONB: `{"usd": 3500, "eur": 3200, "chf": 3100, "gbp": 2800, "aed": 12800}`
- Switching currency reads from stored data — no re-fetch needed
- Stale prices (configurable threshold) trigger fail-closed behavior

### Verify CoinGecko prices
1. Navigate to Token Prices tab
2. Three CoinGecko prices should appear: ETH, USDT, USDC
3. Each card shows: price, status (Live/Stale/Unavailable), last update time
4. Switch currency → prices update instantly without re-fetch

### API
```bash
# List system prices (includes prices_by_currency for all currencies)
curl http://localhost:8080/api/v1/admin/compliance/system-token-prices \
  -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

### CoinGecko disabled
1. Set `DISABLE_COINGECKO=true` in env and restart
2. Token Prices page shows "CoinGecko price fetching is disabled" message
3. Manual per-org prices still work
4. **Important:** Without CoinGecko AND without manual prices, ETH transfers are blocked (fail-closed)

---

## 3. Per-Org Token Prices

**Admin UI:** `/admin/compliance/tokens` → "Per-Organization Token Prices" section

### Two pricing modes

| Mode | How it works | Currency switching |
|------|-------------|-------------------|
| **CoinGecko-linked** | Price resolves from system CoinGecko price | Automatic (all currencies pre-fetched) |
| **Manual** | Admin sets price per currency via `prices` map | Must set price for each currency used |

### Add a CoinGecko-linked token (UI)
1. Select an organization from the dropdown
2. Click "Add Token"
3. Set token address to `native`, select source "CoinGecko: ETH"
4. Symbol and decimals auto-fill, price auto-resolves from system CoinGecko price
5. Save — token appears with "CoinGecko: ETH" badge and live price

### Add a manual-priced token (UI)
1. Click "Add Token"
2. Set token address (must be `native` or valid 42-char 0x address)
3. Source: "Manual", symbol: "MYTOKEN", decimals: 18, price: 42.50
4. Save — price is stored for the **currently active currency**

### Token Price API

**Important:** Use the org **UUID**, not the slug. Find it via:
```bash
curl -s http://localhost:8080/api/v1/admin/rbac/organizations \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" | jq '.[].id'
# e.g. "00000000-0000-0000-0000-000000000001"
```

```bash
ORG_ID="00000000-0000-0000-0000-000000000001"

# List per-org tokens (includes prices_by_currency)
curl "http://localhost:8080/api/v1/admin/orgs/$ORG_ID/compliance/tokens" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Add/update a manual token with prices in multiple currencies
curl -X PUT "http://localhost:8080/api/v1/admin/orgs/$ORG_ID/compliance/tokens/0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"symbol":"MYTOKEN","decimals":18,"prices":{"usd":42.50,"eur":39.00,"gbp":34.00}}'
# prices_by_currency is accumulated — new currencies merge with existing

# Add a CoinGecko-linked token (price auto-resolves)
curl -X PUT "http://localhost:8080/api/v1/admin/orgs/$ORG_ID/compliance/tokens/native" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"symbol":"ETH","decimals":18,"coingecko_id":"ethereum"}'

# Delete a token
curl -X DELETE "http://localhost:8080/api/v1/admin/orgs/$ORG_ID/compliance/tokens/0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97" \
  -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

### Input validation
- **Token address:** must be `"native"` or `0x` + 40 hex chars (42 total). Short addresses like `0x1` are rejected.
- **Symbol:** max 20 characters
- **Decimals:** 0–77 (standard ERC-20 is 18)
- **Prices:** at least one currency required for manual tokens. Each price must be > 0. Currency codes validated against: `usd`, `eur`, `chf`, `gbp`, `aed`.
- **CoinGecko ID:** must be one of: `ethereum`, `tether`, `usd-coin`

### Test fail-closed behavior
1. Add a manual token with USD price only: `{"prices":{"usd":42.50}}`
2. Switch currency to EUR → 409 Conflict warns about the token
3. Force switch → token's `price_fiat` becomes 0 (no EUR price)
4. Red warning banner appears: "1 token blocking transactions"
5. Any compliance check for this token → **denied** ("no price configured for token X")
6. Add EUR price: `{"prices":{"eur":39.00}}` — merges with existing USD price, transactions work

---

## 4. Contract Grant UX — Self-Constraint Checkboxes

**Admin UI:** `/admin/rbac/contracts` → create/edit a contract grant

### What's new
When granting a group access to specific contract functions, you can restrict address-type parameters to the caller's own address ("self" constraint). This is enforced at runtime — the proxy decodes calldata and checks that the address parameter matches one of the user's linked wallet addresses.

### Examples
| Function | Self-constraint | Effect |
|----------|----------------|--------|
| `balanceOf(address)` | param 0 = self | User can only check their own balance |
| `transfer(address to, uint256)` | param 0 = self | User can only transfer to themselves |
| `transferFrom(address from, address to, uint256)` | param 0 = self | User can only transfer from themselves |
| `approve(address spender, uint256)` | param 0 = self | User can only approve themselves as spender |

### Test steps
1. Create a contract grant → select "Specific functions only"
2. **With ABI:** Upload an ABI → functions listed with names and selectors. Address-type params get a checkbox: "param must be caller's own address"
3. **Without ABI:** Common ERC20 selectors shown as buttons (balanceOf, transfer, approve, etc.)
4. Add `0xa9059cbb` (transfer) → check "to must be caller's own address"
5. Add `0x23b872dd` (transferFrom) → check both "from" and "to" must be self
6. Save → edit again → verify checkboxes persist

### Validation
- Invalid selector (not `0x` + 8 hex chars) → error
- Duplicate selector → error

---

## 5. Quick Checklist

### Currency
- [ ] Switch between USD/EUR/CHF/GBP/AED via UI dropdown
- [ ] Switch via API (`PUT /api/v1/admin/compliance/currency`)
- [ ] Prices switch instantly (no re-fetch delay)
- [ ] UI shows correct currency symbol everywhere
- [ ] Invalid currency rejected (400)
- [ ] 409 Conflict warning when manual tokens lack prices for target currency
- [ ] Force switch works after confirming warning
- [ ] Red warning banner appears for tokens blocking transactions after force switch
- [ ] Historical compliance logs retain their original currency

### System Prices (CoinGecko)
- [ ] ETH, USDT, USDC prices appear with Live status
- [ ] `prices_by_currency` includes all 5 currencies in API response
- [ ] Stale prices show warning
- [ ] Refresh button reloads prices
- [ ] `DISABLE_COINGECKO=true` shows disabled message
- [ ] With CoinGecko disabled and no manual prices → ETH transfers blocked

### Per-Org Token Prices
- [ ] Add CoinGecko-linked token (price auto-resolves, multi-currency)
- [ ] Add manual-priced token (price stored for active currency)
- [ ] Set multi-currency prices via API (`"prices":{"usd":42,"eur":39}`)
- [ ] Edit token (change price, switch source)
- [ ] Delete token
- [ ] No org selected → "Select an organization" prompt
- [ ] Price shows "Unavailable" when CoinGecko price is missing
- [ ] Invalid token address rejected (must be "native" or 42-char 0x address)
- [ ] **Fail-closed**: manual token without price for active currency blocks transactions
- [ ] **Fail-closed**: $0 price blocks transactions (never silently passes)
- [ ] **Fail-closed**: no token price at all → transactions blocked

### Contract Grants
- [ ] Self-constraint checkboxes for address params
- [ ] Works with and without ABI
- [ ] Rules persist after save
- [ ] Selector validation works
- [ ] Runtime enforcement: self-constrained params checked against caller's addresses
