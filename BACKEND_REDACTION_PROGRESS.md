# Backend Address Redaction - Implementation Progress

## Goal
Make address redaction happen on the backend, not frontend. For pseudonymous/redacted disclosures, the real address should NEVER be sent to the client.

## Completed

### Privacy-Proxy Backend (`internal/server/explorer_api.go`)

1. **Updated `DisclosedAddress` struct** - Now includes:
   - `address` - Contains pseudonym for pseudonymous, "[REDACTED]" for redacted, real address for full
   - `address_id` - Opaque hash-based identifier for routing (doesn't reveal real address)
   - Removed `pseudonym` field (now `address` IS the pseudonym for pseudonymous)
   - `ens_name` only included for full disclosure

2. **Added `generateAddressID()` function** - Creates hash-based opaque ID from address + grantID

3. **Updated `getDisclosedAddressesForViewer()`** - Now properly redacts:
   - Full: includes real address + ENS
   - Pseudonymous: includes pseudonym as address, no ENS
   - Redacted: includes "[REDACTED]" as address, no ENS

4. **Added new endpoint `GET /api/v1/explorer/grant/:grant_id/resolve/:address_id`**
   - Resolves address_id back to real address (for explorer backend internal use only)
   - Localhost-only, returns: `{ real_address, disclosure_level, grant_id, pseudonym }`

5. **Privacy-proxy builds successfully**

### Explorer Frontend (partial)

1. **Updated `DisclosedAddress` type in `api.ts`** - Added `address_id` field

2. **Updated `useViewableAddresses` hook** - Now includes `addressId` in returned data

3. **Updated `AddressLink` component** - Handles pseudonymous/redacted display (tooltip doesn't leak real address)

4. **Updated `PrivacyDashboard`** - Shows pseudonym/redacted based on disclosure_level

## Completed (Full Implementation)

### 1. Explorer Frontend - New Grant-based Route ✅

**File: `src/pages/GrantedAddressPage.tsx`** (NEW)
- Created new page component for viewing disclosed addresses via grant
- Fetches data via `GET /api/privacy/grant/:grantId/:addressId`
- Displays address info with proper redaction based on disclosure level
- Shows pseudonym or "[REDACTED]" with appropriate styling
- Handles error states (expired/revoked grants, not found)

**File: `src/App.tsx`** ✅
- Added route: `<Route path="grant/:grantId/:addressId" element={<GrantedAddressPage />} />`

### 2. Explorer Frontend - Update Privacy Dashboard Links ✅

**File: `src/pages/PrivacyDashboard.tsx`**
- For `full` disclosure: Links to `/address/:address` (existing)
- For `pseudonymous`/`redacted`: Links to `/grant/:grant_id/:address_id` (new route)
- Updated to use pre-redacted `address` field from backend (no client-side pseudonym handling)
- Copy button only shown for full disclosure

### 3. Explorer Backend - New Endpoint ✅

**File: `internal/api/privacy_handlers.go`**
- Added `GrantedAddressResponse` struct with redacted display_address
- Added `handleGetGrantedAddress()` handler for `GET /api/privacy/grant/:grantId/:addressId`
- Resolves address_id via privacy-proxy, fetches data, applies redaction before response

**File: `internal/api/server.go`**
- Registered new route under `/api/privacy/grant/{grantId}/{addressId}`

### 4. Explorer Backend - Privacy Client Update ✅

**File: `internal/privacy/client.go`**
- Added `ResolveAddressResponse` struct
- Added `ResolveAddressID()` method to call privacy-proxy resolve endpoint
- Handles not found, forbidden (expired/revoked), and success cases

### 5. Frontend API Client Update ✅

**File: `src/lib/api.ts`**
- Added `GrantedAddressResponse` type
- Added `getGrantedAddress(grantId, addressId)` API method

## Security Fixes Applied

### HIGH: Default Case Fails-Safe ✅

Fixed both privacy-proxy and explorer backend to treat unknown disclosure levels as "redacted" instead of exposing real address:

**privacy-proxy** (`explorer_api.go:258-261`):
```go
default:
    // SECURITY: Fail-safe - treat unknown disclosure levels as redacted
    disclosed.Address = "[REDACTED]"
```

**explorer backend** (`privacy_handlers.go:306-308`):
```go
default:
    // SECURITY: Fail-safe - treat unknown disclosure levels as redacted
    displayAddress = "[REDACTED]"
```

## Security Review Findings (For Future Work)

### CRITICAL: Missing Viewer Authorization on Resolve Endpoint
The `resolveAddressID` endpoint validates grant expiry/revocation but does NOT verify that the requester is the authorized grant recipient. Any process on localhost can resolve any valid grant's address_id.

**Recommendation:** Add requester DID validation to the resolve endpoint.

### MEDIUM: Pseudonym is Reversible
The pseudonym is derived from first 4 hex chars of address (e.g., "0xABCD" → "Address-KLMN"). With ~65,536 possible pseudonyms, attackers could pre-compute a rainbow table.

**Recommendation:** Use HMAC-SHA256 with a server-side secret for pseudonym generation.

### MEDIUM: Address ID Lacks Server Secret
Address ID is SHA256(address:grantID) - anyone who knows/guesses the address can compute its ID.

**Recommendation:** Include a server-side secret (HMAC) in address ID generation.

### LOW: Other Findings
- Timing side channel in address_id lookup
- Error message information leakage (differentiates "not found" vs "expired" vs "revoked")
- No UUID validation on grant_id
- No length validation on address_id

## Testing Added ✅

Comprehensive tests written in:

1. **privacy-proxy** (`internal/server/explorer_api_test.go`) - 450+ lines:
   - `generateAddressID()`: Consistency, uniqueness, case insensitivity, no leakage
   - `generatePseudonym()`: Format, consistency, no leakage, edge cases
   - `getDisclosedAddressesForViewer()`: Full/pseudonymous/redacted disclosure
   - `resolveAddressID()`: Success, expired, revoked, invalid params
   - Security: Address leakage prevention tests
   - Edge cases: Empty values, concurrent access, multiple addresses

2. **explorer backend** (`internal/privacy/client_test.go`) - 200+ lines:
   - `ResolveAddressID()`: All disclosure levels, error handling
   - Mixed disclosure levels in viewable addresses
   - Timeout and network error handling

3. **explorer backend** (`internal/api/privacy_handlers_test.go`) - 200+ lines:
   - `handleGetGrantedAddress()`: Service disabled, missing params, errors
   - `filterAddressesForVisibility()`: Pseudonym usage, fail-open behavior
   - Address normalization tests

## Manual Testing Checklist

- [ ] Test full disclosure: Real address visible, links work
- [ ] Test pseudonymous: Only pseudonym visible, can view address via grant route
- [ ] Test redacted: Only "[REDACTED]" visible, limited view via grant route
- [ ] Test expired grant: Should return forbidden error
- [ ] Test revoked grant: Should return forbidden error

## Quick Commands

```bash
# Rebuild privacy-proxy
BASE_URL="http://192.168.1.133:8080" docker-compose up --build -d

# Rebuild explorer
SSO_REDIRECT_URI="http://192.168.1.133:3000/api/auth/callback" VITE_RPC_URL="http://192.168.1.133:8545" docker-compose -f /Users/blade/work/software/explorer/docker-compose.privacy-proxy.yml up --build -d

# Test viewable-addresses API
curl -s "http://localhost:8080/api/v1/explorer/viewable-addresses?did=YOUR_DID" | jq .

# Test resolve endpoint
curl -s "http://localhost:8080/api/v1/explorer/grant/GRANT_ID/resolve/ADDRESS_ID" | jq .
```
