# Privacy Proxy - CREATE3 Proxy Upgrade Demo

This demo showcases the complete flow of deploying and upgrading contracts using the CREATE3 deterministic deployment pattern with preregistered addresses.

## Prerequisites

1. **Foundry** - Install from https://getfoundry.sh
2. **Privacy Proxy** running with:
   - Admin API available
   - RPC endpoint configured
   - An organization with CREATE3 factory configured
3. **jq** - For JSON parsing
4. **curl** - For API calls

## Environment Variables

```bash
# Required - use ORG_SLUG (recommended, this is what you see in the UI)
export ORG_SLUG="your-org-slug"

# Or use ORG_ID directly if you know it
# export ORG_ID="uuid-of-your-org"

# Optional (defaults shown)
export ADMIN_API_URL="http://localhost:8080/api"
export RPC_URL="http://localhost:8545"
export CREATE3_FACTORY="<fetched from org config if not set>"

# Deployer key - defaults to Anvil's first account
export DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

**Note:** The script will automatically look up the organization ID from the slug via the API.

## Running the Demo

```bash
./demo-proxy-upgrade.sh
```

## What the Demo Does

### 1. Configuration Check
- Validates environment variables
- Fetches CREATE3 factory from org config (if not provided)

### 2. List Preregistered Addresses
- Shows existing preregistered addresses for the organization
- API: `GET /api/orgs/:org_id/addresses/preregistered`

### 3. Preregister New Addresses
- Registers 3 addresses for: proxy, implementation V1, implementation V2
- API: `POST /api/orgs/:org_id/addresses/preregister`

### 4. Build Contracts
- Compiles BoxV1 and BoxV2 Solidity contracts
- Uses OpenZeppelin's UUPS upgradeable pattern

### 5. Deploy Implementation V1
- Deploys BoxV1 to preregistered address via CREATE3 factory
- Verifies deployment

### 6. Deploy ERC1967 Proxy
- Deploys proxy pointing to V1 implementation
- Initializes with deployer as owner

### 7. Interact with V1
- Calls `version()` → returns "1.0.0"
- Calls `store(42)` → stores value
- Calls `retrieve()` → returns 42

### 8. Deploy Implementation V2
- Deploys BoxV2 to second preregistered address

### 9. Upgrade Proxy
- Calls `upgradeToAndCall()` to point proxy to V2

### 10. Interact with V2
- Calls `version()` → returns "2.0.0"
- Calls `retrieve()` → returns 42 (state preserved!)
- Calls `increment()` → new V2 function
- Calls `retrieve()` → returns 43

## Contract Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ERC1967 Proxy                           │
│  (Preregistered Address #1)                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Storage Slot 0x360894...                            │   │
│  │ Implementation Address → BoxV1 or BoxV2             │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ delegatecall
┌─────────────────────────────────────────────────────────────┐
│  BoxV1 (Preregistered Address #2)                           │
│  - version() → "1.0.0"                                      │
│  - store(uint256)                                           │
│  - retrieve() → uint256                                     │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼ upgrade
┌─────────────────────────────────────────────────────────────┐
│  BoxV2 (Preregistered Address #3)                           │
│  - version() → "2.0.0"                                      │
│  - store(uint256)                                           │
│  - retrieve() → uint256                                     │
│  - increment() ← NEW!                                       │
└─────────────────────────────────────────────────────────────┘
```

## Security Features Demonstrated

1. **Address Preregistration**: Addresses must be preregistered before deployment
2. **CREATE3 Determinism**: Addresses are determined by factory + salt, not bytecode
3. **Per-Org Isolation**: Each org has its own factory and address pool
4. **Bytecode Validation**: Deployed bytecode is validated for security

## Sample Output

```
╔══════════════════════════════════════════════════════════════════════╗
║                    CREATE3 Proxy Upgrade Demo                         ║
╚══════════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
▶ Step 1: Checking CREATE3 Factory Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✓ CREATE3 Factory: 0x1234...

...

╔══════════════════════════════════════════════════════════════════════╗
║                          Demo Complete!                               ║
╚══════════════════════════════════════════════════════════════════════╝

Summary:
┌─────────────────────────────────────────────────────────────────────┐
│  CREATE3 Factory:     0x1234...                                     │
│  Proxy Address:       0xabcd...                                     │
│  Implementation V1:   0x5678...                                     │
│  Implementation V2:   0x9abc...                                     │
├─────────────────────────────────────────────────────────────────────┤
│  Version before upgrade:  "1.0.0"                                   │
│  Version after upgrade:   "2.0.0"                                   │
│  Value preserved:         42                                        │
│  Value after increment:   43                                        │
└─────────────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### "No CREATE3 factory configured"
Configure a factory for your org via:
```bash
curl -X PUT "$ADMIN_API_URL/orgs/$ORG_ID/config/create3" \
  -H "Content-Type: application/json" \
  -d '{"factory": "0x..."}'
```

### "target address is not preregistered"
The CREATE3 factory call validation ensures all deployments go to preregistered addresses. Make sure you're using the salts returned from preregistration.

### "missing required deploy claim"
Ensure your user has the `deploy` claim in their group's permissions.
