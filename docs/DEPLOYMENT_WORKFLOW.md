# Privacy Proxy: Contract Deployment Workflow

## Overview

This document describes the recommended approach for deploying smart contracts to a privacy-protected blockchain while maintaining cross-org isolation and maximum compatibility with existing development tools.

## Goals

1. **Maximum Compatibility** - Existing contracts written for public chains should deploy with minimal changes
2. **Familiar Tooling** - Use Hardhat, Foundry, Truffle as normal
3. **Cross-Org Isolation** - Contracts from Org A cannot interact with Org B's contracts
4. **Security** - All address references validated at deploy and runtime

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Developer Workflow                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Write contracts (unchanged from public chain)           │
│  2. npx hardhat privacy:prepare  ──────────────────────┐    │
│  3. npx hardhat deploy (unchanged)                     │    │
│                                                        │    │
└────────────────────────────────────────────────────────│────┘
                                                         │
                                                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Privacy Proxy                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────┐    ┌─────────────────┐                 │
│  │ Deployment      │    │ Runtime         │                 │
│  │ Validation      │    │ Validation      │                 │
│  │                 │    │                 │                 │
│  │ - Preregistered │    │ - Trace calls   │                 │
│  │   addresses     │    │ - Verify targets│                 │
│  │ - Constructor   │    │ - Check org     │                 │
│  │   ABI & args    │    │   ownership     │                 │
│  └─────────────────┘    └─────────────────┘                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    EVM Blockchain                            │
└─────────────────────────────────────────────────────────────┘
```

## Deployment Flow

### Step 1: One-Time Setup

```bash
npm install @privacy-proxy/hardhat-plugin
```

```javascript
// hardhat.config.js
require('@privacy-proxy/hardhat-plugin');

module.exports = {
  networks: {
    privacy: {
      url: "http://localhost:8080/rpc",
      accounts: [PRIVATE_KEY],
      privacyProxy: {
        apiUrl: "http://localhost:8080/api/v1",
        orgId: process.env.ORG_ID,
        // Factory auto-discovered or specified
      }
    }
  }
};
```

### Step 2: Prepare Deployment

```bash
npx hardhat privacy:prepare --network privacy
```

This command:
1. **Dry-runs** the deployment script to capture all contract deployments
2. **Computes** CREATE3 addresses for all contracts
3. **Extracts** constructor ABIs and argument values
4. **Resolves** inter-contract address references
5. **Registers** everything with the proxy via single API call

Output:
```
🔍 Analyzing deployment script...

Found 3 contracts:
  ├── Token (no address dependencies)
  ├── Pool (depends on: Token)
  └── Router (depends on: Pool, Token)

📝 Computed addresses:
  ├── Token:  0x1234...
  ├── Pool:   0x5678...
  └── Router: 0x9abc...

✅ Registered with Privacy Proxy
   Deployment ID: dep_abc123
   Valid for: 24 hours
```

### Step 3: Deploy (Unchanged!)

```bash
npx hardhat run scripts/deploy.js --network privacy
```

The existing deployment script works without modification. The plugin:
- Intercepts `contract.deploy()` calls
- Routes through CREATE3 factory
- Uses preregistered addresses

## API Endpoint

### POST /api/v1/orgs/{org_id}/deployments/prepare

Registers a deployment plan with computed addresses and constructor validation.

**Request:**
```json
{
  "contracts": [
    {
      "name": "Token",
      "salt": "0x746f6b656e2d7631",
      "bytecode_hash": "0xabc...",
      "constructor_abi": [{"type": "constructor", "inputs": [...]}],
      "constructor_args": ["MyToken", "MTK"]
    },
    {
      "name": "Pool",
      "salt": "0x706f6f6c2d7631",
      "bytecode_hash": "0xdef...",
      "constructor_abi": [{"type": "constructor", "inputs": [
        {"name": "token", "type": "address"},
        {"name": "fee", "type": "uint256"}
      ]}],
      "constructor_args": ["0x1234...", 1000]
    }
  ],
  "factory": "0x..."
}
```

**Response:**
```json
{
  "deployment_id": "dep_abc123",
  "addresses": {
    "Token": "0x1234...",
    "Pool": "0x5678..."
  },
  "expires_at": "2024-01-15T00:00:00Z"
}
```

**Validation performed:**
1. All constructor address arguments are authorized (same org, shared infra, or in same deployment)
2. Bytecode hashes recorded for deploy-time verification
3. All addresses preregistered atomically

## Runtime Validation

Every transaction is validated before forwarding to the chain:

```
Transaction arrives
       │
       ▼
┌─────────────────┐
│ debug_traceCall │  ← Simulate transaction
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Extract calls:  │
│ - CALL          │
│ - DELEGATECALL  │
│ - STATICCALL    │
│ - CREATE/CREATE2│
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│ For each target address:            │
│                                     │
│ ✓ Same org?         → Allowed       │
│ ✓ Shared infra?     → Allowed       │
│ ✓ Precompile?       → Allowed       │
│ ✗ Other org?        → REJECT        │
│ ✗ Unknown?          → REJECT        │
└────────┬────────────────────────────┘
         │
         ▼
    Forward or Reject
```

## Handling Special Cases

### Circular Dependencies

```solidity
// Pool needs Router address in constructor
// Router needs Pool address in constructor
```

Handled automatically because CREATE3 addresses are computed before any deployment:

```javascript
// Addresses computed first (deterministic)
Pool:   0x111...  = CREATE3(factory, deployer, "pool-salt")
Router: 0x222...  = CREATE3(factory, deployer, "router-salt")

// Constructor args resolved
Pool.constructor(router: 0x222...)
Router.constructor(pool: 0x111...)

// Deploy in any order - addresses are known!
```

### Upgradeable Proxies

The plugin detects common proxy patterns (TransparentProxy, UUPS, Beacon):

```bash
npx hardhat privacy:prepare --network privacy --with-proxies
```

Registers:
- Implementation contract addresses
- Proxy contract addresses
- Admin/upgrade authority addresses

### External Dependencies

Shared infrastructure (oracles, bridges, DEX routers) configured in org settings:

```javascript
// hardhat.config.js
privacyProxy: {
  sharedContracts: {
    "chainlink-oracle": "0x...",
    "uniswap-router": "0x..."
  }
}
```

These must be pre-approved by org admin via the admin API.

## Security Model

| Layer | Check | Timing |
|-------|-------|--------|
| Address Ownership | All deployed addresses belong to org | Prepare |
| Constructor Args | All address params authorized | Prepare |
| Bytecode Integrity | Hash matches registration | Deploy |
| Runtime Calls | All call targets authorized | Every tx |
| State Access | Storage modifications traced | Every tx |

### What's Protected

- **Cross-org calls**: Contract in Org A cannot call contract in Org B
- **Unauthorized addresses**: Cannot deploy to or interact with unregistered addresses
- **Hidden dependencies**: Constructor args with addresses must be declared via ABI

### What's NOT Protected (by design)

- **Intra-org calls**: Contracts within same org can call each other freely
- **Shared infrastructure**: Approved shared contracts accessible to all orgs
- **Precompiles**: Standard EVM precompiles (0x01-0x09) always allowed

## Performance Considerations

### Overhead

| Operation | Additional Latency | Notes |
|-----------|-------------------|-------|
| Prepare | ~1-5s | One-time per deployment |
| Deploy tx | ~10-50ms | Address lookup + validation |
| Runtime tx | ~50-200ms | Full trace simulation |

### Mitigation Strategies

1. **Caching**: Cache trace results for identical transactions
2. **Parallel tracing**: Trace while validating other checks
3. **Trusted mode**: Skip tracing for contracts marked as "audited"
4. **Batch optimization**: Group multiple calls in single trace

## Example: Complete DeFi Deployment

```javascript
// scripts/deploy.js - UNCHANGED from public chain!
const { ethers } = require("hardhat");

async function main() {
  const Token = await ethers.getContractFactory("MyToken");
  const token = await Token.deploy("MyToken", "MTK");
  await token.deployed();
  console.log("Token:", token.address);

  const Pool = await ethers.getContractFactory("Pool");
  const pool = await Pool.deploy(token.address, 100);
  await pool.deployed();
  console.log("Pool:", pool.address);

  const Router = await ethers.getContractFactory("Router");
  const router = await Router.deploy(pool.address, token.address);
  await router.deployed();
  console.log("Router:", router.address);
}

main();
```

**Commands:**
```bash
# Analyze and register (first time or when contracts change)
npx hardhat privacy:prepare --network privacy

# Deploy (identical to public chain)
npx hardhat run scripts/deploy.js --network privacy
```

## Future Enhancements

1. **Foundry support**: `forge privacy:prepare` equivalent
2. **VS Code extension**: Visual deployment planning
3. **Gas estimation**: Account for proxy overhead in estimates
4. **Deployment versioning**: Track contract versions across upgrades
