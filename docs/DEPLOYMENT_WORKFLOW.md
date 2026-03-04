# Privacy Proxy: Contract Deployment Workflow

## Overview

This document describes how to deploy smart contracts through the privacy proxy. There are two modes:

1. **Runtime Tracing Mode** (default, recommended) - Simple workflow, no special tooling needed
2. **Preregistration Mode** - Advanced workflow with deterministic CREATE3 addresses

## Quick Start: Runtime Tracing Mode

When `ENABLE_RUNTIME_TRACING=true` (the default), deploying contracts is nearly identical to deploying on any public chain. The proxy validates all transactions at runtime using `debug_traceCall`.

### Prerequisites

1. User account with `deploy` permission in an organization
2. JWT access token (obtained from web UI after ZK proof authentication)
3. Foundry or Hardhat installed

### Step 1: Get Your Access Token

1. Open the Privacy Proxy web UI (e.g., `http://localhost:5173`)
2. Authenticate with your Privado ID wallet (scan QR code)
3. Go to **Settings** → **Developer** → **Copy Access Token**

### Step 2: Configure Your Environment

```bash
# Set the authorization header for all RPC requests
export ETH_RPC_HEADERS="Authorization: Bearer YOUR_JWT_TOKEN_HERE"

# Set the RPC URL
export ETH_RPC_URL="http://localhost:8080/rpc"
```

### Step 3: Deploy with Foundry

```bash
# Standard Foundry deployment - no changes needed!
forge script script/Deploy.s.sol \
  --rpc-url $ETH_RPC_URL \
  --broadcast \
  --private-key $PRIVATE_KEY
```

Or with a keystore:

```bash
forge script script/Deploy.s.sol \
  --rpc-url $ETH_RPC_URL \
  --broadcast \
  --account myKeystore \
  --sender 0xYourAddress
```

### Step 3 (Alternative): Deploy with Hardhat

```javascript
// hardhat.config.js
module.exports = {
  networks: {
    privacy: {
      url: process.env.ETH_RPC_URL,
      httpHeaders: {
        "Authorization": `Bearer ${process.env.PRIVACY_TOKEN}`
      },
      accounts: [process.env.PRIVATE_KEY]
    }
  }
};
```

```bash
export PRIVACY_TOKEN="YOUR_JWT_TOKEN_HERE"
npx hardhat run scripts/deploy.js --network privacy
```

### Step 3 (Alternative): Deploy with Cast

```bash
# Single contract deployment
cast send --create \
  --rpc-url $ETH_RPC_URL \
  --private-key $PRIVATE_KEY \
  $(cat out/MyContract.sol/MyContract.bin)
```

### How It Works

When you send a transaction through the proxy:

```
Your Transaction
       │
       ▼
┌─────────────────────────────────────┐
│         Privacy Proxy               │
├─────────────────────────────────────┤
│ 1. Validate JWT token               │
│ 2. Check user has 'deploy' claim    │
│ 3. Run debug_traceCall simulation   │
│ 4. Verify all call targets:         │
│    ├── Your org's contracts? ✓      │
│    ├── Precompiles (0x01-09)? ✓     │
│    ├── Shared infrastructure? ✓     │
│    └── Other org's contracts? ✗     │
│ 5. Forward to node if all pass      │
└─────────────────────────────────────┘
       │
       ▼
   EVM Node
```

### Token Refresh

Access tokens expire after 30 minutes. To refresh:

```bash
# Get a new token from the web UI, or use the refresh endpoint:
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'

# Update your environment
export ETH_RPC_HEADERS="Authorization: Bearer NEW_ACCESS_TOKEN"
```

### Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `401 Unauthorized` | Invalid or expired token | Get a new token from web UI |
| `403 Forbidden: deploy claim required` | User lacks deploy permission | Ask org admin to grant `deploy` claim |
| `403 Forbidden: cross-org access denied` | Contract calls another org's contract | Only interact with your org's contracts |
| `403 Forbidden: method not allowed` | Method not in user's allowlist | Check group permissions |

### Example: Full Deployment Session

```bash
# 1. Set up environment
export ETH_RPC_HEADERS="Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
export ETH_RPC_URL="http://localhost:8080/rpc"

# 2. Check connection
cast chain-id --rpc-url $ETH_RPC_URL
# Returns: 31337 (or your chain ID)

# 3. Check your balance
cast balance 0xYourAddress --rpc-url $ETH_RPC_URL

# 4. Deploy contracts
forge script script/Deploy.s.sol --rpc-url $ETH_RPC_URL --broadcast --private-key $PK

# 5. Verify deployment
cast code 0xDeployedContractAddress --rpc-url $ETH_RPC_URL
```

---

## Preregistration Mode (Advanced)

When `ENABLE_RUNTIME_TRACING=false`, you must preregister contract addresses before deployment. This mode provides deterministic CREATE3 addresses but requires additional setup.

> **Note**: Preregistration mode is disabled when runtime tracing is enabled. Use the simpler workflow above for most use cases.

---

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
│  Hardhat:                        Foundry:                   │
│  1. Write contracts              1. Write contracts         │
│  2. npx hardhat privacy:prepare  2. privacy-cli prepare     │
│  3. npx hardhat deploy           3. forge script --broadcast│
│         │                               │                   │
└─────────│───────────────────────────────│───────────────────┘
          │                               │
          └───────────────┬───────────────┘
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

---

## Option A: Hardhat Workflow

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

---

## Common: API Endpoint

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

## Common: Runtime Validation

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

## Common: Handling Special Cases

### Circular Dependencies

```solidity
// Pool needs Router address in constructor
// Router needs Pool address in constructor
```

Handled automatically because CREATE3 addresses are computed before any deployment:

```javascript
// Addresses computed first (deterministic with org-scoped salts)
// Salt = keccak256(orgID || saltPrefix || counter)
Pool:   0x111...  = CREATE3(factory, keccak256(orgID + "pool-salt" + 0))
Router: 0x222...  = CREATE3(factory, keccak256(orgID + "router-salt" + 0))

// Constructor args resolved
Pool.constructor(router: 0x222...)
Router.constructor(pool: 0x111...)

// Deploy in any order - addresses are known!
```

**Cross-org isolation**: The org ID is included in salt computation, so different organizations using the same factory and salt prefix will get different addresses. This prevents address collision attacks.

### Upgradeable Proxies

The plugin detects common proxy patterns (TransparentProxy, UUPS, Beacon):

```bash
npx hardhat privacy:prepare --network privacy --with-proxies
```

Registers:
- Implementation contract addresses
- Proxy contract addresses
- Admin/upgrade authority addresses

### Auto-Registration After Deployment

Contracts deployed through the privacy proxy are **automatically registered** in the RBAC system. Two paths:

**CREATE3 factory deployments:**
1. You preregister addresses (via API or CLI)
2. You deploy via the CREATE3 factory
3. Privacy proxy detects the successful factory deploy
4. Contract is auto-registered in the `contracts` table with metadata (`auto_registered: true`, factory address, salt)

**Plain CREATE deployments (`eth_sendTransaction` without `to`):**
1. Proxy computes the deterministic CREATE address from `keccak256(rlp([sender, nonce]))` _before_ forwarding
2. Address is immediately pre-registered to the deployer's org (closes cross-org access window)
3. Transaction is forwarded to the node
4. On successful mining: pre-registration is finalized as a full `Contract` record (`auto_registered: true`, `via: plain_create`)
5. On revert: pre-registration is cleaned up

**No manual registration step required for either path!**

You can then optionally add fine-grained grants (specific claims per group) via the admin API or UI.

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

## Common: Security Model

| Layer | Check | Timing |
|-------|-------|--------|
| Org-Scoped Salts | Salt = keccak256(orgID + prefix + i) | Prepare |
| Address Ownership | All deployed addresses belong to org | Prepare |
| Constructor Args | All address params authorized | Prepare |
| Bytecode Integrity | Hash matches registration | Deploy |
| Plain CREATE Pre-reg | CREATE address pre-registered before tx forwarded | Deploy |
| Auto-Registration | Contract added to RBAC after mine | Deploy |
| Runtime Calls | All call targets authorized | Every tx |
| State Access | Storage modifications traced | Every tx |

### What's Protected

- **Cross-org calls**: Contract in Org A cannot call contract in Org B
- **Address collision**: Org-scoped salts ensure different orgs get different CREATE3 addresses
- **Unauthorized addresses**: Cannot deploy to or interact with unregistered addresses
- **Hidden dependencies**: Constructor args with addresses must be declared via ABI

### What's NOT Protected (by design)

- **Intra-org calls**: Contracts within same org can call each other freely
- **Shared infrastructure**: Approved shared contracts accessible to all orgs
- **Precompiles**: Standard EVM precompiles (0x01-0x09) always allowed

## Common: Performance Considerations

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

## Example: Complete DeFi Deployment (Hardhat)

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

---

## Option B: Foundry Workflow

Foundry doesn't have a plugin system like Hardhat, so we provide two approaches:
1. **CLI Tool** (recommended) - Works with standard Foundry scripts
2. **Solidity Library** - For advanced users who want in-script control

### Approach 1: CLI Tool (Recommended)

#### Step 1: Install CLI

```bash
# Install the privacy-proxy CLI
go install github.com/privacy-proxy/cli@latest

# Or download binary
curl -L https://github.com/privacy-proxy/cli/releases/latest/download/privacy-cli-$(uname -s)-$(uname -m) -o /usr/local/bin/privacy-cli
chmod +x /usr/local/bin/privacy-cli
```

#### Step 2: Configure

Create `privacy.toml` in your project root:

```toml
[proxy]
api_url = "http://localhost:8080/api/v1"
rpc_url = "http://localhost:8080/rpc"
org_id = "org_abc123"

[factory]
# CREATE3 factory address (auto-discovered if not set)
address = "0x..."

[auth]
# JWT token or path to token file
token = "${PRIVACY_PROXY_TOKEN}"
```

#### Step 3: Write Standard Forge Script

```solidity
// script/Deploy.s.sol - UNCHANGED from public chain!
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/MyToken.sol";
import "../src/Pool.sol";
import "../src/Router.sol";

contract DeployScript is Script {
    function run() external {
        vm.startBroadcast();

        MyToken token = new MyToken("MyToken", "MTK");
        console.log("Token:", address(token));

        Pool pool = new Pool(address(token), 100);
        console.log("Pool:", address(pool));

        Router router = new Router(address(pool), address(token));
        console.log("Router:", address(router));

        vm.stopBroadcast();
    }
}
```

#### Step 4: Dry-Run and Prepare

```bash
# Run forge script in dry-run mode to capture deployments
forge script script/Deploy.s.sol --rpc-url $RPC_URL --dry-run

# Analyze dry-run output and register with privacy proxy
privacy-cli prepare --broadcast-file broadcast/Deploy.s.sol/31337/dry-run/run-latest.json
```

Output:
```
🔍 Analyzing Foundry broadcast file...

Found 3 contract deployments:
  ├── MyToken (no address dependencies)
  ├── Pool (depends on: MyToken)
  └── Router (depends on: Pool, MyToken)

📝 Computed CREATE3 addresses:
  ├── MyToken: 0x1234...
  ├── Pool:    0x5678...
  └── Router:  0x9abc...

📋 Extracted constructor ABIs:
  ├── MyToken: constructor(string,string)
  ├── Pool:    constructor(address,uint256)
  └── Router:  constructor(address,address)

✅ Registered with Privacy Proxy
   Deployment ID: dep_xyz789
   Valid for: 24 hours
```

#### Step 5: Deploy

```bash
# Deploy through privacy proxy (uses CREATE3 factory)
forge script script/Deploy.s.sol --rpc-url $PRIVACY_RPC --broadcast
```

The CLI modifies the broadcast to route through the CREATE3 factory, ensuring addresses match the preregistered values.

### Approach 2: Solidity Library

For users who want programmatic control within their Forge scripts:

#### Install Library

```bash
forge install privacy-proxy/foundry-lib
```

#### Use in Script

```solidity
// script/Deploy.s.sol
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "privacy-proxy/PrivacyDeploy.sol";
import "../src/MyToken.sol";
import "../src/Pool.sol";

contract DeployScript is Script, PrivacyDeploy {
    function run() external {
        // Initialize with proxy API (reads from env or config)
        initPrivacy(vm.envString("PRIVACY_API_URL"), vm.envString("ORG_ID"));

        vm.startBroadcast();

        // Compute addresses first (deterministic)
        address tokenAddr = computeAddress("token-v1");
        address poolAddr = computeAddress("pool-v1");

        // Register with privacy proxy (includes constructor ABI)
        registerDeployment("MyToken", tokenAddr, type(MyToken).creationCode,
            abi.encode("MyToken", "MTK"));
        registerDeployment("Pool", poolAddr, type(Pool).creationCode,
            abi.encode(tokenAddr, 100));

        // Deploy via CREATE3
        MyToken token = MyToken(deployCreate3("token-v1",
            type(MyToken).creationCode, abi.encode("MyToken", "MTK")));

        Pool pool = Pool(deployCreate3("pool-v1",
            type(Pool).creationCode, abi.encode(address(token), 100)));

        vm.stopBroadcast();

        console.log("Token:", address(token));
        console.log("Pool:", address(pool));
    }
}
```

### CLI Command Reference

```bash
# Prepare deployment from Foundry broadcast
privacy-cli prepare --broadcast-file <path>

# Prepare with custom config
privacy-cli prepare --broadcast-file <path> --config privacy.toml

# Prepare with explicit parameters
privacy-cli prepare --broadcast-file <path> \
  --api-url http://localhost:8080/api/v1 \
  --org-id org_abc123 \
  --token $JWT_TOKEN

# Dry-run (show what would be registered without calling API)
privacy-cli prepare --broadcast-file <path> --dry-run

# Verify deployment matches registration
privacy-cli verify --deployment-id dep_xyz789

# List pending deployments
privacy-cli list --org-id org_abc123
```

### Foundry Configuration

Add to `foundry.toml`:

```toml
[profile.privacy]
# Use privacy proxy RPC
eth_rpc_url = "http://localhost:8080/rpc"

# Increase timeout for tracing overhead
timeout = 60000

# Optional: custom sender for testing
sender = "0x..."
```

Deploy with privacy profile:

```bash
forge script script/Deploy.s.sol --profile privacy --broadcast
```

---

## Example: Complete DeFi Deployment (Foundry)

```solidity
// script/DeployDeFi.s.sol
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import "../src/Token.sol";
import "../src/Pool.sol";
import "../src/Router.sol";
import "../src/Staking.sol";

contract DeployDeFi is Script {
    function run() external {
        vm.startBroadcast();

        // Deploy token
        Token token = new Token("DeFi Token", "DFT", 1_000_000 ether);

        // Deploy pool with token reference
        Pool pool = new Pool(address(token), 30); // 0.3% fee

        // Deploy router with both references
        Router router = new Router(address(pool), address(token));

        // Deploy staking with token reference
        Staking staking = new Staking(address(token), 7 days);

        // Setup permissions
        token.setMinter(address(staking));
        pool.setRouter(address(router));

        vm.stopBroadcast();

        console.log("Token:", address(token));
        console.log("Pool:", address(pool));
        console.log("Router:", address(router));
        console.log("Staking:", address(staking));
    }
}
```

**Commands:**
```bash
# 1. Compile
forge build

# 2. Dry-run to capture deployment plan
forge script script/DeployDeFi.s.sol --rpc-url $RPC_URL --dry-run

# 3. Register with privacy proxy
privacy-cli prepare --broadcast-file broadcast/DeployDeFi.s.sol/31337/dry-run/run-latest.json

# 4. Deploy for real
forge script script/DeployDeFi.s.sol --rpc-url $PRIVACY_RPC --broadcast

# 5. Verify deployment
privacy-cli verify --deployment-id dep_xyz789
```

---

## Comparison: Hardhat vs Foundry

| Aspect | Hardhat | Foundry |
|--------|---------|---------|
| Integration | Native plugin | CLI tool + optional library |
| Setup | `npm install` + config | `go install` or binary download |
| Prepare step | `npx hardhat privacy:prepare` | `privacy-cli prepare --broadcast-file` |
| Script changes | None (plugin intercepts) | None (CLI analyzes broadcast) |
| CREATE3 routing | Automatic via plugin | Automatic via CLI |
| Advanced control | Plugin options | Solidity library |

Both approaches achieve the same result: deterministic addresses, preregistration, and runtime validation.

---

## Future Enhancements

1. **VS Code extension**: Visual deployment planning
2. **Gas estimation**: Account for proxy overhead in estimates
3. **Deployment versioning**: Track contract versions across upgrades
4. **Truffle support**: Legacy tooling compatibility
