# Privacy Proxy Demo Scripts

This directory contains demo scripts showcasing the privacy proxy's deployment and RBAC features with UUPS upgradeable contracts.

## Demo Scripts Overview

| Script | Description | Requires Proxy |
|--------|-------------|----------------|
| `demo-anvil-direct.sh` | Baseline deployment directly to Anvil | No |
| `demo-privacy-proxy.sh` | Full workflow through privacy proxy with RBAC | Yes |
| `demo-defi-deployment.sh` | CREATE3 deterministic DeFi deployment | Yes |
| `demo-upgrade.sh` | UUPS proxy upgrade demonstration | Yes |
| `demo-proxy-upgrade.sh` | Proxy upgrade with preregistered addresses | Yes |
| `demo-blocked-deployment.sh` | Demonstrates RBAC blocking unauthorized deploys | Yes |

## Prerequisites

1. **Foundry** - Install from https://getfoundry.sh
2. **jq** - For JSON parsing
3. **curl** - For API calls
4. **Anvil** - Running on localhost:8545

For proxy scripts, also need:
- **Privacy Proxy** running on localhost:8080
- An organization configured in the proxy

## Quick Start

```bash
# Run the baseline demo (no proxy needed, just Anvil)
anvil &
./demo-anvil-direct.sh

# Run proxy demos (requires privacy proxy running)
./demo-privacy-proxy.sh
```

## Script Details

### demo-anvil-direct.sh (Baseline)

**Purpose:** Demonstrates direct deployment to Anvil without RBAC - serves as a baseline to verify contract logic works correctly.

**What it does:**
1. Compiles DemoToken, LiquidityPool, and SwapRouter contracts
2. Deploys implementation contracts using regular CREATE opcode
3. Predicts proxy addresses using nonce-based address computation
4. Deploys UUPS proxies with initialization data
5. Verifies circular references (Token ↔ Pool ↔ Router)
6. Tests contract interactions:
   - Mints 1000 DEMO tokens
   - Approves and adds liquidity to pool
   - Executes a swap through the router

**Key Points:**
- Uses nonce-based address prediction to resolve circular dependencies
- No RBAC or permissions - anyone with ETH can deploy
- Demonstrates that contracts work correctly before adding proxy layer

---

### demo-privacy-proxy.sh (Full RBAC Workflow)

**Purpose:** Demonstrates the complete deployment flow through the privacy proxy with RBAC enforcement.

**What it does:**
1. Authenticates user via mock token
2. Sets up organization and user permissions
3. Deploys/configures CREATE3 factory
4. Preregisters contract addresses
5. Deploys contracts through proxy to preregistered addresses
6. Verifies deployment and tests interactions

**Security Features:**
- All transactions go through RBAC-enforced proxy
- Addresses must be preregistered before deployment
- User must have KYC and deploy permissions

---

### demo-defi-deployment.sh (CREATE3 Deterministic)

**Purpose:** Showcases CREATE3 deterministic deployment for DeFi contracts with circular dependencies.

**What it does:**
1. Computes addresses deterministically using CREATE3 (factory + salt)
2. Preregisters all addresses before any deployment
3. Deploys Token, Pool, Router with known addresses
4. Demonstrates that addresses are independent of bytecode

**Key Benefit:** Same addresses across all EVM chains when using same factory and salts.

---

### demo-upgrade.sh (UUPS Upgrade Flow)

**Purpose:** Demonstrates upgrading UUPS proxies from V1 to V2 implementations.

**What it does:**
1. Deploys V1 implementations (Token, Pool, Router)
2. Deploys proxies pointing to V1
3. Interacts with V1 (version returns "1.0.0")
4. Deploys V2 implementations with new features
5. Upgrades proxies to V2
6. Verifies state preservation and new features

**V2 Features:**
- DemoTokenV2: `burn()` function
- LiquidityPoolV2: Configurable fees
- SwapRouterV2: Deadline protection

---

### demo-proxy-upgrade.sh (Preregistered Upgrade)

**Purpose:** Shows the admin/deployer separation for contract upgrades.

**Security Model:**
- **Org Admin**: Preregisters addresses (controls WHERE)
- **Deployer**: Deploys to preregistered addresses only

---

### demo-blocked-deployment.sh (RBAC Enforcement)

**Purpose:** Demonstrates that the RBAC system blocks unauthorized deployments.

**What it shows:**
- Deployments to non-preregistered addresses are blocked
- Users without proper permissions cannot deploy
- Cross-org isolation is enforced

## Environment Variables

```bash
# Optional (defaults shown)
export ADMIN_API_URL="http://localhost:8080/api"
export PROXY_RPC_URL="http://localhost:8080"
export ANVIL_URL="http://localhost:8545"

# Deployer key - defaults to Anvil's first account
export PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
```

## Contract Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        DemoToken Proxy                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ ERC1967 Storage: implementation → DemoToken V1/V2          │  │
│  │ State: balances, allowances, owner, pool reference         │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼ delegatecall
┌──────────────────────────────────────────────────────────────────┐
│  DemoToken Implementation (V1 or V2)                              │
│  - ERC20 functionality                                            │
│  - mint() (owner only)                                            │
│  - pool reference for circular dependency                         │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                      LiquidityPool Proxy                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ State: token reference, reserves, liquidity shares         │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼ delegatecall
┌──────────────────────────────────────────────────────────────────┐
│  LiquidityPool Implementation                                     │
│  - addLiquidity() / removeLiquidity()                             │
│  - swap() functionality                                           │
│  - V2 adds: setFee(), configurable fees                           │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                       SwapRouter Proxy                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ State: pool reference, token reference                     │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼ delegatecall
┌──────────────────────────────────────────────────────────────────┐
│  SwapRouter Implementation                                        │
│  - swapTokensForETH() / swapETHForTokens()                        │
│  - V2 adds: deadline protection                                   │
└──────────────────────────────────────────────────────────────────┘
```

## Circular Dependency Resolution

The contracts have circular dependencies:
- Token needs Pool address (for authorized minting)
- Pool needs Token address (to transfer tokens)
- Router needs both Pool and Token addresses

**Solution with CREATE3:**
1. Compute all addresses deterministically BEFORE deployment
2. Pass addresses during initialization
3. Deploy in any order - addresses are already known

**Solution with CREATE (nonce-based):**
1. Predict addresses using deployer + nonce
2. Deploy proxies in predicted order
3. Initialize with predicted addresses

## Troubleshooting

### "Could not connect to Anvil"
```bash
# Start Anvil
anvil
```

### "No CREATE3 factory configured" / "Factory has no code"
The scripts now auto-deploy the factory using the dev endpoint. If issues persist:
```bash
curl -X POST "http://localhost:8080/api/v1/dev/create3-factory"
```

### "target address is not preregistered"
Addresses must be preregistered before deployment. The demo scripts handle this automatically.

### "missing required deploy claim"
Ensure the user has deploy permissions in their group.

### RBAC blocks upgrade calls
The `upgradeToAndCall()` function may be blocked by RBAC if the V2 implementation address isn't properly registered. Use `demo-anvil-direct.sh` to verify contract logic works.
