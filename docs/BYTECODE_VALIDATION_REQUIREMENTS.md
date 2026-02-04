# Bytecode Validation Requirements & Security Analysis

## Overview

This document captures the security requirements and findings for bytecode validation in the privacy proxy's RBAC system. The goal is to sandbox deployed contracts so they can only interact with org-owned addresses.

**IMPORTANT: This is for PRIVATE chains, not public chains.**

On a private chain:
- There are no external services (Chainlink, Uniswap, etc.)
- ALL contracts are deployed through our RBAC system
- ALL addresses are owned by some organization
- Cross-org interaction is a matter of permissions, not external dependencies

## Core Security Model

### The Challenge

The privacy proxy cannot sandbox contracts at **execution time** because it doesn't run the EVM. Instead, sandboxing must happen at **deployment time** through bytecode analysis.

Once a contract is deployed on-chain, it can execute any code in its bytecode without going through the proxy.

### Security Goals

1. **Cross-org isolation**: Org A's contracts cannot interact with Org B's contracts
2. **Predictable behavior**: Deployed contracts can only call pre-approved addresses
3. **Upgrade safety**: Proxy upgrades can only point to org-owned implementations

## Call Types Analysis

### CALL vs DELEGATECALL

| Type | What it does | Security concern |
|------|--------------|------------------|
| **CALL** | Executes target's code in target's context | Can interact with ANY address, including other orgs' contracts |
| **DELEGATECALL** | Executes target's code in caller's context | Target must be deployed (validated), but could use other org's code |

### Dynamic vs Static Calls

| Type | Address source | Can be validated at deployment? |
|------|----------------|--------------------------------|
| **Static** | Hardcoded in bytecode (PUSH20) | Yes - we know exactly what address will be called |
| **Dynamic** | From storage (SLOAD), calldata (CALLDATALOAD), or memory (MLOAD) | No - address determined at runtime |

### Address Declaration Types in Solidity

| Declaration | Where Stored | Access Pattern | Bytecode Analysis | Configurable? |
|-------------|--------------|----------------|-------------------|---------------|
| `address constant X = 0x...` | In bytecode | PUSH20 | **Static ✓** | No - compile time only |
| `address immutable x` | In bytecode (set at deploy) | PUSH20 | **Static ✓** | Yes - via constructor |
| `address public x` | In storage | SLOAD | **Dynamic ✗** | Yes - but BLOCKED |

**Key insight**: `immutable` variables offer the best of both worlds:
- Set at deployment time (flexible)
- Embedded in runtime bytecode (static, validatable)
- No SLOAD at runtime (gas efficient)

```solidity
// RECOMMENDED: immutable with constructor injection
address immutable oracle;

constructor(address _oracle) {
    oracle = _oracle;  // Value embedded in runtime bytecode
}

function useOracle() {
    oracle.call(...);  // Compiles to PUSH20, NOT SLOAD
}
```

## UUPS Upgradeable Pattern Analysis

### How UUPS Works

```
1. User calls: proxy.upgradeToAndCall(newImplementation, data)
2. Proxy DELEGATECALLs to current implementation
3. Implementation's upgradeToAndCall() runs:
   - Stores newImplementation in ERC1967 slot
   - DELEGATECALLs to newImplementation with data
```

### Why UUPS Implementations Have Dynamic DELEGATECALL

The upgrade mechanism uses `Address.functionDelegateCall(newImplementation, data)` where `newImplementation` comes from function parameters (CALLDATALOAD).

This is detected as "dynamic DELEGATECALL" by bytecode analysis.

### Security Chain for UUPS

```
To upgrade to MaliciousImpl:
    ↓
MaliciousImpl must be DEPLOYED first
    ↓
Deployment goes through bytecode validation
    ↓
If MaliciousImpl has dangerous patterns → BLOCKED
    ↓
Therefore: upgrade targets are always validated
```

### Cross-Org DELEGATECALL Concern

**Problem**: If Org B DELEGATECALLs to Org A's contract:
1. Org A's code runs in Org B's context
2. If Org A's code has static CALLs to Org A's other contracts
3. Those CALLs execute on-chain, bypassing the proxy
4. Org B effectively interacts with Org A's contracts

**Solution**: DELEGATECALL targets must be owned by the **SAME org**, verified at runtime through upgrade interception.

## Validation Rules

### At Deployment Time

The behavior of deployment validation depends on whether **runtime tracing** is enabled via `ENABLE_RUNTIME_TRACING=true`:

#### Without Runtime Tracing (default)

| Pattern | Action | Reason |
|---------|--------|--------|
| Dynamic CALL | **BLOCK** | Can call any address at runtime |
| Dynamic STATICCALL | **BLOCK** | Can read from any address at runtime |
| Dynamic DELEGATECALL | **ALLOW** (with caveats) | Target must be deployed (validated), runtime interception ensures same-org |
| Static CALL to non-org address | **BLOCK** | Cross-org interaction (unless cross-org permission configured) |
| Static CALL to org-owned address | **ALLOW** | Safe, predictable |
| CREATE/CREATE2 | **BLOCK** | Bypasses address preregistration |

#### With Runtime Tracing Enabled

When `ENABLE_RUNTIME_TRACING=true`, dynamic calls are **ALLOWED** at deployment time because they will be validated at execution time via `debug_traceCall`. This enables compatibility with more contracts (e.g., OpenZeppelin upgradeable contracts) while maintaining security through runtime validation.

| Pattern | Action | Reason |
|---------|--------|--------|
| Dynamic CALL | **ALLOW** | Validated at runtime via trace |
| Dynamic STATICCALL | **ALLOW** | Validated at runtime via trace |
| Dynamic DELEGATECALL | **ALLOW** | Validated at runtime via trace |
| Static CALL to non-org address | **BLOCK** | Cross-org interaction (unless cross-org permission configured) |
| Static CALL to org-owned address | **ALLOW** | Safe, predictable |
| CREATE/CREATE2 | **BLOCK** | Bypasses address preregistration |

See `RUNTIME_VALIDATION_ANALYSIS.md` for detailed analysis of the runtime tracing approach.

### Constructor Argument Validation

For contracts using `immutable` addresses via constructor injection, we must validate the addresses at deployment time:

**Validation Flow:**
1. Extract constructor arguments from deployment transaction (init code + args)
2. Parse ABI to identify which arguments are addresses
3. For each address argument:
   - Verify it's preregistered to the deploying org, OR
   - Verify cross-org permission is configured
4. Block deployment if any address fails validation

**Implementation Requirements:**
- Need contract ABI (from compilation artifacts or provided by deployer)
- ABI decoding of constructor arguments
- Cross-reference with preregistered addresses database

**Security Note:** This is critical - without constructor argument validation, a deployer could pass any address to an `immutable` variable and bypass cross-org isolation.

### At Runtime (Upgrade Interception)

When detecting upgrade function calls (`upgradeToAndCall`, `upgradeTo`, etc.):
1. Extract new implementation address from calldata
2. Verify new implementation is owned by **THIS org**
3. Reject if cross-org or not preregistered

### Trusted Contract Patterns

These patterns are allowed despite having dynamic DELEGATECALLs:

| Pattern | Detection | Validation |
|---------|-----------|------------|
| ERC1967 Proxy | Storage slot signatures | Initial impl must be org-owned |
| UUPS Implementation | ERC1967 + upgrade functions | Upgrade targets validated at runtime |
| CREATE3 Factory | Bytecode hash whitelist | Only whitelisted factory bytecode |

## Open Questions

### Multiple DELEGATECALLs in UUPS

A contract inheriting from UUPSUpgradeable could have:
- The upgrade DELEGATECALL (expected, intercepted)
- Additional DELEGATECALLs for other purposes (libraries, etc.)

**Question**: How do we distinguish safe upgrade DELEGATECALLs from potentially unsafe ones?

### Dynamic CALLs from Storage - BLOCKED

If a contract has an address in storage and calls it:

```solidity
address public oracle;                              // Address in storage slot
function setOracle(address _o) { oracle = _o; }     // Setter (doesn't matter)
function useOracle() { oracle.call(...); }          // CALL with address from SLOAD
```

**This contract is BLOCKED at deployment because:**
1. We analyze bytecode and find `CALL` opcode
2. We look backwards and find `SLOAD` (address loaded from storage)
3. This is detected as **dynamic CALL** → deployment rejected

**The setter is irrelevant** - we block based on the CALL pattern, not whether a setter exists.

**Why we block this:**
- At deployment, we don't know what address will be called at runtime
- Even on a private chain, this could enable cross-org calls without permission
- We can't validate what we can't see at deployment time

**What developers must do instead:**
```solidity
// BLOCKED - address from storage (SLOAD)
address public oracle;
function useOracle() { oracle.call(...); }

// ALLOWED - address hardcoded as constant
address constant ORACLE = 0x1234567890123456789012345678901234567890;
function useOracle() { ORACLE.call(...); }

// RECOMMENDED - address injected via constructor as immutable
address immutable oracle;
constructor(address _oracle) { oracle = _oracle; }
function useOracle() { oracle.call(...); }  // Still PUSH20, not SLOAD!
```

**The `immutable` pattern is preferred** because:
- Address can be determined at deployment time (not compile time)
- Still results in static bytecode (PUSH20)
- Enables preregistration workflow: preregister address → deploy dependency → deploy with constructor arg

If a developer needs to change their oracle later, they must redeploy their contract (to a new preregistered address or via UUPS upgrade).

### Compatibility with Existing Contracts (Private Chain Context)

For companies bringing existing contracts to the private chain:

1. **Redeploy to the private chain** - all deployments go through RBAC validation
2. **Preregister all deployment addresses** (via CREATE3)
3. **Ensure all call targets are hardcoded** as constants in bytecode
4. **Configure cross-org permissions** if calling another org's contracts

**Contracts that ARE compatible (deploy as-is):**
- Contracts with `immutable` addresses set via constructor
- Contracts with static/hardcoded call targets (`address constant X = 0x...`)
- UUPS/ERC1967 upgradeable proxies (upgrade targets validated at runtime)
- Contracts with no external calls

**Contracts that are BLOCKED (need modification):**
- Contracts with dynamic call targets from storage (`address public x; x.call(...)`)
- Contracts using registry patterns (lookup address at runtime, then call)
- Contracts with configurable/updatable call targets via setters

**To make blocked contracts compatible:**
- Change `address public target` to `address immutable target` with constructor injection
- Remove setter functions for call targets (they're useless anyway since calls are blocked)
- If you need to change targets later, redeploy the contract or use UUPS proxy pattern

## Expected Developer Workflow (Private Chain)

### For New Contracts

1. **Pre-register all addresses** you will deploy to (via CREATE3)
2. **Identify all addresses** you will call (must be deployed on this chain by some org)
3. **Use `immutable` for call target addresses** (injected via constructor):
   ```solidity
   // RECOMMENDED: immutable with constructor injection
   address immutable oracle;
   constructor(address _oracle) { oracle = _oracle; }
   function useOracle() { oracle.call(...); }

   // ALSO ALLOWED: constant (if address known at compile time)
   address constant ORACLE = 0x1234567890123456789012345678901234567890;
   function useOracle() { ORACLE.call(...); }

   // BLOCKED: address in storage (dynamic call from SLOAD)
   address public oracle;
   function useOracle() { oracle.call(...); }
   ```
4. **Deploy dependencies first**, then deploy contracts that call them (passing addresses to constructors)
5. **Use UUPS/ERC1967** for upgradeability (upgrades validated at runtime)

### Constructor Argument Validation

When deploying a contract with `immutable` address variables:

1. Privacy proxy extracts constructor arguments from deployment transaction
2. Identifies address arguments
3. Verifies each address is either:
   - Preregistered to the deploying org, OR
   - Has cross-org permission configured
4. Deployment proceeds only if all addresses are validated

This enables flexible deployment while maintaining security.

### Changing Call Targets

If you need to change what address your contract calls:
- You **cannot** update an address in storage and call it (blocked)
- You must **redeploy** your contract with the new hardcoded address
- Deploy to a new preregistered address

### Cross-Org Calls

If Org A's contract needs to call Org B's contract:
1. Org B deploys their contract to a preregistered address
2. Org A hardcodes Org B's address as a constant in their contract
3. Admin configures cross-org permissions (Org A allowed to call Org B's address)
4. At deployment, we verify Org A's static call to Org B's address is permitted
5. Org A deploys their contract

## Adoption Analysis

### Challenges for Developers

#### 1. No Runtime-Configurable Call Targets
Call targets cannot be changed after deployment via setters:

```solidity
// Traditional approach (BLOCKED) - storage + setter
address public oracle;
function setOracle(address _o) { oracle = _o; }
function getPrice() { oracle.call(...); }

// Privacy proxy compatible (ALLOWED) - immutable via constructor
address immutable oracle;
constructor(address _oracle) { oracle = _oracle; }
function getPrice() { oracle.call(...); }
```

**Impact**: Addresses must be known at deployment time. Use UUPS proxies if you need to change targets later.

#### 2. Deployment Order Dependencies
Contracts must be deployed in dependency order:
1. Preregister all addresses via CREATE3
2. Deploy leaf contracts (no external calls) first
3. Deploy dependent contracts, passing dependency addresses to constructors

**Impact**: Multi-contract systems require orchestration, but addresses can be precomputed (CREATE3) so contracts can be compiled in parallel.

#### 3. Testing Workflow Changes
Local testing becomes more complex:
- Mock contracts need stable addresses (use CREATE3 in tests too)
- Cannot easily swap implementations for testing
- Test fixtures must match production deployment order

#### 4. No Post-Deployment Configuration of Call Targets
Traditional "deploy then configure" patterns for call targets don't work:

```solidity
// Traditional (BLOCKED) - configure after deployment
contract MyContract {
    address public dependency;
    function setDependency(address _d) { dependency = _d; }
    function useDependency() { dependency.call(...); }
}

// Privacy proxy compatible - configure at deployment
contract MyContract {
    address immutable dependency;
    constructor(address _d) { dependency = _d; }
    function useDependency() { dependency.call(...); }
}
```

**Impact**: Call target "wiring" happens at deployment time via constructors, not post-deployment via setters. Other configuration (non-address state) can still use traditional patterns.

#### 5. Cascade Redeployments
If Contract A calls Contract B, and B needs to change:
1. Deploy new Contract B to new address
2. Recompile Contract A with new B address
3. Redeploy Contract A to new address
4. Update anything that calls A...

**Impact**: Changes cascade through the dependency graph. Use UUPS proxies to mitigate.

### Incompatible Patterns

These common Solidity patterns are **fundamentally incompatible**:

| Pattern | Why It's Blocked | Alternative |
|---------|------------------|-------------|
| **Diamond (EIP-2535)** | Dynamic routing to facets via storage | Use multiple UUPS proxies |
| **Plugin Systems** | Runtime-registered handlers | Pre-deploy all plugins, hardcode addresses |
| **Registry Patterns** | Lookup address then call | Hardcode addresses, redeploy for changes |
| **Configurable Oracles** | Swappable data sources | Hardcode oracle, use UUPS for upgrades |
| **Factory-Created Contracts** | CREATE/CREATE2 inside contracts | Use external CREATE3 factory |
| **Callback Registries** | Store and call arbitrary addresses | Whitelist callbacks at compile time |

### Adoption Barriers

| Barrier | Severity | Mitigation |
|---------|----------|------------|
| Existing contracts need modification | Medium | Change `public` → `immutable`, add constructor params |
| Multi-contract deployment complexity | Low | CREATE3 precomputes addresses; deploy in dependency order |
| Testing workflow changes | Low | Same patterns work locally with CREATE3 |
| No runtime call target configuration | Medium | Use UUPS proxies for upgradeable targets |
| Cascade redeployments | Medium | UUPS proxies for stable interfaces |
| Diamond pattern incompatibility | High | Alternative architecture patterns |

**Note**: The `immutable` pattern significantly reduces adoption friction. Most contracts only need to change `address public x` to `address immutable x` and add constructor parameters.

### What Would Help Adoption

1. **Tooling**
   - Deployment orchestrator that handles dependency ordering
   - CREATE3 address calculator/predictor
   - Contract analyzer that warns about incompatible patterns before deployment

2. **Patterns Library**
   - Privacy-proxy-compatible versions of common patterns
   - Example implementations of multi-contract systems
   - Migration guides from blocked patterns

3. **Documentation**
   - Clear compatibility checklist for existing contracts
   - Decision tree: "Can my contract work with privacy proxy?"
   - Worked examples of common use cases

4. **Development Experience**
   - Local testing tools that simulate CREATE3 + validation
   - Foundry/Hardhat plugins for address preregistration
   - CI integration for bytecode validation

## Implementation Status

- [x] Static call target extraction
- [x] Dynamic call detection (SLOAD, CALLDATALOAD, MLOAD)
- [x] CREATE/CREATE2 blocking
- [x] Proxy pattern detection (ERC1967, UUPS, Beacon)
- [x] Upgrade interception
- [x] CREATE3 factory whitelisting
- [x] Constructor argument validation (extract addresses, verify preregistration)
- [ ] UUPS implementation pattern allowlisting
- [ ] Storage slot modification detection
- [ ] Cross-org DELEGATECALL validation at deployment

## Constructor ABI Workflow

Constructor argument validation is critical for contracts using `immutable` address variables.
The ABI is required to decode and validate addresses in constructor arguments.

### Providing Constructor ABI

The ABI can be provided in two ways:

1. **At preregistration time** (recommended):
   ```bash
   POST /admin/orgs/:org_id/addresses/preregister
   {
     "factory": "0x...",
     "salt_prefix": "0x...",
     "count": 1,
     "constructor_abi": "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"oracle\",\"type\":\"address\"}]}]"
   }
   ```

2. **After preregistration** (update):
   ```bash
   PUT /admin/orgs/:org_id/addresses/preregistered/:address/abi
   {
     "constructor_abi": "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"oracle\",\"type\":\"address\"}]}]"
   }
   ```

### Validation Rules

| Scenario | ABI | Result |
|----------|-----|--------|
| No constructor args (ABI says no inputs) | Required | Allowed |
| Constructor args exist | Required | Validated |
| No ABI provided | - | **Rejected** |
| Address in constructor args not allowed for org | Required | **Rejected** |
| All addresses in constructor args allowed | Required | Allowed |
| Dynamic types (address[], string, bytes) in ABI | Required | **Rejected** |

### Supported Constructor Types

- `address` - Single address
- `address[N]` - Fixed-size address array
- `uint*`, `int*`, `bool`, `bytes32` - Non-address fixed types (no validation needed)
- Tuples/structs with fixed-size elements

### Unsupported Constructor Types

Dynamic types cannot be validated statically and are rejected:
- `address[]` - Dynamic address array
- `bytes` - Dynamic bytes
- `string` - Dynamic string
- `T[]` - Any dynamic array

## References

- `internal/rbac/deploy_validator.go` - Deployment validation with ABI support
- `internal/rbac/upgrade_validator.go` - Upgrade interception
- `internal/evm/bytecode/calls.go` - Call target extraction
- `internal/evm/bytecode/proxy.go` - Proxy pattern detection
- `internal/evm/bytecode/constructor.go` - Constructor argument extraction
- `internal/evm/create3/factory.go` - CREATE3 factory whitelist
