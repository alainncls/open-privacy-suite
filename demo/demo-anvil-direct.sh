#!/bin/bash

# =============================================================================
# Privacy Proxy - Direct Anvil Deployment Demo (Baseline)
# =============================================================================
# This script demonstrates deployment directly to Anvil without privacy proxy.
# Used as a baseline for comparison with the privacy proxy workflow.
#
# Steps:
# 1. Start Anvil (or use existing instance)
# 2. Deploy DemoToken, LiquidityPool, SwapRouter contracts
# 3. Interact with them (mint tokens, add liquidity, swap)
# 4. Show success
# =============================================================================

set -e

# Colors for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Box drawing characters
BOX_TL="╔"
BOX_TR="╗"
BOX_BL="╚"
BOX_BR="╝"
BOX_H="═"
BOX_V="║"

# Print functions
print_header() {
    local text="$1"
    local width=70
    local padding=$(( (width - ${#text} - 2) / 2 ))
    echo ""
    echo -e "${CYAN}${BOX_TL}$(printf '%*s' $width | tr ' ' "$BOX_H")${BOX_TR}${NC}"
    echo -e "${CYAN}${BOX_V}${NC}$(printf '%*s' $padding)${BOLD}${WHITE}$text${NC}$(printf '%*s' $((width - padding - ${#text})))${CYAN}${BOX_V}${NC}"
    echo -e "${CYAN}${BOX_BL}$(printf '%*s' $width | tr ' ' "$BOX_H")${BOX_BR}${NC}"
    echo ""
}

print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}▶${NC} ${BOLD}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_substep() {
    echo -e "  ${CYAN}→${NC} $1"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${MAGENTA}ℹ${NC} $1"
}

print_value() {
    echo -e "  ${WHITE}│${NC} $1: ${GREEN}$2${NC}"
}

print_json() {
    echo -e "${WHITE}$1${NC}" | jq '.' 2>/dev/null || echo -e "${WHITE}$1${NC}"
}

print_contract_call() {
    local contract="$1"
    local method="$2"
    local result="$3"
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC} Contract: ${YELLOW}$contract${NC}"
    echo -e "  ${CYAN}│${NC} Method:   ${YELLOW}$method${NC}"
    echo -e "  ${CYAN}│${NC} Result:   ${GREEN}$result${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
}

# =============================================================================
# Configuration
# =============================================================================

print_header "Direct Anvil Deployment Demo (Baseline)"

print_step "Step 1: Checking Configuration"

# Environment variables with defaults
: "${ANVIL_URL:=http://localhost:8545}"
: "${PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

print_value "Anvil URL" "$ANVIL_URL"
print_value "Private Key" "${PRIVATE_KEY:0:10}..."

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Check Anvil is running
print_substep "Checking Anvil connection..."
CHAIN_ID=$(cast chain-id --rpc-url "$ANVIL_URL" 2>/dev/null || echo "")
if [ -z "$CHAIN_ID" ]; then
    print_error "Could not connect to Anvil at $ANVIL_URL"
    echo ""
    echo -e "  ${WHITE}Start Anvil with:${NC}"
    echo -e "  ${GREEN}anvil${NC}"
    echo ""
    exit 1
fi
print_success "Connected to Anvil (chainId: $CHAIN_ID)"

# Check deployer balance
BALANCE=$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Deployer Balance" "$BALANCE wei"

# =============================================================================
# Step 2: Build Contracts
# =============================================================================

print_step "Step 2: Building Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_SRC_DIR="$SCRIPT_DIR/contracts"

# Create a temp directory for building (keeps repo clean)
BUILD_DIR=$(mktemp -d)
print_substep "Using temp build directory: $BUILD_DIR"

# Copy contracts to temp dir
cp -r "$CONTRACTS_SRC_DIR"/* "$BUILD_DIR/"
cd "$BUILD_DIR"

# Cleanup on exit
cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# Initialize git repo (required for forge install)
print_substep "Initializing git repository for forge..."
git init --quiet
git config user.email "demo@example.com"
git config user.name "Demo"
git add -A
git commit -m "Initial" --quiet

# Install dependencies using git clone directly
print_substep "Installing OpenZeppelin contracts..."
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable 2>/dev/null || {
    print_error "Failed to clone openzeppelin-contracts-upgradeable"
    exit 1
}
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts 2>/dev/null || {
    print_error "Failed to clone openzeppelin-contracts"
    exit 1
}
print_success "OpenZeppelin contracts installed"

print_substep "Compiling contracts..."
forge build --quiet

print_success "Contracts compiled successfully"

# Get bytecode for all contracts
DEMOTOKEN_BYTECODE=$(forge inspect DemoToken bytecode)
LIQUIDITYPOOL_BYTECODE=$(forge inspect LiquidityPool bytecode)
SWAPROUTER_BYTECODE=$(forge inspect SwapRouter bytecode)

print_value "DemoToken bytecode size" "$(echo -n "$DEMOTOKEN_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "LiquidityPool bytecode size" "$(echo -n "$LIQUIDITYPOOL_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "SwapRouter bytecode size" "$(echo -n "$SWAPROUTER_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 3: Deploy Contracts Using CREATE2 (for address prediction)
# =============================================================================

print_step "Step 3: Deploying Contracts (Direct to Anvil)"

print_info "Note: Direct deployment uses regular CREATE opcode"
print_info "      Addresses are determined by nonce, not deterministically"
echo ""

# Deploy DemoToken Implementation
print_substep "Deploying DemoToken implementation..."
DEMOTOKEN_IMPL_RESULT=$(forge create src/token/DemoToken.sol:DemoToken \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
DEMOTOKEN_IMPL=$(echo "$DEMOTOKEN_IMPL_RESULT" | jq -r '.deployedTo')
print_success "DemoToken impl: $DEMOTOKEN_IMPL"

# Deploy LiquidityPool Implementation
print_substep "Deploying LiquidityPool implementation..."
LIQUIDITYPOOL_IMPL_RESULT=$(forge create src/pool/LiquidityPool.sol:LiquidityPool \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
LIQUIDITYPOOL_IMPL=$(echo "$LIQUIDITYPOOL_IMPL_RESULT" | jq -r '.deployedTo')
print_success "LiquidityPool impl: $LIQUIDITYPOOL_IMPL"

# Deploy SwapRouter Implementation
print_substep "Deploying SwapRouter implementation..."
SWAPROUTER_IMPL_RESULT=$(forge create src/router/SwapRouter.sol:SwapRouter \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
SWAPROUTER_IMPL=$(echo "$SWAPROUTER_IMPL_RESULT" | jq -r '.deployedTo')
print_success "SwapRouter impl: $SWAPROUTER_IMPL"

# =============================================================================
# Step 4: Deploy Proxies and Initialize
# =============================================================================

print_step "Step 4: Deploying Proxies"

# Create proxy bytecode helper
cat > "$BUILD_DIR/src/DeployProxy.sol" << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployableProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}
}
EOF

forge build --quiet

# For direct deployment, we can't pre-compute addresses easily
# So we deploy in order: Pool -> Token -> Router
# But Token needs Pool address and Pool needs Token address (circular!)
# In direct deployment, we work around this by:
# 1. Deploy proxies first without initialization
# 2. Then initialize them with each other's addresses

# Deploy all proxies first (with empty init data)
print_substep "Deploying DemoToken proxy..."
TOKEN_INIT_DATA="0x" # Empty - will initialize later
TOKEN_PROXY_RESULT=$(forge create src/DeployProxy.sol:DeployableProxy \
    --constructor-args "$DEMOTOKEN_IMPL" "$TOKEN_INIT_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
TOKEN_PROXY=$(echo "$TOKEN_PROXY_RESULT" | jq -r '.deployedTo')
print_success "DemoToken proxy: $TOKEN_PROXY"

print_substep "Deploying LiquidityPool proxy..."
POOL_INIT_DATA="0x"
POOL_PROXY_RESULT=$(forge create src/DeployProxy.sol:DeployableProxy \
    --constructor-args "$LIQUIDITYPOOL_IMPL" "$POOL_INIT_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
POOL_PROXY=$(echo "$POOL_PROXY_RESULT" | jq -r '.deployedTo')
print_success "LiquidityPool proxy: $POOL_PROXY"

print_substep "Deploying SwapRouter proxy..."
ROUTER_INIT_DATA="0x"
ROUTER_PROXY_RESULT=$(forge create src/DeployProxy.sol:DeployableProxy \
    --constructor-args "$SWAPROUTER_IMPL" "$ROUTER_INIT_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
ROUTER_PROXY=$(echo "$ROUTER_PROXY_RESULT" | jq -r '.deployedTo')
print_success "SwapRouter proxy: $ROUTER_PROXY"

# =============================================================================
# Step 5: Initialize Contracts
# =============================================================================

print_step "Step 5: Initializing Contracts"

# Initialize DemoToken with pool address
print_substep "Initializing DemoToken..."
INIT_TOKEN_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY")
cast send "$TOKEN_PROXY" "$INIT_TOKEN_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "DemoToken initialized (owner: $DEPLOYER_ADDRESS, pool: $POOL_PROXY)"

# Initialize LiquidityPool with token address
print_substep "Initializing LiquidityPool..."
INIT_POOL_DATA=$(cast calldata "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_PROXY")
cast send "$POOL_PROXY" "$INIT_POOL_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "LiquidityPool initialized (owner: $DEPLOYER_ADDRESS, token: $TOKEN_PROXY)"

# Initialize SwapRouter with pool and token addresses
print_substep "Initializing SwapRouter..."
INIT_ROUTER_DATA=$(cast calldata "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_PROXY" "$TOKEN_PROXY")
cast send "$ROUTER_PROXY" "$INIT_ROUTER_DATA" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "SwapRouter initialized (owner: $DEPLOYER_ADDRESS, pool: $POOL_PROXY, token: $TOKEN_PROXY)"

# =============================================================================
# Step 6: Verify Deployment
# =============================================================================

print_step "Step 6: Verifying Deployment"

# Check versions
print_substep "Checking contract versions..."
TOKEN_VERSION=$(cast call "$TOKEN_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_VERSION=$(cast call "$POOL_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_VERSION=$(cast call "$ROUTER_PROXY" "version()(string)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_contract_call "$TOKEN_PROXY" "version()" "$TOKEN_VERSION"
print_contract_call "$POOL_PROXY" "version()" "$POOL_VERSION"
print_contract_call "$ROUTER_PROXY" "version()" "$ROUTER_VERSION"

# Check cross-references
print_substep "Verifying cross-references..."
TOKEN_POOL=$(cast call "$TOKEN_PROXY" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
POOL_TOKEN=$(cast call "$POOL_PROXY" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_POOL=$(cast call "$ROUTER_PROXY" "pool()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ROUTER_TOKEN=$(cast call "$ROUTER_PROXY" "token()(address)" --rpc-url "$ANVIL_URL" 2>/dev/null)

print_value "Token.pool" "$TOKEN_POOL"
print_value "Pool.token" "$POOL_TOKEN"
print_value "Router.pool" "$ROUTER_POOL"
print_value "Router.token" "$ROUTER_TOKEN"

# =============================================================================
# Step 7: Interact with Contracts
# =============================================================================

print_step "Step 7: Interacting with Contracts"

# Mint some tokens
MINT_AMOUNT="1000000000000000000000" # 1000 tokens (18 decimals)
print_substep "Minting 1000 DEMO tokens..."
cast send "$TOKEN_PROXY" "mint(address,uint256)" "$DEPLOYER_ADDRESS" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Minted 1000 DEMO tokens"

# Check balance
TOKEN_BALANCE=$(cast call "$TOKEN_PROXY" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Balance" "$TOKEN_BALANCE (wei)"

# Approve pool to spend tokens
print_substep "Approving pool to spend tokens..."
cast send "$TOKEN_PROXY" "approve(address,uint256)" "$POOL_PROXY" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Pool approved to spend tokens"

# Add liquidity
LIQUIDITY_TOKENS="500000000000000000000" # 500 tokens
LIQUIDITY_ETH="1000000000000000000" # 1 ETH
print_substep "Adding liquidity (500 DEMO + 1 ETH)..."
cast send "$POOL_PROXY" "addLiquidity(uint256)" "$LIQUIDITY_TOKENS" \
    --value "$LIQUIDITY_ETH" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Liquidity added"

# Check pool reserves
TOKEN_RESERVE=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve" "$TOKEN_RESERVE"
print_value "ETH Reserve" "$ETH_RESERVE"

# Approve router to spend tokens
print_substep "Approving router to spend tokens..."
cast send "$TOKEN_PROXY" "approve(address,uint256)" "$ROUTER_PROXY" "$MINT_AMOUNT" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json > /dev/null 2>&1
print_success "Router approved to spend tokens"

# Execute a swap through the router
SWAP_AMOUNT="100000000000000000000" # 100 tokens
print_substep "Swapping 100 DEMO for ETH through router..."
SWAP_RESULT=$(cast send "$ROUTER_PROXY" "swapExactTokensForEth(uint256,uint256)" "$SWAP_AMOUNT" "0" \
    --rpc-url "$ANVIL_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>/dev/null)
SWAP_TX=$(echo "$SWAP_RESULT" | jq -r '.transactionHash')
print_success "Swap executed"
print_value "Transaction" "$SWAP_TX"

# Check new reserves
TOKEN_RESERVE_AFTER=$(cast call "$POOL_PROXY" "tokenReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
ETH_RESERVE_AFTER=$(cast call "$POOL_PROXY" "ethReserve()(uint256)" --rpc-url "$ANVIL_URL" 2>/dev/null)
print_value "Token Reserve After" "$TOKEN_RESERVE_AFTER"
print_value "ETH Reserve After" "$ETH_RESERVE_AFTER"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}Deployed Contracts (Direct to Anvil):${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken Proxy:${NC}      $TOKEN_PROXY"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool Proxy:${NC}  $POOL_PROXY"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter Proxy:${NC}     $ROUTER_PROXY"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}DemoToken Impl:${NC}       $DEMOTOKEN_IMPL"
echo -e "${CYAN}│${NC}  ${YELLOW}LiquidityPool Impl:${NC}   $LIQUIDITYPOOL_IMPL"
echo -e "${CYAN}│${NC}  ${YELLOW}SwapRouter Impl:${NC}      $SWAPROUTER_IMPL"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Points (Baseline):${NC}"
echo -e "  ${CYAN}1.${NC} Direct deployment uses CREATE opcode (nonce-based addresses)"
echo -e "  ${CYAN}2.${NC} No address preregistration or permission checks"
echo -e "  ${CYAN}3.${NC} Circular dependencies handled by delayed initialization"
echo -e "  ${CYAN}4.${NC} Anyone with ETH can deploy (no RBAC)"
echo ""
echo -e "${WHITE}Compare with:${NC}"
echo -e "  ${GREEN}./demo-privacy-proxy.sh${NC}     - Same flow through privacy proxy with RBAC"
echo -e "  ${GREEN}./demo-defi-deployment.sh${NC}   - CREATE3 deterministic deployment"
echo ""
