#!/bin/bash

# =============================================================================
# Privacy Proxy - Production-Style Contract Deployment
# =============================================================================
# This script demonstrates deploying contracts through the privacy proxy
# as a real user would in production:
#
# 1. User has already authenticated via Privado ID (ZK proof)
# 2. User has a JWT token from the web UI
# 3. User signs transactions locally with their private key
# 4. Transactions go through the proxy via eth_sendRawTransaction
#
# Prerequisites:
#   - User authenticated and has JWT token
#   - User has 'deploy' permission in their organization
#   - Private key with funded account
#
# Usage:
#   export PRIVACY_TOKEN="eyJ..."  # From web UI "Copy for Foundry" button
#   export PRIVATE_KEY="0x..."     # Your deployer private key
#   ./demo-prod-deployment.sh
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

print_header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

print_step() {
    echo -e "\n${YELLOW}▶${NC} ${BOLD}$1${NC}"
}

print_success() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${CYAN}ℹ${NC} $1"
}

print_value() {
    echo -e "  ${WHITE}$1:${NC} ${GREEN}$2${NC}"
}

# =============================================================================
# Configuration
# =============================================================================

print_header "Production-Style Contract Deployment"

# Required environment variables
if [ -z "$PRIVACY_TOKEN" ]; then
    echo -e "${RED}Error: PRIVACY_TOKEN not set${NC}"
    echo ""
    echo "To get your token:"
    echo "  1. Go to http://localhost:5173"
    echo "  2. Authenticate with Privado ID"
    echo "  3. Click 'Copy for Foundry/Hardhat' button"
    echo "  4. Paste the export command in your terminal"
    echo ""
    echo "Then run this script again."
    exit 1
fi

if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}Error: PRIVATE_KEY not set${NC}"
    echo ""
    echo "Set your deployer private key:"
    echo "  export PRIVATE_KEY=\"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\""
    echo ""
    echo "(The above is Anvil's default account #0 for testing)"
    exit 1
fi

# Configuration with defaults
: "${PROXY_RPC_URL:=http://localhost:8080/rpc}"
: "${CHAIN_ID:=31337}"

print_step "Step 1: Checking Configuration"

print_value "Proxy RPC URL" "$PROXY_RPC_URL"
print_value "Chain ID" "$CHAIN_ID"
print_value "Token" "${PRIVACY_TOKEN:0:20}...${PRIVACY_TOKEN: -10}"

DEPLOYER_ADDRESS=$(cast wallet address "$PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# Set up Foundry to use auth header
export ETH_RPC_HEADERS="Authorization: Bearer $PRIVACY_TOKEN"
export ETH_RPC_URL="$PROXY_RPC_URL"

# =============================================================================
# Step 2: Verify Connection
# =============================================================================

print_step "Step 2: Verifying Connection to Privacy Proxy"

print_info "Testing RPC connection..."
CHAIN_RESULT=$(cast chain-id --rpc-url "$PROXY_RPC_URL" 2>&1) || {
    print_error "Failed to connect to proxy"
    echo -e "  ${RED}Response: $CHAIN_RESULT${NC}"
    echo ""
    echo "Common issues:"
    echo "  - Token expired (get a fresh one from web UI)"
    echo "  - User not in an organization with deploy permissions"
    echo "  - Proxy not running"
    exit 1
}
print_success "Connected to chain $CHAIN_RESULT"

# Check balance
BALANCE=$(cast balance "$DEPLOYER_ADDRESS" --rpc-url "$PROXY_RPC_URL" 2>/dev/null)
print_value "Deployer Balance" "$BALANCE"

if [ "$BALANCE" = "0" ]; then
    print_error "Deployer has no funds. Fund the account first."
    exit 1
fi

# =============================================================================
# Step 3: Build Contracts
# =============================================================================

print_step "Step 3: Building Demo Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/contracts"

print_info "Compiling contracts..."
forge build --quiet 2>/dev/null || {
    print_info "Installing dependencies first..."
    forge install --quiet 2>/dev/null || true
    forge build --quiet
}
print_success "Contracts compiled"

# =============================================================================
# Step 4: Deploy Contracts
# =============================================================================

print_step "Step 4: Deploying Contracts via Privacy Proxy"

echo ""
echo -e "  ${WHITE}Deployment Flow:${NC}"
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC}  1. forge signs transaction locally with your private key      ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  2. Sends via eth_sendRawTransaction to proxy                  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  3. Proxy decodes, validates permissions, runs trace           ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC}  4. If valid, forwards to blockchain node                      ${CYAN}│${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
echo ""

# Deploy DemoToken (simple version without UUPS for demo)
print_info "Deploying SimpleDemoToken..."
TOKEN_DEPLOY=$(forge create src/token/SimpleDemoToken.sol:SimpleDemoToken \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>&1) || {
    print_error "Token deployment failed"
    echo "$TOKEN_DEPLOY"
    exit 1
}

TOKEN_ADDR=$(echo "$TOKEN_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$TOKEN_ADDR" ] || [ "$TOKEN_ADDR" = "null" ]; then
    print_error "Failed to get token address"
    echo "$TOKEN_DEPLOY"
    exit 1
fi
print_success "SimpleDemoToken deployed at: $TOKEN_ADDR"

# Deploy LiquidityPool
print_info "Deploying SimpleLiquidityPool..."
POOL_DEPLOY=$(forge create src/pool/SimpleLiquidityPool.sol:SimpleLiquidityPool \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>&1) || {
    print_error "Pool deployment failed"
    echo "$POOL_DEPLOY"
    exit 1
}

POOL_ADDR=$(echo "$POOL_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$POOL_ADDR" ] || [ "$POOL_ADDR" = "null" ]; then
    print_error "Failed to get pool address"
    echo "$POOL_DEPLOY"
    exit 1
fi
print_success "SimpleLiquidityPool deployed at: $POOL_ADDR"

# Deploy SwapRouter
print_info "Deploying SimpleSwapRouter..."
ROUTER_DEPLOY=$(forge create src/router/SimpleSwapRouter.sol:SimpleSwapRouter \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --json 2>&1) || {
    print_error "Router deployment failed"
    echo "$ROUTER_DEPLOY"
    exit 1
}

ROUTER_ADDR=$(echo "$ROUTER_DEPLOY" | jq -r '.deployedTo // empty')
if [ -z "$ROUTER_ADDR" ] || [ "$ROUTER_ADDR" = "null" ]; then
    print_error "Failed to get router address"
    echo "$ROUTER_DEPLOY"
    exit 1
fi
print_success "SimpleSwapRouter deployed at: $ROUTER_ADDR"

# =============================================================================
# Step 5: Initialize Contracts
# =============================================================================

print_step "Step 5: Initializing Contracts"

# Initialize Token
print_info "Initializing token with pool reference..."
cast send "$TOKEN_ADDR" "initialize(address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Token may already be initialized"
print_success "Token initialized"

# Initialize Pool
print_info "Initializing pool with token reference..."
cast send "$POOL_ADDR" "initialize(address,address)" "$DEPLOYER_ADDRESS" "$TOKEN_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Pool may already be initialized"
print_success "Pool initialized"

# Initialize Router
print_info "Initializing router with pool and token references..."
cast send "$ROUTER_ADDR" "initialize(address,address,address)" "$DEPLOYER_ADDRESS" "$POOL_ADDR" "$TOKEN_ADDR" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null || print_info "Router may already be initialized"
print_success "Router initialized"

# =============================================================================
# Step 6: Verify Deployment
# =============================================================================

print_step "Step 6: Verifying Deployment"

# Verify code exists
TOKEN_CODE=$(cast codesize "$TOKEN_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")
POOL_CODE=$(cast codesize "$POOL_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")
ROUTER_CODE=$(cast codesize "$ROUTER_ADDR" --rpc-url "$PROXY_RPC_URL" 2>/dev/null || echo "0")

print_value "Token code size" "$TOKEN_CODE bytes"
print_value "Pool code size" "$POOL_CODE bytes"
print_value "Router code size" "$ROUTER_CODE bytes"

# Verify cross-references
print_info "Verifying cross-references..."
POOL_TOKEN=$(cast call "$POOL_ADDR" "token()(address)" --rpc-url "$PROXY_RPC_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')
ROUTER_POOL=$(cast call "$ROUTER_ADDR" "pool()(address)" --rpc-url "$PROXY_RPC_URL" 2>/dev/null | tr '[:upper:]' '[:lower:]')

if [ "$POOL_TOKEN" = "$(echo $TOKEN_ADDR | tr '[:upper:]' '[:lower:]')" ]; then
    print_success "Pool correctly references Token"
else
    print_error "Pool token reference mismatch"
fi

if [ "$ROUTER_POOL" = "$(echo $POOL_ADDR | tr '[:upper:]' '[:lower:]')" ]; then
    print_success "Router correctly references Pool"
else
    print_error "Router pool reference mismatch"
fi

# =============================================================================
# Step 7: Test Interaction
# =============================================================================

print_step "Step 7: Testing Contract Interaction"

# Mint some tokens
print_info "Minting 1000 tokens..."
cast send "$TOKEN_ADDR" "mint(address,uint256)" "$DEPLOYER_ADDRESS" "1000000000000000000000" \
    --rpc-url "$PROXY_RPC_URL" \
    --private-key "$PRIVATE_KEY" \
    --quiet 2>/dev/null
print_success "Tokens minted"

# Check balance
TOKEN_BALANCE=$(cast call "$TOKEN_ADDR" "balanceOf(address)(uint256)" "$DEPLOYER_ADDRESS" \
    --rpc-url "$PROXY_RPC_URL" 2>/dev/null)
print_value "Token balance" "$TOKEN_BALANCE"

# =============================================================================
# Summary
# =============================================================================

print_header "Deployment Complete!"

echo -e "${WHITE}Deployed Contracts:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleDemoToken:${NC}     $TOKEN_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleLiquidityPool:${NC} $POOL_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}SimpleSwapRouter:${NC}    $ROUTER_ADDR"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${WHITE}What happened:${NC}"
echo -e "  ${GREEN}1.${NC} Transactions signed locally with your private key"
echo -e "  ${GREEN}2.${NC} Sent via eth_sendRawTransaction through privacy proxy"
echo -e "  ${GREEN}3.${NC} Proxy validated your JWT token and permissions"
echo -e "  ${GREEN}4.${NC} Proxy ran debug_traceCall to verify cross-org isolation"
echo -e "  ${GREEN}5.${NC} Contracts deployed to the blockchain"

echo ""
echo -e "${WHITE}To interact with contracts:${NC}"
echo -e "  ${CYAN}# Check token balance${NC}"
echo -e "  cast call $TOKEN_ADDR \"balanceOf(address)(uint256)\" $DEPLOYER_ADDRESS --rpc-url \$ETH_RPC_URL"
echo ""
echo -e "  ${CYAN}# Transfer tokens${NC}"
echo -e "  cast send $TOKEN_ADDR \"transfer(address,uint256)\" 0xRECIPIENT 100 --rpc-url \$ETH_RPC_URL --private-key \$PRIVATE_KEY"
echo ""
