#!/bin/bash

# =============================================================================
# Privacy Proxy - CREATE3 Proxy Upgrade Demo
# =============================================================================
# This script demonstrates the full flow of:
# 1. Preregistering addresses via CREATE3
# 2. Deploying an upgradeable proxy contract
# 3. Making calls before upgrade
# 4. Upgrading the implementation
# 5. Making calls after upgrade
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

print_header "CREATE3 Proxy Upgrade Demo"

print_step "Checking Configuration"

# Environment variables with defaults
# Default private key is Anvil's first account (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
: "${ADMIN_API_URL:=http://localhost:8080/api}"
: "${RPC_URL:=http://localhost:8545}"
: "${ORG_ID:?ORG_ID environment variable is required}"
: "${DEPLOYER_PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

# Optional: CREATE3 factory address (will be fetched from org config if not set)
CREATE3_FACTORY="${CREATE3_FACTORY:-}"

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "RPC URL" "$RPC_URL"
print_value "Organization ID" "$ORG_ID"
print_value "Deployer Key" "${DEPLOYER_PRIVATE_KEY:0:10}..."

# Get deployer address from private key
DEPLOYER_ADDRESS=$(cast wallet address "$DEPLOYER_PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# =============================================================================
# Step 1: Get or verify CREATE3 factory
# =============================================================================

print_step "Step 1: Checking CREATE3 Factory Configuration"

if [ -z "$CREATE3_FACTORY" ]; then
    print_substep "Fetching factory address from org config..."
    FACTORY_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/config/create3")
    CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')

    if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
        print_error "No CREATE3 factory configured for this organization"
        print_info "Please configure a factory first via the admin UI or API"
        exit 1
    fi
fi

print_success "CREATE3 Factory: $CREATE3_FACTORY"

# =============================================================================
# Step 2: List existing preregistered addresses
# =============================================================================

print_step "Step 2: Fetching Preregistered Addresses"

print_substep "Calling GET /orgs/$ORG_ID/addresses/preregistered..."

PREREGISTERED_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregistered")
PREREGISTERED_COUNT=$(echo "$PREREGISTERED_RESPONSE" | jq 'length')

print_success "Found $PREREGISTERED_COUNT preregistered addresses"

if [ "$PREREGISTERED_COUNT" -gt 0 ]; then
    echo ""
    echo -e "  ${WHITE}Available addresses:${NC}"
    echo "$PREREGISTERED_RESPONSE" | jq -r '.[] | "  │ \(.address) (salt: \(.salt[:16])...)"' 2>/dev/null || echo "$PREREGISTERED_RESPONSE"
fi

# =============================================================================
# Step 3: Preregister new addresses for this demo
# =============================================================================

print_step "Step 3: Preregistering Addresses for Demo"

SALT_PREFIX="demo-$(date +%s)"
print_substep "Using salt prefix: $SALT_PREFIX"

print_substep "Preregistering 3 addresses (proxy + 2 implementations)..."

PREREGISTER_RESPONSE=$(curl -s -X POST "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregister" \
    -H "Content-Type: application/json" \
    -d "{
        \"factory\": \"$CREATE3_FACTORY\",
        \"salt_prefix\": \"$SALT_PREFIX\",
        \"count\": 3,
        \"note\": \"Demo proxy upgrade addresses\"
    }")

if echo "$PREREGISTER_RESPONSE" | jq -e '.addresses' > /dev/null 2>&1; then
    print_success "Addresses preregistered successfully!"

    # Extract addresses
    PROXY_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].address')
    IMPL_V1_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].address')
    IMPL_V2_ADDR=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].address')

    PROXY_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[0].salt')
    IMPL_V1_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[1].salt')
    IMPL_V2_SALT=$(echo "$PREREGISTER_RESPONSE" | jq -r '.addresses[2].salt')

    echo ""
    echo -e "  ${WHITE}Preregistered addresses:${NC}"
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC} ${YELLOW}Proxy:${NC}              $PROXY_ADDR"
    echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V1:${NC}  $IMPL_V1_ADDR"
    echo -e "  ${CYAN}│${NC} ${YELLOW}Implementation V2:${NC}  $IMPL_V2_ADDR"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
else
    print_error "Failed to preregister addresses"
    echo "$PREREGISTER_RESPONSE" | jq '.'
    exit 1
fi

# =============================================================================
# Step 4: Build contracts
# =============================================================================

print_step "Step 4: Building Contracts"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_DIR="$SCRIPT_DIR/contracts"

cd "$CONTRACTS_DIR"

# Install dependencies if needed
if [ ! -d "lib/openzeppelin-contracts-upgradeable" ]; then
    print_substep "Installing OpenZeppelin contracts..."
    forge install OpenZeppelin/openzeppelin-contracts-upgradeable --no-commit 2>/dev/null || true
    forge install OpenZeppelin/openzeppelin-contracts --no-commit 2>/dev/null || true
fi

print_substep "Compiling contracts..."
forge build --quiet

print_success "Contracts compiled successfully"

# Get bytecode
BOXV1_BYTECODE=$(forge inspect BoxV1 bytecode)
BOXV2_BYTECODE=$(forge inspect BoxV2 bytecode)

print_value "BoxV1 bytecode size" "$(echo -n "$BOXV1_BYTECODE" | wc -c | tr -d ' ') chars"
print_value "BoxV2 bytecode size" "$(echo -n "$BOXV2_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 5: Deploy Implementation V1
# =============================================================================

print_step "Step 5: Deploying Implementation V1"

print_substep "Deploying BoxV1 to preregistered address via CREATE3..."
print_info "Target address: $IMPL_V1_ADDR"
print_info "Salt: ${IMPL_V1_SALT:0:20}..."

# Deploy via CREATE3 factory
# The factory.deploy(bytes32 salt, bytes creationCode) function
DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$IMPL_V1_SALT" "$BOXV1_BYTECODE")

TX_HASH_V1=$(cast send "$CREATE3_FACTORY" "$DEPLOY_CALLDATA" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --json 2>/dev/null | jq -r '.transactionHash')

if [ -z "$TX_HASH_V1" ] || [ "$TX_HASH_V1" = "null" ]; then
    print_error "Failed to deploy BoxV1"
    exit 1
fi

print_success "BoxV1 deployed!"
print_value "Transaction" "$TX_HASH_V1"
print_value "Address" "$IMPL_V1_ADDR"

# Verify deployment
CODE_SIZE=$(cast codesize "$IMPL_V1_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
print_value "Contract code size" "$CODE_SIZE bytes"

# =============================================================================
# Step 6: Deploy ERC1967 Proxy
# =============================================================================

print_step "Step 6: Deploying ERC1967 Proxy"

print_substep "Building proxy deployment bytecode..."

# Initialize data for BoxV1.initialize(owner)
INIT_DATA=$(cast calldata "initialize(address)" "$DEPLOYER_ADDRESS")

# ERC1967Proxy constructor takes (implementation, data)
# We need to deploy a proxy that points to our V1 implementation
# Using OpenZeppelin's ERC1967Proxy pattern

# For simplicity, let's use a minimal UUPS proxy bytecode
# This is a simplified version - in production you'd use OZ's proxy

print_info "Target proxy address: $PROXY_ADDR"
print_info "Implementation: $IMPL_V1_ADDR"

# Get the ERC1967Proxy bytecode and encode constructor args
# We'll need to compile a proxy contract
cat > "$CONTRACTS_DIR/src/DeployProxy.sol" << 'EOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployableProxy is ERC1967Proxy {
    constructor(address implementation, bytes memory data) ERC1967Proxy(implementation, data) {}
}
EOF

forge build --quiet

PROXY_BYTECODE=$(forge inspect DeployableProxy bytecode)
# Encode constructor args: (implementation, initData)
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address,bytes)" "$IMPL_V1_ADDR" "$INIT_DATA")
# Remove 0x prefix from constructor args
CONSTRUCTOR_ARGS_NO_PREFIX="${CONSTRUCTOR_ARGS:2}"
PROXY_INIT_CODE="${PROXY_BYTECODE}${CONSTRUCTOR_ARGS_NO_PREFIX}"

print_substep "Deploying proxy via CREATE3..."

DEPLOY_PROXY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$PROXY_SALT" "$PROXY_INIT_CODE")

TX_HASH_PROXY=$(cast send "$CREATE3_FACTORY" "$DEPLOY_PROXY_CALLDATA" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --json 2>/dev/null | jq -r '.transactionHash')

if [ -z "$TX_HASH_PROXY" ] || [ "$TX_HASH_PROXY" = "null" ]; then
    print_error "Failed to deploy proxy"
    exit 1
fi

print_success "Proxy deployed!"
print_value "Transaction" "$TX_HASH_PROXY"
print_value "Proxy Address" "$PROXY_ADDR"

# =============================================================================
# Step 7: Interact with V1
# =============================================================================

print_step "Step 7: Interacting with Contract (V1)"

print_substep "Calling version()..."
VERSION_V1=$(cast call "$PROXY_ADDR" "version()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "error")
print_contract_call "$PROXY_ADDR" "version()" "$VERSION_V1"

print_substep "Calling store(42)..."
cast send "$PROXY_ADDR" "store(uint256)" 42 \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --quiet 2>/dev/null
print_success "Stored value: 42"

print_substep "Calling retrieve()..."
STORED_VALUE=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE"

# =============================================================================
# Step 8: Deploy Implementation V2
# =============================================================================

print_step "Step 8: Deploying Implementation V2"

print_substep "Deploying BoxV2 to preregistered address via CREATE3..."
print_info "Target address: $IMPL_V2_ADDR"

DEPLOY_V2_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$IMPL_V2_SALT" "$BOXV2_BYTECODE")

TX_HASH_V2=$(cast send "$CREATE3_FACTORY" "$DEPLOY_V2_CALLDATA" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --json 2>/dev/null | jq -r '.transactionHash')

if [ -z "$TX_HASH_V2" ] || [ "$TX_HASH_V2" = "null" ]; then
    print_error "Failed to deploy BoxV2"
    exit 1
fi

print_success "BoxV2 deployed!"
print_value "Transaction" "$TX_HASH_V2"
print_value "Address" "$IMPL_V2_ADDR"

# =============================================================================
# Step 9: Upgrade Proxy to V2
# =============================================================================

print_step "Step 9: Upgrading Proxy to V2"

print_substep "Calling upgradeToAndCall()..."
print_info "Old implementation: $IMPL_V1_ADDR"
print_info "New implementation: $IMPL_V2_ADDR"

# UUPS upgrade - call upgradeTo on the proxy
TX_HASH_UPGRADE=$(cast send "$PROXY_ADDR" "upgradeToAndCall(address,bytes)" "$IMPL_V2_ADDR" "0x" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --json 2>/dev/null | jq -r '.transactionHash')

if [ -z "$TX_HASH_UPGRADE" ] || [ "$TX_HASH_UPGRADE" = "null" ]; then
    print_error "Failed to upgrade proxy"
    exit 1
fi

print_success "Proxy upgraded to V2!"
print_value "Transaction" "$TX_HASH_UPGRADE"

# =============================================================================
# Step 10: Interact with V2
# =============================================================================

print_step "Step 10: Interacting with Contract (V2)"

print_substep "Calling version()..."
VERSION_V2=$(cast call "$PROXY_ADDR" "version()(string)" --rpc-url "$RPC_URL" 2>/dev/null || echo "error")
print_contract_call "$PROXY_ADDR" "version()" "$VERSION_V2"

print_substep "Calling retrieve() - value should be preserved..."
STORED_VALUE_V2=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE_V2"

print_substep "Calling increment() - new V2 function..."
cast send "$PROXY_ADDR" "increment()" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --quiet 2>/dev/null
print_success "Called increment()"

print_substep "Calling retrieve() after increment..."
STORED_VALUE_AFTER=$(cast call "$PROXY_ADDR" "retrieve()(uint256)" --rpc-url "$RPC_URL" 2>/dev/null)
print_contract_call "$PROXY_ADDR" "retrieve()" "$STORED_VALUE_AFTER"

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete!"

echo -e "${WHITE}Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}CREATE3 Factory:${NC}     $CREATE3_FACTORY"
echo -e "${CYAN}│${NC}  ${YELLOW}Proxy Address:${NC}       $PROXY_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}Implementation V1:${NC}   $IMPL_V1_ADDR"
echo -e "${CYAN}│${NC}  ${YELLOW}Implementation V2:${NC}   $IMPL_V2_ADDR"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}Version before upgrade:${NC}  $VERSION_V1"
echo -e "${CYAN}│${NC}  ${GREEN}Version after upgrade:${NC}   $VERSION_V2"
echo -e "${CYAN}│${NC}  ${GREEN}Value preserved:${NC}         $STORED_VALUE_V2"
echo -e "${CYAN}│${NC}  ${GREEN}Value after increment:${NC}   $STORED_VALUE_AFTER"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"

echo ""
echo -e "${GREEN}All operations completed successfully!${NC}"
echo ""
echo -e "${WHITE}Key Points Demonstrated:${NC}"
echo -e "  ${CYAN}1.${NC} Addresses were preregistered before deployment"
echo -e "  ${CYAN}2.${NC} Contracts deployed to deterministic CREATE3 addresses"
echo -e "  ${CYAN}3.${NC} Proxy pattern preserves state across upgrades"
echo -e "  ${CYAN}4.${NC} New functionality (increment) available after upgrade"
echo ""
