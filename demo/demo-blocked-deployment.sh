#!/bin/bash

# =============================================================================
# Privacy Proxy - Security Boundary Demo
# =============================================================================
# This script demonstrates the security boundaries of the privacy proxy.
#
# The MaliciousBox contract:
# 1. Gets deployed to a preregistered address (allowed)
# 2. Contains code that makes internal CALL to 0xDeaDbeeF...
#
# This demonstrates:
# - Deployment TO preregistered addresses: ALLOWED
# - Internal CALL opcodes during execution: NOT BLOCKED (EVM limitation)
# - RPC transactions to non-allowed addresses: BLOCKED
#
# The privacy proxy operates at the RPC layer, not at the EVM opcode level.
# This means it can control what transactions users submit, but cannot
# intercept internal contract-to-contract calls during execution.
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

print_warning() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

# =============================================================================
# Configuration
# =============================================================================

print_header "Security Boundary Demo"

print_step "Checking Configuration"

# Environment variables with defaults
: "${ADMIN_API_URL:=http://localhost:8080/api}"
: "${RPC_URL:=http://localhost:8545}"
: "${DEPLOYER_PRIVATE_KEY:=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

if [ -z "$ORG_ID" ] && [ -z "$ORG_SLUG" ]; then
    echo -e "${RED}Error: Either ORG_SLUG or ORG_ID environment variable is required${NC}"
    exit 1
fi

print_value "Admin API URL" "$ADMIN_API_URL"
print_value "RPC URL" "$RPC_URL"

# Lookup org by slug if needed
if [ -n "$ORG_SLUG" ] && [ -z "$ORG_ID" ]; then
    print_substep "Looking up organization by slug: $ORG_SLUG"
    ORGS_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs")
    ORG_ID=$(echo "$ORGS_RESPONSE" | jq -r ".[] | select(.slug == \"$ORG_SLUG\") | .id")

    if [ -z "$ORG_ID" ] || [ "$ORG_ID" = "null" ]; then
        print_error "Organization with slug '$ORG_SLUG' not found"
        exit 1
    fi
    print_success "Found organization"
fi

print_value "Organization ID" "$ORG_ID"

DEPLOYER_ADDRESS=$(cast wallet address "$DEPLOYER_PRIVATE_KEY" 2>/dev/null)
print_value "Deployer Address" "$DEPLOYER_ADDRESS"

# =============================================================================
# Step 1: Get CREATE3 factory
# =============================================================================

print_step "Step 1: Checking CREATE3 Factory"

if [ -z "$CREATE3_FACTORY" ]; then
    print_substep "Fetching factory address from org config..."
    FACTORY_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/config/create3")
    CREATE3_FACTORY=$(echo "$FACTORY_RESPONSE" | jq -r '.factory // empty')

    if [ -z "$CREATE3_FACTORY" ] || [ "$CREATE3_FACTORY" = "null" ]; then
        print_error "No CREATE3 factory configured for this organization"
        exit 1
    fi
fi

print_success "CREATE3 Factory: $CREATE3_FACTORY"

# Verify factory has code
FACTORY_CODE_SIZE=$(cast codesize "$CREATE3_FACTORY" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
if [ "$FACTORY_CODE_SIZE" = "0" ]; then
    print_error "No contract found at factory address"
    exit 1
fi
print_success "Factory contract verified"

# =============================================================================
# Step 2: Get preregistered address
# =============================================================================

print_step "Step 2: Getting Preregistered Address"

print_substep "Fetching preregistered addresses..."
PREREGISTERED_RESPONSE=$(curl -s "$ADMIN_API_URL/orgs/$ORG_ID/addresses/preregistered")
FACTORY_LOWER=$(echo "$CREATE3_FACTORY" | tr '[:upper:]' '[:lower:]')

# Find an unused address for the current factory
MALICIOUS_ADDR=""
MALICIOUS_SALT=""

PREREGISTERED_COUNT=$(echo "$PREREGISTERED_RESPONSE" | jq 'length' 2>/dev/null || echo "0")

for i in $(seq 0 $((PREREGISTERED_COUNT - 1))); do
    ADDR=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].address")
    SALT=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].salt")
    ADDR_FACTORY=$(echo "$PREREGISTERED_RESPONSE" | jq -r ".[$i].factory" | tr '[:upper:]' '[:lower:]')

    if [ "$ADDR_FACTORY" != "$FACTORY_LOWER" ]; then
        continue
    fi

    CODE_SIZE=$(cast codesize "$ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")
    if [ "$CODE_SIZE" = "0" ]; then
        MALICIOUS_ADDR="$ADDR"
        MALICIOUS_SALT="$SALT"
        break
    fi
done

if [ -z "$MALICIOUS_ADDR" ]; then
    print_error "No unused preregistered addresses available"
    print_info "Please preregister more addresses first"
    exit 1
fi

print_success "Found unused preregistered address"
print_value "Target Address" "$MALICIOUS_ADDR"
print_value "Salt" "${MALICIOUS_SALT:0:20}..."

# =============================================================================
# Step 3: Build MaliciousBox contract
# =============================================================================

print_step "Step 3: Building MaliciousBox Contract"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACTS_SRC_DIR="$SCRIPT_DIR/contracts"

BUILD_DIR=$(mktemp -d)
print_substep "Using temp build directory: $BUILD_DIR"

cp -r "$CONTRACTS_SRC_DIR"/* "$BUILD_DIR/"
cd "$BUILD_DIR"

cleanup() {
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}
trap cleanup EXIT

# Initialize git repo
print_substep "Initializing git repository..."
git init --quiet
git config user.email "demo@example.com"
git config user.name "Demo"
git add -A
git commit -m "Initial" --quiet

# Install OpenZeppelin
print_substep "Installing OpenZeppelin contracts..."
mkdir -p lib
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git lib/openzeppelin-contracts-upgradeable 2>/dev/null
git clone --quiet --depth 1 https://github.com/OpenZeppelin/openzeppelin-contracts.git lib/openzeppelin-contracts 2>/dev/null
print_success "Dependencies installed"

print_substep "Compiling MaliciousBox..."
forge build --quiet

print_success "Contract compiled"

MALICIOUS_BYTECODE=$(forge inspect MaliciousBox bytecode)
print_value "Bytecode size" "$(echo -n "$MALICIOUS_BYTECODE" | wc -c | tr -d ' ') chars"

# =============================================================================
# Step 4: Show what the contract does
# =============================================================================

print_step "Step 4: Understanding the Malicious Contract"

echo -e "  ${WHITE}The MaliciousBox contract contains:${NC}"
echo ""
echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────────────┐${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}Hardcoded external address:${NC}"
echo -e "  ${CYAN}│${NC}   0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}In constructor:${NC}"
echo -e "  ${CYAN}│${NC}   (bool success, ) = EXTERNAL_TARGET.call(\"\");"
echo -e "  ${CYAN}│${NC}   externalCallMade = success;"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${YELLOW}Also has callExternal() function for testing${NC}"
echo -e "  ${CYAN}│${NC}"
echo -e "  ${CYAN}│${NC} ${RED}External address is NOT preregistered!${NC}"
echo -e "  ${CYAN}└─────────────────────────────────────────────────────────────────┘${NC}"
echo ""

print_warning "The privacy proxy should detect this and block the deployment"

# =============================================================================
# Step 5: Attempt deployment (should fail)
# =============================================================================

print_step "Step 5: Attempting Deployment (Expected to FAIL)"

print_substep "Deploying MaliciousBox via CREATE3..."
print_info "Target address: $MALICIOUS_ADDR"
print_info "External call target: 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"

DEPLOY_CALLDATA=$(cast calldata "deploy(bytes32,bytes)" "$MALICIOUS_SALT" "$MALICIOUS_BYTECODE")

echo ""
print_substep "Sending deployment transaction..."

DEPLOY_RESULT=$(cast send "$CREATE3_FACTORY" "$DEPLOY_CALLDATA" \
    --private-key "$DEPLOYER_PRIVATE_KEY" \
    --rpc-url "$RPC_URL" \
    --json 2>&1)

TX_HASH=$(echo "$DEPLOY_RESULT" | jq -r '.transactionHash' 2>/dev/null)

if [ -z "$TX_HASH" ] || [ "$TX_HASH" = "null" ]; then
    echo ""
    echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${GREEN}│${NC}                    ${BOLD}${GREEN}DEPLOYMENT BLOCKED!${NC}                         ${GREEN}│${NC}"
    echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
    echo ""
    print_success "The privacy proxy correctly blocked the deployment!"
    echo ""
    echo -e "  ${WHITE}Error from proxy:${NC}"
    echo "$DEPLOY_RESULT" | head -5 | sed 's/^/  │ /'
    echo ""
else
    # Transaction was sent - check if contract was actually deployed
    CODE_SIZE=$(cast codesize "$MALICIOUS_ADDR" --rpc-url "$RPC_URL" 2>/dev/null || echo "0")

    if [ "$CODE_SIZE" = "0" ]; then
        echo ""
        echo -e "  ${YELLOW}┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${YELLOW}│${NC}              ${BOLD}${YELLOW}DEPLOYMENT FAILED (tx reverted)${NC}                  ${YELLOW}│${NC}"
        echo -e "  ${YELLOW}└─────────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        print_warning "Transaction was sent but deployment failed"
        print_value "Transaction" "$TX_HASH"
        print_value "Contract code size" "0 bytes (not deployed)"
    else
        echo ""
        echo -e "  ${YELLOW}┌─────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "  ${YELLOW}│${NC}           ${BOLD}${YELLOW}DEPLOYMENT SUCCEEDED (as expected)${NC}                  ${YELLOW}│${NC}"
        echo -e "  ${YELLOW}└─────────────────────────────────────────────────────────────────┘${NC}"
        echo ""
        print_info "The contract was deployed to the preregistered address"
        print_info "The external call happens at RUNTIME, not deployment"
        print_value "Transaction" "$TX_HASH"
        print_value "Contract address" "$MALICIOUS_ADDR"
        print_value "Code size" "$CODE_SIZE bytes"

        # Check if the constructor's external call succeeded
        print_step "Step 6: Checking Constructor External Call Result"

        print_substep "Checking if the external call in constructor succeeded..."
        EXTERNAL_CALL_MADE=$(cast call "$MALICIOUS_ADDR" "externalCallMade()(bool)" --rpc-url "$RPC_URL" 2>/dev/null)

        if [ "$EXTERNAL_CALL_MADE" = "false" ]; then
            echo ""
            echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "  ${GREEN}│${NC}         ${BOLD}${GREEN}CONSTRUCTOR EXTERNAL CALL FAILED!${NC}                   ${GREEN}│${NC}"
            echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
            echo ""
            print_success "The external call to 0xDeaDbeeF in constructor returned false"
            print_info "The call to non-preregistered address failed (as expected)"
        else
            print_warning "Constructor external call returned: $EXTERNAL_CALL_MADE"
            print_info "This may indicate the external call wasn't blocked"
        fi

        # Now try callExternal() function
        print_step "Step 7: Calling callExternal() Function"

        print_substep "Calling callExternal() which tries to call 0xDeaDbeeF..."
        echo ""

        CALL_RESULT=$(cast call "$MALICIOUS_ADDR" "callExternal()(bool)" --rpc-url "$RPC_URL" 2>&1)

        if [ "$CALL_RESULT" = "false" ]; then
            echo ""
            echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "  ${GREEN}│${NC}           ${BOLD}${GREEN}EXTERNAL CALL RETURNED FALSE!${NC}                      ${GREEN}│${NC}"
            echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
            echo ""
            print_success "callExternal() returned false"
            print_info "The call to 0xDeaDbeeF failed (no code at that address)"
        elif echo "$CALL_RESULT" | grep -qi "error\|revert\|blocked"; then
            echo ""
            echo -e "  ${GREEN}┌─────────────────────────────────────────────────────────────────┐${NC}"
            echo -e "  ${GREEN}│${NC}              ${BOLD}${GREEN}EXTERNAL CALL BLOCKED!${NC}                          ${GREEN}│${NC}"
            echo -e "  ${GREEN}└─────────────────────────────────────────────────────────────────┘${NC}"
            echo ""
            print_success "The privacy proxy blocked the external call!"
            echo -e "  ${WHITE}Response:${NC}"
            echo "$CALL_RESULT" | head -3 | sed 's/^/  │ /'
        else
            print_warning "callExternal() returned: $CALL_RESULT"
        fi
    fi
fi

# =============================================================================
# Summary
# =============================================================================

print_header "Demo Complete"

echo -e "${WHITE}Summary:${NC}"
echo -e "${CYAN}┌─────────────────────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}│${NC}  ${YELLOW}Contract:${NC}            MaliciousBox"
echo -e "${CYAN}│${NC}  ${YELLOW}External Target:${NC}     0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
echo -e "${CYAN}│${NC}  ${YELLOW}Target Preregistered:${NC} ${RED}NO${NC}"
echo -e "${CYAN}├─────────────────────────────────────────────────────────────────────┤${NC}"
echo -e "${CYAN}│${NC}  ${GREEN}Deployment:${NC}          Allowed (to preregistered address)"
echo -e "${CYAN}│${NC}  ${YELLOW}Internal CALL:${NC}       Not blocked (EVM internal execution)"
echo -e "${CYAN}└─────────────────────────────────────────────────────────────────────┘${NC}"
echo ""
echo -e "${WHITE}Security Model Clarification:${NC}"
echo -e "  ${CYAN}•${NC} Deployment TO preregistered addresses: ${GREEN}allowed${NC}"
echo -e "  ${CYAN}•${NC} RPC transactions TO non-allowed addresses: ${RED}blocked${NC}"
echo -e "  ${CYAN}•${NC} Internal CALL opcodes (contract-to-contract): ${YELLOW}NOT blocked${NC}"
echo ""
echo -e "  ${WHITE}Why internal CALLs aren't blocked:${NC}"
echo -e "  ${CYAN}•${NC} The privacy proxy intercepts RPC requests, not EVM opcodes"
echo -e "  ${CYAN}•${NC} Blocking internal CALLs would require a modified EVM"
echo -e "  ${CYAN}•${NC} call() to address with no code returns true (like EOA)"
echo ""
echo -e "  ${WHITE}What IS protected:${NC}"
echo -e "  ${CYAN}•${NC} Users can only send transactions through the proxy RPC"
echo -e "  ${CYAN}•${NC} Factory deployments must target preregistered addresses"
echo -e "  ${CYAN}•${NC} Contract interactions are logged and can be audited"
echo ""
