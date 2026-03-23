#!/usr/bin/env bash
# setup-test-accounts.sh — Creates test identities for the dev identity picker.
#
# Creates orgs, users, groups, memberships, ETH address links, and a disclosure
# grant so developers can quickly switch between test perspectives in the UI.
#
# Prerequisites:
#   - privacy-proxy running at localhost:8080 with ALLOW_MOCK_LOGIN=true
#   - Anvil running (for ETH transfers and contract deployment)
#   - cast (from Foundry) installed (for signing and sending transactions)
#
# Usage:
#   ./scripts/setup-test-accounts.sh
#   PROXY_URL=http://localhost:8080 ADMIN_TOKEN=secret ./scripts/setup-test-accounts.sh

set -euo pipefail

# Source .env if present (picks up ADMIN_API_TOKEN, etc.)
if [[ -f "$(dirname "$0")/../.env" ]]; then
    set -a
    source "$(dirname "$0")/../.env"
    set +a
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROXY_URL="${PROXY_URL:-http://localhost:8080}"
ADMIN_URL="${PROXY_URL}/api/v1/admin"
ADMIN_TOKEN="${ADMIN_TOKEN:-${ADMIN_API_TOKEN:-}}"
ANVIL_URL="${ANVIL_URL:-http://localhost:8545}"

# Anvil default accounts (deterministic from mnemonic "test test test test test test test test test test test junk")
# Account 0 is the default deployer, we use accounts 1-4 for test users.
ALICE_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
ALICE_ADDR="0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

BOB_KEY="0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
BOB_ADDR="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

CHARLIE_KEY="0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
CHARLIE_ADDR="0x90F79bf6EB2c4f870365E785982E1f101E93b906"

DAVE_KEY="0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
DAVE_ADDR="0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"

# DIDs
ALICE_DID="did:test:alice"
BOB_DID="did:test:bob"
CHARLIE_DID="did:test:charlie"
DAVE_DID="did:test:dave"

# ---------------------------------------------------------------------------
# Colours
# ---------------------------------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No colour

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${CYAN}==> $*${NC}"; }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Build admin auth headers as an array (avoids word-splitting issues)
ADMIN_CURL_HEADERS=()
if [[ -n "$ADMIN_TOKEN" ]]; then
    ADMIN_CURL_HEADERS=(-H "X-Admin-Token: $ADMIN_TOKEN")
fi

# Admin API request helper
admin_get() {
    local path="$1"
    curl -sf "${ADMIN_CURL_HEADERS[@]}" "${ADMIN_URL}${path}" 2>/dev/null || echo ""
}

admin_post() {
    local path="$1"
    local data="$2"
    curl -sf -X POST "${ADMIN_CURL_HEADERS[@]}" -H "Content-Type: application/json" \
        -d "$data" "${ADMIN_URL}${path}" 2>/dev/null || echo ""
}

admin_put() {
    local path="$1"
    local data="$2"
    curl -sf -X PUT "${ADMIN_CURL_HEADERS[@]}" -H "Content-Type: application/json" \
        -d "$data" "${ADMIN_URL}${path}" 2>/dev/null || echo ""
}

# Mock login: creates a user with a specific DID and returns the access token
mock_login() {
    local did="$1"

    # 1. Create auth session
    local session_resp
    session_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d '{"reason":"setup-test-accounts"}' \
        "${PROXY_URL}/api/v1/auth/request" 2>/dev/null)

    if [[ -z "$session_resp" ]]; then
        err "Failed to create auth session for $did"
        return 1
    fi

    local session_id
    session_id=$(echo "$session_resp" | jq -r '.session_id // empty')
    if [[ -z "$session_id" ]]; then
        err "No session_id in response for $did"
        return 1
    fi

    # 2. Mock verify with specific DID
    local token_resp
    token_resp=$(curl -sf -X POST -H "Content-Type: application/json" \
        -d "{\"session_id\":\"$session_id\",\"jwz_token\":\"mock.$did\"}" \
        "${PROXY_URL}/api/v1/auth/verify" 2>/dev/null)

    if [[ -z "$token_resp" ]]; then
        err "Failed to verify mock token for $did"
        return 1
    fi

    local access_token
    access_token=$(echo "$token_resp" | jq -r '.access_token // empty')
    if [[ -z "$access_token" ]]; then
        err "No access_token in response for $did"
        return 1
    fi

    echo "$access_token"
}

# Find user by external_id (DID) via the admin users list
find_user_by_did() {
    local did="$1"
    admin_get "/users?search=$(echo "$did" | sed 's/:/%3A/g')" | jq -r ".data[]? | select(.external_id == \"$did\") | .id // empty"
}

# Find org by slug
find_org_by_slug() {
    local slug="$1"
    admin_get "/orgs" | jq -r ".data[]? | select(.slug == \"$slug\") | .id // empty"
}

# Find group by slug within an org
find_group_by_slug() {
    local org_id="$1"
    local slug="$2"
    admin_get "/orgs/${org_id}/groups" | jq -r ".data[]? | select(.group.slug == \"$slug\") | .group.id // empty"
}

# Link ETH address to a user via the challenge/verify flow
link_eth_address() {
    local access_token="$1"
    local private_key="$2"
    local eth_addr="$3"

    # Check if already linked
    local existing
    existing=$(curl -sf -H "Authorization: Bearer $access_token" \
        "${PROXY_URL}/api/v1/eth/addresses" 2>/dev/null | jq -r ".addresses[]? | select(.address == \"$(echo "$eth_addr" | tr '[:upper:]' '[:lower:]')\") | .address // empty")
    if [[ -n "$existing" ]]; then
        ok "  Address $eth_addr already linked"
        return 0
    fi

    # 1. Get challenge
    local challenge_resp
    challenge_resp=$(curl -sf -X POST -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json" \
        "${PROXY_URL}/api/v1/eth/link/challenge" 2>/dev/null)

    local nonce message
    nonce=$(echo "$challenge_resp" | jq -r '.nonce // empty')
    message=$(echo "$challenge_resp" | jq -r '.message // empty')

    if [[ -z "$nonce" || -z "$message" ]]; then
        err "  Failed to get link challenge for $eth_addr"
        return 1
    fi

    # 2. Sign the message with cast
    local signature
    signature=$(cast wallet sign --private-key "$private_key" "$message" 2>/dev/null)

    if [[ -z "$signature" ]]; then
        err "  Failed to sign challenge for $eth_addr"
        return 1
    fi

    # 3. Verify
    local verify_resp
    verify_resp=$(curl -sf -X POST -H "Authorization: Bearer $access_token" \
        -H "Content-Type: application/json" \
        -d "{\"nonce\":\"$nonce\",\"address\":\"$eth_addr\",\"signature\":\"$signature\"}" \
        "${PROXY_URL}/api/v1/eth/link/verify" 2>/dev/null)

    local linked_addr
    linked_addr=$(echo "$verify_resp" | jq -r '.address // empty')
    if [[ -n "$linked_addr" ]]; then
        ok "  Linked $linked_addr"
    else
        err "  Failed to link $eth_addr: $(echo "$verify_resp" | jq -r '.error // "unknown error"')"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------

step "Preflight checks"

# Check proxy is running
if ! curl -sf "${PROXY_URL}/health" > /dev/null 2>&1; then
    err "Privacy proxy not reachable at ${PROXY_URL}"
    err "Start it with: docker-compose up -d"
    exit 1
fi
ok "Privacy proxy reachable at ${PROXY_URL}"

# Check Anvil is running
if ! curl -sf -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "$ANVIL_URL" > /dev/null 2>&1; then
    err "Anvil not reachable at ${ANVIL_URL}"
    exit 1
fi
ok "Anvil reachable at ${ANVIL_URL}"

# Check cast is installed
if ! command -v cast &> /dev/null; then
    err "cast (Foundry) not found. Install: https://book.getfoundry.sh/getting-started/installation"
    exit 1
fi
ok "cast found"

# Check jq is installed
if ! command -v jq &> /dev/null; then
    err "jq not found. Install: brew install jq"
    exit 1
fi
ok "jq found"

# ---------------------------------------------------------------------------
# Step 1: Create users via mock login
# ---------------------------------------------------------------------------

step "Creating test users via mock login"

ALICE_TOKEN=$(mock_login "$ALICE_DID")
ok "Alice logged in ($ALICE_DID)"

BOB_TOKEN=$(mock_login "$BOB_DID")
ok "Bob logged in ($BOB_DID)"

CHARLIE_TOKEN=$(mock_login "$CHARLIE_DID")
ok "Charlie logged in ($CHARLIE_DID)"

DAVE_TOKEN=$(mock_login "$DAVE_DID")
ok "Dave logged in ($DAVE_DID)"

# ---------------------------------------------------------------------------
# Step 2: Find user IDs
# ---------------------------------------------------------------------------

step "Looking up user IDs"

ALICE_USER_ID=$(find_user_by_did "$ALICE_DID")
BOB_USER_ID=$(find_user_by_did "$BOB_DID")
CHARLIE_USER_ID=$(find_user_by_did "$CHARLIE_DID")
DAVE_USER_ID=$(find_user_by_did "$DAVE_DID")

if [[ -z "$ALICE_USER_ID" || -z "$BOB_USER_ID" || -z "$CHARLIE_USER_ID" || -z "$DAVE_USER_ID" ]]; then
    err "Failed to find one or more user IDs"
    err "  Alice=$ALICE_USER_ID Bob=$BOB_USER_ID Charlie=$CHARLIE_USER_ID Dave=$DAVE_USER_ID"
    exit 1
fi

ok "Alice=$ALICE_USER_ID"
ok "Bob=$BOB_USER_ID"
ok "Charlie=$CHARLIE_USER_ID"
ok "Dave=$DAVE_USER_ID"

# ---------------------------------------------------------------------------
# Step 3: Link ETH addresses
# ---------------------------------------------------------------------------

step "Linking ETH addresses"

info "Linking Alice -> $ALICE_ADDR"
link_eth_address "$ALICE_TOKEN" "$ALICE_KEY" "$ALICE_ADDR"

info "Linking Bob -> $BOB_ADDR"
link_eth_address "$BOB_TOKEN" "$BOB_KEY" "$BOB_ADDR"

info "Linking Charlie -> $CHARLIE_ADDR"
link_eth_address "$CHARLIE_TOKEN" "$CHARLIE_KEY" "$CHARLIE_ADDR"

info "Linking Dave -> $DAVE_ADDR"
link_eth_address "$DAVE_TOKEN" "$DAVE_KEY" "$DAVE_ADDR"

# ---------------------------------------------------------------------------
# Step 4: Create organizations
# ---------------------------------------------------------------------------

step "Creating organizations"

ALPHA_ORG_ID=$(find_org_by_slug "alpha-corp")
if [[ -z "$ALPHA_ORG_ID" ]]; then
    resp=$(admin_post "/orgs" '{"slug":"alpha-corp","name":"Alpha Corp"}')
    ALPHA_ORG_ID=$(echo "$resp" | jq -r '.id // empty')
    if [[ -z "$ALPHA_ORG_ID" ]]; then
        err "Failed to create Alpha Corp: $resp"
        exit 1
    fi
    ok "Created Alpha Corp ($ALPHA_ORG_ID)"
else
    ok "Alpha Corp already exists ($ALPHA_ORG_ID)"
fi

BETA_ORG_ID=$(find_org_by_slug "beta-inc")
if [[ -z "$BETA_ORG_ID" ]]; then
    resp=$(admin_post "/orgs" '{"slug":"beta-inc","name":"Beta Inc"}')
    BETA_ORG_ID=$(echo "$resp" | jq -r '.id // empty')
    if [[ -z "$BETA_ORG_ID" ]]; then
        err "Failed to create Beta Inc: $resp"
        exit 1
    fi
    ok "Created Beta Inc ($BETA_ORG_ID)"
else
    ok "Beta Inc already exists ($BETA_ORG_ID)"
fi

# ---------------------------------------------------------------------------
# Step 5: Create groups with appropriate claims
# ---------------------------------------------------------------------------

step "Creating groups"

# Alpha Corp deployers group
ALPHA_DEPLOYERS_ID=$(find_group_by_slug "$ALPHA_ORG_ID" "deployers")
if [[ -z "$ALPHA_DEPLOYERS_ID" ]]; then
    resp=$(admin_post "/orgs/${ALPHA_ORG_ID}/groups" '{"slug":"deployers","name":"Deployers","description":"Can deploy and manage contracts"}')
    ALPHA_DEPLOYERS_ID=$(echo "$resp" | jq -r '.id // empty')
    ok "Created Alpha Corp deployers group ($ALPHA_DEPLOYERS_ID)"
else
    ok "Alpha Corp deployers group already exists ($ALPHA_DEPLOYERS_ID)"
fi

# Set deployers access: deploy claim (implies read + write)
admin_put "/orgs/${ALPHA_ORG_ID}/groups/${ALPHA_DEPLOYERS_ID}/access" \
    '{"allowed_methods":["*"],"claims":["deploy"]}' > /dev/null
ok "Set deployers access (deploy claim)"

# Alpha Corp readers group
ALPHA_READERS_ID=$(find_group_by_slug "$ALPHA_ORG_ID" "readers")
if [[ -z "$ALPHA_READERS_ID" ]]; then
    resp=$(admin_post "/orgs/${ALPHA_ORG_ID}/groups" '{"slug":"readers","name":"Readers","description":"Read-only access to org contracts"}')
    ALPHA_READERS_ID=$(echo "$resp" | jq -r '.id // empty')
    ok "Created Alpha Corp readers group ($ALPHA_READERS_ID)"
else
    ok "Alpha Corp readers group already exists ($ALPHA_READERS_ID)"
fi

# Set readers access: read claim only
admin_put "/orgs/${ALPHA_ORG_ID}/groups/${ALPHA_READERS_ID}/access" \
    '{"allowed_methods":["eth_call","eth_getBalance","eth_getTransactionByHash","eth_getTransactionReceipt","eth_blockNumber","eth_getBlockByNumber","eth_getBlockByHash","eth_chainId","net_version","eth_getCode","eth_getStorageAt","eth_getLogs","eth_getTransactionCount"],"claims":["read"]}' > /dev/null
ok "Set readers access (read claim)"

# Beta Inc deployers group
BETA_DEPLOYERS_ID=$(find_group_by_slug "$BETA_ORG_ID" "deployers")
if [[ -z "$BETA_DEPLOYERS_ID" ]]; then
    resp=$(admin_post "/orgs/${BETA_ORG_ID}/groups" '{"slug":"deployers","name":"Deployers","description":"Can deploy and manage contracts"}')
    BETA_DEPLOYERS_ID=$(echo "$resp" | jq -r '.id // empty')
    ok "Created Beta Inc deployers group ($BETA_DEPLOYERS_ID)"
else
    ok "Beta Inc deployers group already exists ($BETA_DEPLOYERS_ID)"
fi

# Set Beta deployers access
admin_put "/orgs/${BETA_ORG_ID}/groups/${BETA_DEPLOYERS_ID}/access" \
    '{"allowed_methods":["*"],"claims":["deploy"]}' > /dev/null
ok "Set Beta deployers access (deploy claim)"

# ---------------------------------------------------------------------------
# Step 6: Add users to groups (memberships)
# ---------------------------------------------------------------------------

step "Creating memberships"

# Helper: create membership if not exists
create_membership() {
    local user_id="$1"
    local group_id="$2"
    local label="$3"

    # Check existing memberships
    local existing
    existing=$(admin_get "/users/${user_id}/memberships" | jq -r ".[].membership.group_id // empty" 2>/dev/null)
    if echo "$existing" | grep -q "$group_id"; then
        ok "$label already a member"
        return 0
    fi

    local resp
    resp=$(admin_post "/users/${user_id}/memberships" "{\"group_id\":\"$group_id\"}")
    local mid
    mid=$(echo "$resp" | jq -r '.id // empty')
    if [[ -n "$mid" ]]; then
        ok "$label membership created"
    else
        warn "$label membership may already exist or failed: $resp"
    fi
}

create_membership "$ALICE_USER_ID"   "$ALPHA_DEPLOYERS_ID" "Alice -> Alpha Corp deployers"
create_membership "$BOB_USER_ID"     "$ALPHA_READERS_ID"   "Bob -> Alpha Corp readers"
create_membership "$CHARLIE_USER_ID" "$BETA_DEPLOYERS_ID"  "Charlie -> Beta Inc deployers"
# Dave has no org membership (anonymous user)
ok "Dave has no org membership (anonymous user)"

# ---------------------------------------------------------------------------
# Step 7: Set user notes and KYC
# ---------------------------------------------------------------------------

step "Setting user notes and KYC"

admin_put "/users/${ALICE_USER_ID}" \
    '{"note":"Alice (Alpha Corp, deployer)","kyc":true}' > /dev/null
ok "Alice: note + KYC set"

admin_put "/users/${BOB_USER_ID}" \
    '{"note":"Bob (Alpha Corp, reader)","kyc":true}' > /dev/null
ok "Bob: note + KYC set"

admin_put "/users/${CHARLIE_USER_ID}" \
    '{"note":"Charlie (Beta Inc, deployer)","kyc":true}' > /dev/null
ok "Charlie: note + KYC set"

admin_put "/users/${DAVE_USER_ID}" \
    '{"note":"Dave (no org, anonymous)","kyc":false}' > /dev/null
ok "Dave: note set (no KYC)"

# ---------------------------------------------------------------------------
# Step 8: Create disclosure (Alice grants disclosure to Bob)
# ---------------------------------------------------------------------------

step "Creating disclosure request (Alice -> Bob)"

# Create a disclosure request from Bob to view Alice's data
DISCLOSURE_RESP=$(admin_post "/disclosure/requests" \
    "{\"requester_user_id\":\"$BOB_USER_ID\",\"target_user_id\":\"$ALICE_USER_ID\",\"reason\":\"Team collaboration - test setup\",\"legal_basis\":\"consent\",\"scope\":{\"addresses\":true,\"transactions\":true,\"balances\":true}}")

DISCLOSURE_REQ_ID=$(echo "$DISCLOSURE_RESP" | jq -r '.id // empty')
if [[ -n "$DISCLOSURE_REQ_ID" ]]; then
    ok "Disclosure request created ($DISCLOSURE_REQ_ID)"

    # Alice approves the request
    APPROVE_RESP=$(curl -sf -X POST \
        -H "Authorization: Bearer $ALICE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"grant_duration_hours":720,"reason":"Approved for team collaboration"}' \
        "${PROXY_URL}/api/v1/me/disclosure/requests/${DISCLOSURE_REQ_ID}/approve" 2>/dev/null)

    if echo "$APPROVE_RESP" | jq -e '.grant' > /dev/null 2>&1; then
        ok "Alice approved disclosure to Bob"
    else
        warn "Disclosure approval may have failed: $APPROVE_RESP"
    fi
else
    warn "Disclosure request creation failed (may already exist): $DISCLOSURE_RESP"
fi

# ---------------------------------------------------------------------------
# Step 9: ETH transfers between accounts (directly on Anvil)
# ---------------------------------------------------------------------------

step "Making ETH transfers between accounts"

# Alice sends 1 ETH to Bob
info "Alice -> Bob: 1 ETH"
cast send --private-key "$ALICE_KEY" "$BOB_ADDR" --value 1ether --rpc-url "$ANVIL_URL" > /dev/null 2>&1
ok "Alice -> Bob: 1 ETH"

# Bob sends 0.5 ETH to Charlie
info "Bob -> Charlie: 0.5 ETH"
cast send --private-key "$BOB_KEY" "$CHARLIE_ADDR" --value 0.5ether --rpc-url "$ANVIL_URL" > /dev/null 2>&1
ok "Bob -> Charlie: 0.5 ETH"

# Charlie sends 0.1 ETH to Dave
info "Charlie -> Dave: 0.1 ETH"
cast send --private-key "$CHARLIE_KEY" "$DAVE_ADDR" --value 0.1ether --rpc-url "$ANVIL_URL" > /dev/null 2>&1
ok "Charlie -> Dave: 0.1 ETH"

# Dave sends 0.01 ETH to Alice
info "Dave -> Alice: 0.01 ETH"
cast send --private-key "$DAVE_KEY" "$ALICE_ADDR" --value 0.01ether --rpc-url "$ANVIL_URL" > /dev/null 2>&1
ok "Dave -> Alice: 0.01 ETH"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

step "Setup complete!"

echo ""
echo -e "${GREEN}Test identities created:${NC}"
echo ""
printf "  %-10s %-20s %-44s %s\n" "Name" "DID" "Address" "Role"
printf "  %-10s %-20s %-44s %s\n" "----" "---" "-------" "----"
printf "  %-10s %-20s %-44s %s\n" "Alice"   "$ALICE_DID"   "$ALICE_ADDR"   "Alpha Corp deployer"
printf "  %-10s %-20s %-44s %s\n" "Bob"     "$BOB_DID"     "$BOB_ADDR"     "Alpha Corp reader"
printf "  %-10s %-20s %-44s %s\n" "Charlie" "$CHARLIE_DID" "$CHARLIE_ADDR" "Beta Inc deployer"
printf "  %-10s %-20s %-44s %s\n" "Dave"    "$DAVE_DID"    "$DAVE_ADDR"    "No org (anonymous)"
echo ""
echo -e "${CYAN}Disclosure:${NC} Bob can view Alice's data"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "  1. Open the login page in the browser"
echo "  2. Test identities appear in the 'Development Only' section"
echo "  3. Click a name to instantly log in as that identity"
echo ""
