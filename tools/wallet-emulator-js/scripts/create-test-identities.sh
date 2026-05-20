#!/usr/bin/env bash
# Create a fixed set of named test identities (Alice, Bob, Carol, Dave, Eve)
# DETERMINISTICALLY: seed = sha256("privacy-proxy-staging:<name>"). Same seed
# everywhere → same DID everywhere, so devs / QA see the same five users on
# any staging environment without having to share key files out-of-band.
#
# Idempotent + self-healing: existing files are inspected and only rewritten
# if their persisted seed has drifted from what the deterministic derivation
# now produces.
#
# SECURITY: these JSON files are intentionally committed to git. Anyone with
# repo access can impersonate Alice/Bob/etc. on environments that recognise
# these DIDs. Acceptable for staging test accounts; never grant these
# identities admin / deploy / upgrade claims, and never reuse them in
# production.
#
# Usage:   ./scripts/create-test-identities.sh [OUT_DIR]
# Default: ./identities
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$ROOT/identities}"

mkdir -p "$OUT_DIR"

NAMES=(alice bob carol dave eve)
PREFIX="privacy-proxy-staging"

derive_seed() {
  # sha256("$PREFIX:$1") → 64 hex chars (32 bytes).
  printf '%s:%s' "$PREFIX" "$1" | shasum -a 256 | awk '{print $1}'
}

printf "%-7s %-12s %s\n" "name" "file" "did"
printf "%-7s %-12s %s\n" "----" "----" "---"

for name in "${NAMES[@]}"; do
  out="$OUT_DIR/$name.json"
  expected_seed=$(derive_seed "$name")
  regenerate=1
  if [[ -f "$out" ]]; then
    current_seed=$(python3 -c "import json,sys; d=json.load(open('$out')); print(d.get('wallet_state',{}).get('babyjub_seed_hex',''))" 2>/dev/null || true)
    if [[ "$current_seed" == "$expected_seed" ]]; then
      regenerate=0
    fi
  fi
  if (( regenerate )); then
    rm -f "$out"
    (cd "$ROOT" && WALLET_EMULATOR_SEED_HEX="$expected_seed" npx tsx src/main.ts identity init --out "$out" >/dev/null)
  fi
  did=$(python3 -c "import json,sys; print(json.load(open('$out'))['did'])")
  printf "%-7s %-12s %s\n" "$name" "$name.json" "$did"
done

echo
echo "Identities directory: $OUT_DIR"
echo "Files committed to git (these are staging-only test accounts; see script header)."
echo
echo "Authenticate one of them (JWT goes to stdout, logs to stderr):"
echo "  PROXY_URL=https://your-staging-proxy.example.com ./scripts/auth-as.sh alice"
echo
echo "Or run the full pipeline (circuits + identities + auth all 5) from the repo root:"
echo "  make staging-test-accs PROXY_URL=https://your-staging-proxy.example.com"
