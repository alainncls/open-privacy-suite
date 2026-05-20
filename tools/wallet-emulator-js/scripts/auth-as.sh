#!/usr/bin/env bash
# Authenticate as a named test identity and print the JWT to stdout.
# Status / log lines go to stderr so the caller can capture only the token:
#   PROXY_URL=https://your-proxy.example.com ./scripts/auth-as.sh alice
#   JWT=$(PROXY_URL=https://your-proxy.example.com ./scripts/auth-as.sh alice)
#
# Tokens are short-lived (~5 min). Re-run this when the previous token expires.
#
# Usage:   ./scripts/auth-as.sh <name>
# Env:     PROXY_URL              (required — no default; environment-specific)
#          PRIVADO_CIRCUITS_DIR   (default: ~/.privado-circuits)
set -euo pipefail

NAME="${1:?usage: auth-as.sh <name>  (one of: alice bob carol dave eve)}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IDENT="$ROOT/identities/$NAME.json"

if [[ -z "${PROXY_URL:-}" ]]; then
  echo "auth-as: PROXY_URL must be set." >&2
  echo "         e.g. PROXY_URL=https://your-staging-proxy.example.com $0 $NAME" >&2
  exit 2
fi
PRIVADO_CIRCUITS_DIR="${PRIVADO_CIRCUITS_DIR:-$HOME/.privado-circuits}"

if [[ ! -f "$IDENT" ]]; then
  echo "auth-as: no identity at $IDENT" >&2
  echo "         run 'make staging-create-test-accs' from the repo root first" >&2
  exit 2
fi
if [[ ! -f "$PRIVADO_CIRCUITS_DIR/authV2/circuit.wasm" ]]; then
  echo "auth-as: no auth-v2 circuits at $PRIVADO_CIRCUITS_DIR/authV2/" >&2
  echo "         run 'make wallet-emulator-circuits' from the repo root first" >&2
  exit 2
fi

cd "$ROOT"
exec npx tsx src/main.ts auth \
  --proxy "$PROXY_URL" \
  --identity "$IDENT" \
  --artifacts "$PRIVADO_CIRCUITS_DIR" \
  --callback
