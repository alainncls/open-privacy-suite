#!/usr/bin/env bash
# Create a fixed set of named test identities (Alice, Bob, Carol, Dave, Eve)
# and print their DIDs. Idempotent: existing files are reused, not overwritten,
# so re-running this preserves keys across runs.
#
# Usage:   ./scripts/create-test-identities.sh [OUT_DIR]
# Default: ./identities
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$ROOT/identities}"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true

NAMES=(alice bob carol dave eve)

printf "%-7s %-12s %s\n" "name" "file" "did"
printf "%-7s %-12s %s\n" "----" "----" "---"

for name in "${NAMES[@]}"; do
  out="$OUT_DIR/$name.json"
  if [[ ! -f "$out" ]]; then
    (cd "$ROOT" && npx tsx src/main.ts identity init --out "$out" >/dev/null)
  fi
  did=$(python3 -c "import json,sys; print(json.load(open('$out'))['did'])")
  printf "%-7s %-12s %s\n" "$name" "$name.json" "$did"
done

echo
echo "Identities directory: $OUT_DIR"
echo "Files are mode 0600 (contain BabyJub seeds); the directory is mode 0700."
echo
echo "Auth as one of them:"
echo "  npx tsx src/main.ts auth \\"
echo "    --proxy https://your-proxy.example.com \\"
echo "    --identity $OUT_DIR/alice.json \\"
echo "    --artifacts ~/.privado-circuits \\"
echo "    --callback"
