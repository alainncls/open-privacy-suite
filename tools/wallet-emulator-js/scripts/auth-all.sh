#!/usr/bin/env bash
# Authenticate all five named test identities against the staging proxy
# and print a name → DID table. Mostly a sanity check that lets you see at
# a glance that every test account can still mint a JWT.
#
# To capture an actual JWT for use, run scripts/auth-as.sh <name> instead.
#
# Env:   PROXY_URL              (default in auth-as.sh: staging devnet proxy)
#        PRIVADO_CIRCUITS_DIR   (default: ~/.privado-circuits)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMES=(alice bob carol dave eve)

# Proxy rate-limits /auth/request — pacing between users keeps the bulk
# table reliable. PROXY_AUTH_GAP_S override is exposed for environments
# with tighter or looser limits.
AUTH_GAP_S="${PROXY_AUTH_GAP_S:-6}"

printf "%-7s %s\n" "name" "did"
printf "%-7s %s\n" "----" "---"
first=1
for name in "${NAMES[@]}"; do
  if (( ! first )); then sleep "$AUTH_GAP_S"; fi
  first=0
  err_file=$(mktemp -t auth-all.XXXXXX.err)
  if jwt=$("$SCRIPT_DIR/auth-as.sh" "$name" 2>"$err_file"); then
    did=$(printf '%s' "$jwt" | cut -d. -f2 | base64 -d 2>/dev/null \
          | python3 -c "import json,sys; print(json.load(sys.stdin)['sub'])")
    printf "%-7s %s\n" "$name" "$did"
  else
    last_err=$(tail -1 "$err_file" 2>/dev/null || true)
    printf "%-7s FAILED — %s\n" "$name" "${last_err:-(no error captured; rerun auth-as.sh $name)}"
  fi
  rm -f "$err_file"
done
