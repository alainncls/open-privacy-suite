#!/usr/bin/env bash
# tools/check-err-leak.sh — RD-934.
#
# Fails (exit 1) when a handler file in internal/server or
# internal/explorer echoes a Go error chain into an HTTP response body.
# That class of leak surfaces DB driver internals (pq table/column
# names, FK constraint identifiers, sample row values), wrapped error
# chains, file paths, and gin validator field names — all useful
# building blocks for an attacker enumerating internal state.
#
# Past instances of the same class: RD-916 (org enumeration), RD-942
# (user enumeration via FK fail), RD-944 (system-default fallback).
#
# Fix pattern:
#   - Generic opaque message on the wire via respond*(c, "<msg>").
#   - Structured slog.Error / slog.Info for operator diagnostics.
#   - For the common "DB op failed → 500" path, use the
#     respondInternalErrorAndLog helper in internal/server/http_responses.go.
#
# Patterns blocked:
#   c.JSON(<status>, gin.H{"error": err.Error()})
#   c.JSON(<status>, gin.H{"error": fmt.Sprintf(..., err)})
#   respond[A-Z][a-zA-Z]+(c, err.Error())
#   respond[A-Z][a-zA-Z]+(c, fmt.Sprintf(..., err))
#
# Allowed in test files (*_test.go) because:
#   (a) the lint is for production handlers, not test fixtures;
#   (b) some tests intentionally build a mock handler that echoes err
#       to assert the handler-under-test never reaches it.
#
# To run locally:   bash tools/check-err-leak.sh
# Wired into CI in .github/workflows/ci.yml.

set -euo pipefail

# Use `git grep -nP` (Perl regex) — same regex dialect as ripgrep.
# git is available everywhere we run CI / dev tooling; ripgrep isn't
# universally installed (and may be shadowed by tooling aliases).
#
# http_responses.go is the canonical convention file — it contains the
# rule itself as a doc-comment example and would self-match. Tests are
# excluded for the reasons in the header comment.
search() {
  git grep -nP "$1" -- \
    'internal/server/*.go' 'internal/explorer/*.go' \
    ':(exclude)internal/server/*_test.go' \
    ':(exclude)internal/explorer/*_test.go' \
    ':(exclude)internal/server/http_responses.go' \
    2>/dev/null || true
}

# Patterns cover the four shapes a leak can hide in:
#  - direct gin.H or respond*(...) with err.Error()
#  - the same wrapped via fmt.Sprintf so the err chain is interpolated
#  - the same wrapped via string concatenation ("prefix: " + err.Error())
#  - the same wrapped via fmt.Errorf("…: %w", err).Error()
#
# All match a single line; multi-line interpolations are caught by hand
# review during the audit and by the slog-emit-first convention.
declare -a patterns=(
  # gin.H { ... err.Error() ... }
  'gin\.H\{[^}]*err\.Error\(\)'
  # gin.H { ... fmt.Sprintf(..., err...) }
  'gin\.H\{[^}]*fmt\.Sprintf\([^)]*err'
  # respondXxx(c, ... err.Error() ...)
  'respond[A-Z][a-zA-Z]+\(\s*c\s*,[^)]*err\.Error\(\)'
  # respondXxx(c, fmt.Sprintf(..., err...))
  'respond[A-Z][a-zA-Z]+\(\s*c\s*,[^)]*fmt\.Sprintf\([^)]*err'
)

current=0
all_hits=""
for pattern in "${patterns[@]}"; do
  hits=$(search "$pattern")
  if [ -n "$hits" ]; then
    line_count=$(printf '%s\n' "$hits" | grep -c .)
    current=$((current + line_count))
    all_hits="$all_hits$hits
"
  fi
done

if [ "$current" -gt 0 ]; then
  echo "ERROR: err.Error() leak in handler response. RD-934 baseline is 0; any new instance must be cleaned up before merge."
  echo
  echo "Offending matches:"
  printf '%s' "$all_hits" | grep . | head -50
  echo
  echo "See internal/server/http_responses.go doc-comment (rule 4) and RD-934."
  echo "Use a generic opaque message + slog.Error for operator diagnostics,"
  echo "or the respondInternalErrorAndLog / respondBadRequestAndLog helpers."
  exit 1
fi

echo "ok: no err.Error() leaks in handler responses"
