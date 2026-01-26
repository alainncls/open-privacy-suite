#!/bin/bash
#
# Setup git hooks for the project
# Run this once after cloning the repo
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Setting up git hooks..."

# Option 1: Use core.hooksPath (recommended - hooks are in version control)
git config core.hooksPath scripts/hooks
echo "✓ Configured git to use scripts/hooks directory"

# Make sure hooks are executable
chmod +x "$SCRIPT_DIR/hooks/"* 2>/dev/null

echo ""
echo "Done! Git hooks are now active."
echo ""
echo "Hooks will run automatically:"
echo "  - pre-push: Runs unit tests, frontend tests, and e2e tests before push"
echo ""
echo "To skip hooks (emergency): git push --no-verify"
