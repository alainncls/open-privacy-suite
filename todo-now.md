# TODO Now

Work through these items one at a time.

## High Priority

- [x] Implement API versioning - Add /v1/ prefix to all API endpoints with backwards compatibility (already done: /api/v1/* routes with /api/* legacy + deprecation headers)
- [x] Add access token revocation checking - Check access tokens against revocation list, not just refresh tokens (implemented: /revoke now accepts optional access_token param)

## High Priority (Pre-Audit)

- [ ] **Admin dashboard has no authentication** — anyone who can reach the frontend URL gets full admin access. `ADMIN_API_TOKEN` is embedded in the frontend (visible in DevTools) so it provides no real protection for browser-based access. Prividium (zkSync) solves this by requiring the same Okta/SIWE login for admins as for regular users, with an admin role in the RBAC system. Suggested fix: require a valid JWT with a superadmin/`is_org_admin` flag for admin API calls from the browser; keep `ADMIN_API_TOKEN` as a machine-to-machine token for scripts/CI/explorer backend only; protect the admin dashboard URL at the network level (VPN or firewall) in production deployments.

## Medium Priority

- [x] Standardize error message format - Create consistent error message patterns across handlers (documented conventions in http_responses.go, refactored eth_link.go as example)
- [x] Add missing unit tests for eth_link.go - Add comprehensive tests for ETH address linking (added 16 tests in eth_link_test.go)
- [x] Add coverage enforcement in CI - Set minimum coverage threshold that fails the build (added .github/workflows/ci.yml with 45% threshold, Makefile target test-coverage-check)
- [x] Refactor pre-commit hooks - Use husky + lint-staged for faster, targeted pre-commit checks (added root package.json with husky+lint-staged, .husky/pre-commit)
