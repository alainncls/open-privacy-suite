# TODO Now

Work through these items one at a time.

## High Priority

- [x] Implement API versioning - Add /v1/ prefix to all API endpoints with backwards compatibility (already done: /api/v1/* routes with /api/* legacy + deprecation headers)
- [x] Add access token revocation checking - Check access tokens against revocation list, not just refresh tokens (implemented: /revoke now accepts optional access_token param)

## Medium Priority

- [x] Standardize error message format - Create consistent error message patterns across handlers (documented conventions in http_responses.go, refactored eth_link.go as example)
- [x] Add missing unit tests for eth_link.go - Add comprehensive tests for ETH address linking (added 16 tests in eth_link_test.go)
- [x] Add coverage enforcement in CI - Set minimum coverage threshold that fails the build (added .github/workflows/ci.yml with 45% threshold, Makefile target test-coverage-check)
- [x] Refactor pre-commit hooks - Use husky + lint-staged for faster, targeted pre-commit checks (added root package.json with husky+lint-staged, .husky/pre-commit)
