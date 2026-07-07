# Source-Only Apache-2.0 Readiness TODO

This checklist consolidates `OSS_AUDIT-GPT.md` and `OSS_AUDIT_GLM.md` into the fastest path for publishing source under Apache-2.0 while holding official binaries/images until SBOM, notices, and LGPL binary-distribution review are complete.

## Done On `oss/source-only-apache2-readiness`

- [x] Add root Apache-2.0 `LICENSE`.
- [x] Change `README.md` license section from MIT to Apache-2.0.
- [x] Add `license: Apache-2.0` to npm package manifests.
- [x] Add starter `NOTICE`.
- [x] Add starter `THIRD_PARTY_NOTICES.md`.
- [x] Add `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `GOVERNANCE.md`.
- [x] Ignore internal audit report filenames so they are not accidentally committed.
- [x] Switch `tools/wallet-emulator-js` submodule URL from SSH to public HTTPS.
- [x] Remove accidental `.agents` gitlink on the base hygiene branch.

## Must Finish Before Making The Source Repo Public

- [ ] Confirm legal copyright holder text for `NOTICE`.
- [ ] Confirm private vulnerability contact in `SECURITY.md`.
- [ ] Publish or coordinate `gateway-fm/chain-indexer` under Apache-2.0.
- [ ] Publish or coordinate `gateway-fm/block-explorer` under Apache-2.0.
- [ ] Decide whether `gateway-fm/wallet-emulator-js` is public Apache-2.0; otherwise remove/replace the submodule.
- [ ] Make `.github/workflows/privacy-bypass.yml` safe for public forks without `CROSS_REPO_READ_TOKEN`, or disable it for public PRs until sibling repos are public.
- [ ] Scrub public docs for private Linear URLs and internal roadmap wording.
- [ ] Decide whether to keep `RD-XXXX` references outside migrations or strip them in a mechanical follow-up.
- [ ] Decide whether to keep `.mcp.json` tracked publicly or move it to an example file.
- [ ] Decide git-history email posture: accept as normal OSS attribution or rewrite before public launch.
- [ ] Confirm inbound contribution policy: DCO is documented; add CI enforcement if required.

## Before First Official Binary/Image Release

- [ ] Generate complete SBOMs for source, binaries, and container images.
- [ ] Run Go/npm/Solidity/container license scans and update `THIRD_PARTY_NOTICES.md`.
- [ ] Resolve go-ethereum LGPL-3.0 binary/container distribution obligations.
- [ ] Verify whether iden3 rapidsnark LGPL native code is linked/bundled/loaded in release binaries.
- [ ] Publish source-to-image mapping for each image tag.
- [ ] Sign images/artifacts and publish checksums/provenance.

## Explicitly Deferred For Minimal Source-Only Launch

- [ ] Go module path rename from `privacy-proxy` to public import path.
- [ ] Per-file SPDX headers across Go/TS/TSX.
- [ ] Removing unused dependencies such as indirect Sentry if still present after `go mod tidy`.
- [ ] Production Docker/compose hardening beyond obvious public-source blockers.
