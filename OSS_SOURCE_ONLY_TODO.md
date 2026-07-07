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
- [x] Align project-owned Solidity SPDX identifiers with Apache-2.0.
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

## Prompts To Run Next

Use these prompts as task briefs. Each prompt should produce either a focused PR or a written decision record.

### Legal notice, security contact, and inbound policy

```text
Take the current OSS readiness branch for gateway-fm/privacy-proxy. Verify the public source-only Apache-2.0 legal artifacts: LICENSE, NOTICE, SECURITY.md, CONTRIBUTING.md, CODE_OF_CONDUCT.md, GOVERNANCE.md, README license text, and package metadata. Confirm the correct copyright holder, security contact, and inbound contribution posture. Make only minimal public-source-readiness edits and list any remaining legal decisions that require counsel.
```

### Gateway sibling repositories

```text
Audit gateway-fm/chain-indexer and gateway-fm/block-explorer for source-only Apache-2.0 publication readiness. Check LICENSE, NOTICE, README license text, package metadata, third-party notices, generated code provenance, secrets, private links, CI behavior for public forks, and image/binary release blockers. Produce a short blocker list and minimal PR-ready fixes.
```

### Wallet emulator submodule decision

```text
Determine whether gateway-fm/wallet-emulator-js can be made public under an Apache-compatible license before privacy-proxy is public. If yes, prepare the minimum license/notice/metadata changes in that repo. If no, prepare a privacy-proxy PR that removes or replaces the submodule and updates docs/tests that refer to it.
```

### Public-fork CI hardening

```text
Review .github/workflows/privacy-bypass.yml and any cross-repo CI assumptions for public-fork safety. Make the workflow skip or clearly gate private sibling-repo checkouts when CROSS_REPO_READ_TOKEN is unavailable, while preserving manual/internal coverage. Keep changes minimal and document how maintainers should run the full privacy-mode test.
```

### Public docs and internal-reference scrub

```text
Scan README.md, docs/, site/, .github/, scripts/, and tracked config for private Linear URLs, internal roadmap language, and unnecessary RD-XXXX references. Do not remove useful technical context. Propose or make low-risk wording changes that make the repo public-friendly, and leave a separate list of references that should stay because they are migrations, tests, or useful historical identifiers.
```

### Binary and container release licensing

```text
Prepare the pre-release compliance plan for official binaries and Docker images. Generate or specify SBOMs for Go, npm, Solidity, submodules, and container base images. Identify LGPL/GPL/MPL/CC obligations, especially go-ethereum and native rapidsnark, and update THIRD_PARTY_NOTICES.md with scanner-backed data. Do not publish images or binaries as part of this task.
```

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
