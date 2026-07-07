# Third-Party Notices

This is a starter notice file for a source-only Apache-2.0 publication. It is
not a complete SBOM and must be regenerated before official binary or container
artifacts are published.

## Source-Only Scope

The initial public release should publish source only. Official Docker images
and compiled binaries should remain unpublished until full SBOMs, provenance,
and binary-distribution license obligations are complete.

## Notable Go Dependencies

- `github.com/ethereum/go-ethereum`
  - License: LGPL-3.0 for library packages; GPL-3.0 for upstream `cmd`
    binaries.
  - Use in this repository: Ethereum ABI, address/hash helpers, signature
    handling, ENS helpers, transaction types, and related tooling.
  - Source-only publication is acceptable with notice. Official binary/image
    distribution requires legal review and a documented LGPL compliance plan.

- `github.com/iden3/go-rapidsnark/...`
  - The Go wrapper modules are understood to be Apache-2.0/MIT.
  - The native `iden3/rapidsnark` project is an LGPL-3.0 review item.
  - Before binary/image publication, verify whether release binaries link,
    bundle, or dynamically load LGPL native rapidsnark code.

- `github.com/iden3/*`
  - Used for Privado/iden3 authentication, DID, JWZ, and proof verification
    flows.
  - Track exact licenses in the generated SBOM.

## npm Dependencies

The checked lockfiles are mostly MIT, ISC, BSD-family, or Apache-2.0. Notable
notice items from the lockfiles include:

- MPL-2.0 packages such as EthereumJS packages and `webextension-polyfill`.
- `dompurify` under `(MPL-2.0 OR Apache-2.0)`; prefer the Apache-2.0 option
  for this project where permitted.
- `caniuse-lite` under CC-BY-4.0.
- BlueOak-1.0.0, Python-2.0, Unlicense, and CC0-1.0 entries.

## Solidity and Submodules

- OpenZeppelin Contracts and OpenZeppelin Contracts Upgradeable are expected
  to be MIT-licensed.
- forge-std is expected to be Apache-2.0/MIT.
- Solady is expected to be MIT-licensed.
- `tools/wallet-emulator-js` must either be published under an
  Apache-compatible license or removed/replaced before public release.

## Gateway Repositories In The Coordinated Release

- `gateway-fm/privacy-proxy`
- `gateway-fm/chain-indexer`
- `gateway-fm/block-explorer`
- `gateway-fm/wallet-emulator-js` if retained as a submodule

Each repository and any related images should publish its own LICENSE, NOTICE,
third-party notices, SBOM, and source-to-image mapping.

## Required Follow-Up

- Generate a complete dependency license report for Go modules, npm packages,
  Solidity dependencies, generated code, submodules, and container base images.
- Replace this starter file with a scanner-backed notice file before the first
  official release artifact.
