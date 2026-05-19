# Wallet emulator — Track A (Node.js)

Headless iden3 wallet built on the published `@0xpolygonid/js-sdk`. Same job
as `tools/wallet-emulator/` (Track B, Go) — generates real ZK proofs the
prod-built proxy verifier accepts, no phone or QR scan required. We ship
both tracks because each has different trade-offs:

- **Track A (this dir, RD-948)** — leans on the SDK's working holder
  primitives. Far less custom code; quicker to a JWT.
- **Track B (`tools/wallet-emulator/`, RD-947)** — Go-native, same
  toolchain as the proxy; no Node dependency in CI.

Operators pick whichever fits the workflow.

## Status (Phase A-1a — scaffolding)

| Capability | Status |
|---|---|
| `identity init` — create + persist a wallet via `IdentityWallet.createIdentity()` | **Done** (real DID + state) |
| `identity show` — print DID + state from the persisted file | **Done** |
| HTTP client for `/auth/request` + `/auth/verify` | **Done** |
| Persistent BabyJubJub seed restore (rehydrate KMS across runs) | **TODO (Phase A-1b)** |
| `auth` flow end-to-end — `AuthHandler.handleAuthorizationRequest` + post to `/auth/verify` | **TODO (Phase A-1b)** |
| `make wallet-emulator-js-smoke` target | **TODO (Phase A-1b)** |

Phase A-1a wires the structure and the SDK boilerplate. Phase A-1b finishes
the persistent-KMS hookup so the `auth` subcommand can rehydrate the wallet
and call `AuthHandler` against the auth request.

## Quick start

```bash
cd tools/wallet-emulator-js
npm ci
npm run cli -- identity init --out /tmp/test-id.json

# Output:
#   Created identity:
#     DID:   did:iden3:privado:main:...
#     State: 0x...
#     File:  /tmp/test-id.json (mode 0600)

npm run cli -- identity show --identity /tmp/test-id.json

# After Phase A-1b:
npm run cli -- auth --proxy https://staging-proxy.example.com --identity /tmp/test-id.json
# Stdout: eyJhbGciOi…   <- the access JWT
```

## On-chain registration

Same lifecycle as Track B — the proxy verifier checks the identity's
state against the Privado state contract. Until you publish the
`(DID, state)` pair on-chain, the proxy rejects every JWZ this wallet
produces with a state-not-found error from the resolver.

See `tools/wallet-emulator/README.md` → "On-chain registration" for the
details — the lifecycle is identical regardless of which emulator
generated the identity.

## Security

- The identity JSON file contains a private key. Mode 0600 on creation;
  store in a secret manager (AWS Secrets Manager via IRSA recommended);
  never check in.
- The emulator is operator / CI tooling — no privileged path on the
  proxy. Every JWZ goes through the same `PrivadoVerifier.FullVerify`
  as a real mobile-wallet JWZ. No build flag, env var, or runtime knob
  disables the verifier.
- Do not reuse one identity across staging and prod. Generate one per
  environment, register each on the corresponding state contract.
- The `@0xpolygonid/js-sdk` runtime dependency is third-party. Pin the
  major version in `package.json` and keep `package-lock.json` in
  source control once Phase A-1b lands (Phase A-1a leaves it
  gitignored because there's no functional lockfile yet).

## File layout

```
tools/wallet-emulator-js/
├── README.md         # this file
├── package.json      # SDK + commander only; engines.node >= 20
├── tsconfig.json     # ES2022, strict, NodeNext module resolution
├── .gitignore        # node_modules/, dist/, *identity*.json
├── src/
│   ├── main.ts       # commander CLI dispatcher
│   ├── identity.ts   # IdentityWallet + persistence
│   ├── auth.ts       # AuthHandler orchestrator (stub for Phase A-1b)
│   └── client.ts     # HTTP for /auth/request + /auth/verify
└── dist/             # tsc output, gitignored
```

## Track A vs Track B — which to use

- **Track A**: fastest path to a working smoke test. Recommended for
  CI integration as soon as Phase A-1b lands.
- **Track B**: same Go toolchain as the proxy; no Node dependency.
  Recommended for proxy developers who want to debug iden3 internals
  without a JS context switch.

If you're picking one — start with **A**. Switch if/when the Track B
binary catches up in maturity and the team decides to retire the JS
emulator.

## References

- `@0xpolygonid/js-sdk`: <https://github.com/0xPolygonID/js-sdk>
- Canonical auth-flow pattern to follow: `tests/handlers/auth.test.ts`
  in the SDK repo.
- Track B counterpart: `tools/wallet-emulator/README.md`.
- Tracking issue: RD-948.
