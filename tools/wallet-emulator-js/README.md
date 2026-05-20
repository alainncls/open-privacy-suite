# Wallet emulator - Track A (Node.js)

Headless iden3 wallet built on the published `@0xpolygonid/js-sdk`. Same
job as `tools/wallet-emulator/` (Track B, Go) - generates a real
AuthV2 ZK proof the prod-built proxy verifier accepts, no phone or QR
scan required. We ship both tracks because each has different
trade-offs:

- **Track A (this dir, RD-948)** - published SDK, with persistent BJJ
  seed handled here in the wrapper (the SDK doesn't ship a
  filesystem-backed key store).
- **Track B (`tools/wallet-emulator/`, RD-947)** - Go-native, same
  toolchain as the proxy; no Node dependency in CI. Circuit
  artifact-pinning still TODO there.

## Status

| Capability | Status |
|---|---|
| `identity init` - create + persist a Privado mainnet identity | Done |
| `identity show` - print DID + state from the persisted file | Done |
| Persistent BJJ seed restore (same DID + state across runs) | Done |
| `auth` flow end-to-end - JWZ generation + `/auth/verify` POST | Done |
| `auth --callback` - production-style `/auth/callback?session=<id>` | Done |
| Circuit-artifact dir (`--artifacts`, default `~/.privado-circuits`) | Done |

## Quick start

```bash
# 1. Install (Node >= 20)
cd tools/wallet-emulator-js
npm ci

# 2. Create a fresh identity. Offline - no network calls.
npx tsx src/main.ts identity init --out /path/to/wallet.json

# 3. Register the (DID, state) pair on the Privado mainnet state
#    contract. See "On-chain registration" below. Until this is done
#    the proxy will reject every JWZ this wallet produces with
#    "state not found" from the resolver.

# 4. Download the AuthV2 circuit artifacts (one-time setup):
mkdir -p ~/.privado-circuits
cd ~/.privado-circuits
curl -LO https://circuits.privado.id/latest.zip
unzip latest.zip       # produces ./authV2/{circuit.wasm,circuit_final.zkey,verification_key.json}

# 5. Authenticate. The JWT is printed to stdout; all logs go to stderr.
npx tsx src/main.ts auth \
  --proxy https://staging-proxy.example.com \
  --identity /path/to/wallet.json \
  --artifacts ~/.privado-circuits
```

For a production-style mobile-wallet flow that POSTs to
`/auth/callback?session=<id>` instead of `/auth/verify`, pass
`--callback`:

```bash
npx tsx src/main.ts auth \
  --proxy https://prod-proxy.example.com \
  --identity /path/to/wallet.json \
  --callback
```

## CLI reference

```
wallet-emulator-js identity init --out <file>
wallet-emulator-js identity show --identity <file>
wallet-emulator-js auth
    --proxy <url>            # required
    --identity <file>        # required
    --state-rpc <url>        # optional; default https://rpc-mainnet.privado.id
    --artifacts <dir>        # optional; default ~/.privado-circuits
    --callback               # optional; use /auth/callback instead of /auth/verify
```

## On-chain registration

Same lifecycle as Track B - the proxy verifier checks the identity's
state against the Privado state contract
(`0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896`, mainnet). Until you
publish the `(DID, state)` pair on-chain, the proxy rejects every JWZ
this wallet produces with a state-not-found error from the resolver.

The emulator does NOT publish state for you. Two options:

1. Use the Privado web onboarding flow (recommended for staging
   smoke tests).
2. Call `transitState` on the iden3 state contract directly with an
   EOA you control. The SDK exposes a `transitState` helper on
   `ProofService` if you want to script it.

## Circuit artifacts

The AuthV2 circuit needs three files at the path you pass to
`--artifacts` (default `~/.privado-circuits`):

```
<artifacts-dir>/
  authV2/
    circuit.wasm
    circuit_final.zkey
    verification_key.json
```

The canonical zip lives at <https://circuits.privado.id/latest.zip>
(referenced from the `@0xpolygonid/js-sdk` README). Pin the version
in your CI by mirroring the zip into your artifact store and
hash-verifying.

## Security

- The persisted identity file contains a 32-byte BabyJubJub seed in
  plaintext. The seed is the identity. Anyone with the file can
  produce JWZs the proxy will accept as that DID.
- `identity init` writes the file with mode 0600. Keep it there: do
  NOT loosen permissions, do NOT commit (`*identity*.json` is in
  `.gitignore`), do NOT email it.
- Store the file in a secret manager - AWS Secrets Manager via
  IRSA/CSI Driver is the org-standard. The CI pipeline should pull
  the file at runtime, never bake it into an image.
- Do not reuse one identity across staging and prod. Generate one per
  environment and register each on the corresponding state contract.
- The emulator is operator / CI tooling - no privileged path on the
  proxy. Every JWZ goes through the same `PrivadoVerifier.FullVerify`
  as a real mobile-wallet JWZ. No build flag, env var, or runtime
  knob disables the verifier.

## File layout

```
tools/wallet-emulator-js/
  README.md             # this file
  package.json          # SDK + commander; engines.node >= 20
  package-lock.json     # pinned for CI reproducibility
  tsconfig.json         # ES2022, strict, NodeNext module resolution
  .gitignore            # node_modules/, dist/, *identity*.json
  src/
    main.ts             # commander CLI dispatcher
    identity.ts         # IdentityWallet + persistence (BJJ seed)
    auth.ts             # AuthHandler orchestrator (real)
    client.ts           # HTTP for /auth/request + /auth/verify + /auth/callback
  dist/                 # tsc output, gitignored
```

## Track A vs Track B - which to use

- **Track A** (this dir): published SDK, persistence DIY in this
  wrapper (32-byte BJJ seed only). Recommended for CI integration
  today - it's the only track with the full auth flow shipped.
- **Track B** (`tools/wallet-emulator/`): Go-native, same toolchain
  as the proxy; no Node dependency. Circuit artifact pinning still
  TODO. Recommended once that lands and the team decides which
  track to keep long-term.

## References

- `@0xpolygonid/js-sdk`: <https://github.com/0xPolygonID/js-sdk>
- Circuit artifacts: <https://circuits.privado.id/latest.zip>
- Track B counterpart: `tools/wallet-emulator/README.md`
- Tracking issue: RD-948
