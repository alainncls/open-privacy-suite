# Wallet emulator

Headless iden3 wallet for testing the **prod-built** privacy-proxy in staging.
The proxy's `MOCK_SIGNATURES` / `ALLOW_MOCK_LOGIN` paths are compiled out in
prod (`-tags mockauth` only). This binary generates real iden3 ZK proofs
that pass the prod verifier — no phone, no Privado app, no QR scan.

Tracked under **RD-947**.

## Status (Phase 1a — scaffolding)

| Capability | Status |
|---|---|
| `identity init` — create a BabyJubJub keypair, derive DID + genesis state, persist to JSON | **Done** |
| `identity show` — read the JSON, print DID + state | **Done** |
| HTTP plumbing — `/auth/request` → `/auth/verify` over the proxy | **Done** |
| JWZ packing — `iden3comm.ZKPPacker` wiring with `AuthV2Groth16Alg` | **Done** |
| `prepareAuthV2Inputs` — translate the JWZ message hash + identity into auth-v2 circuit inputs | **TODO (Phase 1b)** — see `proof.go` header |
| Circuit-artifact fetcher (`make wallet-emulator-fetch-artifacts`) | **TODO (Phase 1b)** |
| Integration test against testcontainers proxy | **TODO (Phase 1b)** |

Phase 1a produces a binary that can bootstrap an identity and reach the
proxy. Phase 1b wires the proof generation so `auth` actually issues a
JWT. Splitting now because the proof-gen surface is non-trivial (it
needs a gist-tree fetcher against the on-chain state contract) and
worth its own focused review.

## Quick start

```bash
# Build
go build -o ./bin/wallet-emulator ./tools/wallet-emulator

# Create a fresh identity (one-time per environment)
./bin/wallet-emulator identity init --out ./test-identity.json

# Output:
#   Created identity:
#     DID:   did:iden3:privado:main:2SfDfyt9aCFzDQYPyVu6NgoyLHnWT1BNHAkKe7zJ6W
#     State: 0x0e9f68...
#     File:  ./test-identity.json (mode 0600)

# Print details (for sanity / re-registration)
./bin/wallet-emulator identity show --identity ./test-identity.json

# Authenticate against a proxy (after Phase 1b lands)
./bin/wallet-emulator auth \
  --proxy https://staging-proxy.example.com \
  --identity ./test-identity.json \
  --artifacts ./tools/wallet-emulator/artifacts
# Stdout: eyJhbGciOi...   <- the access JWT
```

## On-chain registration (one-time)

The proxy's verifier checks the identity's state against the Privado
state contract. A freshly-created identity has its state only in
memory — until you publish it on-chain, every JWZ this identity
produces will fail with a state-not-found error from the resolver.

The state-publish flow is **not** wired into the emulator (Phase 2 —
see RD-947's "Phase 2" section). For Phase 1, the operator publishes
once via the Privado mobile app or directly via the state contract's
`transitState` method. Use the `DID` + `State` printed by `identity init`.

State contract addresses:

- **Privado main**: `0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896` (mirrors `internal/auth/privado.go:PrivadoMainnetStateContract`)
- Staging — whichever address the staging environment's `PRIVADO_STATE_CONTRACT` is set to.

## Circuit artifacts

The auth-v2 ZK proof uses a circuit with two heavy assets:

- `authV2.wasm` — witness generator (~24 MB).
- `authV2.zkey` — groth16 proving key (~150 MB).

These come from the public Privado/Polygon ID CDN. The `Makefile`
target (Phase 1b) will `curl` them with SHA-256 verification into
`tools/wallet-emulator/artifacts/`. Both files are gitignored.

Reference URLs (pin in Makefile when wiring):

```
https://iden3-circuits-bucket.s3.eu-west-1.amazonaws.com/latest.zip
  → contains authV2/circuit.wasm and authV2/circuit_final.zkey
```

Pin to a specific release version + verify SHA-256 against published
hashes from the Polygon ID release notes. **Do not** track `latest`
in CI — a new circuit version means re-registering every identity.

## Security

- The identity JSON file **is** the wallet. Anyone with read access can
  authenticate as that DID against any environment where the state is
  registered. The file mode is `0600` on creation; store it in a
  secret manager (AWS Secrets Manager via IRSA, Vault, etc.) and
  never check it in.
- The emulator never logs the private key or the raw inputs to the
  proof. Auth-request envelopes are echoed on error for triage; the
  identity JSON path is shown but its contents are not.
- The emulator binary is operator/CI tooling. It has no privileged
  access path on the proxy — every JWZ it produces goes through the
  exact same verifier as a mobile-wallet JWZ. There is no escape
  hatch and no build flag that disables the verifier.
- Migrating identities between environments: re-running `identity
  init` always creates a fresh keypair. Reusing an identity across
  staging and prod means the prod state-publish accepts the staging
  key as well — usually NOT what you want. Generate one identity per
  environment.

## Architecture

```
identity.go     → BabyJubJub key gen, Auth claim, genesis state, DID derivation
client.go       → HTTP client for /auth/request + /auth/verify
proof.go        → ZKPPacker wiring + prepareAuthV2Inputs (TODO)
auth.go         → end-to-end orchestrator
context.go      → tiny helper
main.go         → CLI dispatcher

artifacts/      → circuit .wasm + .zkey (gitignored, populated by Makefile)
```

Build dependencies are already in the proxy's `go.mod` (no new deps):
`iden3/iden3comm`, `iden3/go-iden3-core`, `iden3/go-iden3-auth`,
`iden3/go-circuits`, `iden3/go-iden3-crypto`, `iden3/go-jwz`,
`iden3/go-rapidsnark/*`. The emulator is a separate Go binary that
imports them directly — it does **not** depend on `internal/` packages
from the proxy.

## Troubleshooting

| Symptom | Probable cause | Fix |
|---|---|---|
| `JWZ verification failed: state not found` | Identity state not registered on-chain for the chain the proxy resolver targets | Publish the state via the state contract; verify with `identity show` that you're publishing the right `(DID, state)` pair |
| `unexpected circuit ID "authV2"` | Build is using a different auth circuit version than expected | Re-run `make wallet-emulator-fetch-artifacts` with a matching pin |
| `auth-v2 input preparation not yet implemented` | Phase 1a binary — Phase 1b not landed | Wait for the follow-up PR; this is intentional |
| Multiple `--identity` files in flight | Each identity bumps the state contract → registration cost | Reuse the one canonical staging identity; rotate only when keys are compromised |
| `read .../authV2.wasm: no such file or directory` | Circuit artifacts not fetched | `make wallet-emulator-fetch-artifacts` (or manually drop the files into `tools/wallet-emulator/artifacts/`) |

## References

- `internal/auth/privado.go` — `PrivadoVerifier` (what the emulator's JWZ has to satisfy)
- `internal/server/auth.go` — `/auth/request` + `/auth/verify` endpoint shape
- [iden3 auth-v2 circuit](https://github.com/iden3/circuits) — the underlying ZK constraint set
- [iden3comm Go SDK](https://github.com/iden3/iden3comm) — `ZKPPacker`, `ProvingParams`, `DataPreparerHandlerFunc`
- Tracking issue: RD-947
