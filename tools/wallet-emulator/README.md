# Wallet emulator

Headless iden3 wallet for testing the **prod-built** privacy-proxy in staging.
The proxy's `MOCK_SIGNATURES` / `ALLOW_MOCK_LOGIN` paths are compiled out in
prod (`-tags mockauth` only). This binary generates real iden3 ZK proofs
that pass the prod verifier — no phone, no Privado app, no QR scan.

Tracked under **RD-947**.

## Status

| Capability | Status |
|---|---|
| `identity init` — create a BabyJubJub keypair, derive DID + genesis state, persist to JSON | **Done (Phase 1a)** |
| `identity show` — read the JSON, print DID + state | **Done (Phase 1a)** |
| HTTP plumbing — `/auth/request` → `/auth/verify` over the proxy | **Done (Phase 1a)** |
| JWZ packing — `iden3comm.ZKPPacker` wiring with `AuthV2Groth16Alg` | **Done (Phase 1a)** |
| `prepareAuthV2Inputs` — translate the JWZ message hash + identity into auth-v2 circuit inputs | **Done (Phase 1b)** — see `proof.go` |
| On-chain gist proof fetcher (`gist.go`) | **Done (Phase 1b)** |
| Circuit-artifact fetcher (`make wallet-emulator-fetch-artifacts`) | **Done (Phase 1b)** — SHA-256 pin pending (see Phase 1c below) |
| Integration test against testcontainers proxy | **TODO (Phase 1c)** |

## Phase 1c — outstanding follow-ups

1. **Pin circuit-artifact SHA-256 hashes.** `make wallet-emulator-fetch-artifacts`
   downloads `authV2.wasm` + `authV2.zkey` from the iden3 / Polygon ID
   public bucket and verifies SHA-256 against constants in the Makefile.
   The current values are the placeholder `TODO_PIN_SHA256` — the target
   fails by design until the real hashes are committed. To pin:
   1. Decide which release version of the circuits we ship against (the
      Privado team publishes circuit releases at
      `https://github.com/iden3/circuits/releases`).
   2. Update `WALLET_EMULATOR_WASM_URL` / `WALLET_EMULATOR_ZKEY_URL` to
      point at the pinned release asset (or keep the S3 path if that's
      what staging uses).
   3. Compute `shasum -a 256 authV2.wasm` and `shasum -a 256 authV2.zkey`
      on the downloaded files and replace `TODO_PIN_SHA256` in the
      Makefile with the real values.

2. **End-to-end testcontainers test.** This requires a decision the
   tooling alone can't make:
   - **Option A**: spin up a mock state contract (Anvil + a deterministic
     contract) and write the wallet's `(DID, state)` into it before
     running the auth flow. Cheap to run in CI but requires either
     deploying a stub state contract that matches the iden3 ABI, or a
     simplified verifier path that skips the on-chain check.
   - **Option B**: hit real Privado mainnet from CI, with one
     pre-registered staging identity whose state is published on-chain.
     Costs gas to set up (one-time) and couples CI to network
     availability, but exercises the exact path real users take.

   Phase 1c should resolve this with the user (security review wants a
   non-network test; SRE may prefer the real-Privado path for
   confidence). Until then, validation is manual against staging.

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

# Fetch circuit artifacts (one-time per environment / version pin)
make wallet-emulator-fetch-artifacts

# Authenticate against a proxy
./bin/wallet-emulator auth \
  --proxy https://staging-proxy.example.com \
  --identity ./test-identity.json \
  --artifacts ./tools/wallet-emulator/artifacts
# Stdout: eyJhbGciOi...   <- the access JWT
```

The `auth` flow:

1. POSTs `/auth/request` to the proxy, gets back a fresh challenge.
2. Re-derives the identity trees from the JSON file (claims + Auth claim
   + empty revocations / roots), computes the Poseidon state.
3. Calls `getGISTProof(id)` on the Privado state contract over RPC to
   get the inclusion / non-inclusion proof of this identity in the
   global identity state tree. Override the RPC and contract address
   with `PRIVADO_RPC_URL` / `PRIVADO_STATE_CONTRACT` env vars.
4. Signs the JWZ challenge (BabyJub Poseidon) and runs the auth-v2
   groth16 prover via go-jwz / go-rapidsnark.
5. POSTs the JWZ to `/auth/verify`, prints the issued access JWT.

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

`make wallet-emulator-fetch-artifacts` downloads them from the iden3 /
Polygon ID public bucket and verifies SHA-256 against the values pinned
in the Makefile (`WALLET_EMULATOR_WASM_SHA256` /
`WALLET_EMULATOR_ZKEY_SHA256`). Both files are gitignored.

**Until Phase 1c lands** the SHA-256 placeholders are `TODO_PIN_SHA256`
and the target will deliberately fail at the checksum step. See "Phase
1c — outstanding follow-ups" above for the pin procedure.

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
proof.go        → ZKPPacker wiring + prepareAuthV2Inputs
gist.go         → on-chain getGISTProof fetcher (Privado state contract)
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
| `FAIL: authV2.wasm sha256 mismatch ... expected: TODO_PIN_SHA256` | Phase 1b ships with placeholder SHA-256 hashes; the real values haven't been pinned yet | See "Phase 1c — outstanding follow-ups" in this README |
| `fetch gist proof from 0x... : ...` | Privado RPC unreachable, or the configured state contract isn't a real state contract | Verify `PRIVADO_RPC_URL` is reachable; verify `PRIVADO_STATE_CONTRACT` matches what `internal/auth/privado.go` expects |
| Multiple `--identity` files in flight | Each identity bumps the state contract → registration cost | Reuse the one canonical staging identity; rotate only when keys are compromised |
| `read .../authV2.wasm: no such file or directory` | Circuit artifacts not fetched | `make wallet-emulator-fetch-artifacts` (or manually drop the files into `tools/wallet-emulator/artifacts/`) |

## References

- `internal/auth/privado.go` — `PrivadoVerifier` (what the emulator's JWZ has to satisfy)
- `internal/server/auth.go` — `/auth/request` + `/auth/verify` endpoint shape
- [iden3 auth-v2 circuit](https://github.com/iden3/circuits) — the underlying ZK constraint set
- [iden3comm Go SDK](https://github.com/iden3/iden3comm) — `ZKPPacker`, `ProvingParams`, `DataPreparerHandlerFunc`
- Tracking issue: RD-947
