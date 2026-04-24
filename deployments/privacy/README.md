# Privacy-mode deployment

This folder holds the artifacts that make up the **privacy-mode**
deployment of the Open Privacy Suite. If you're running corporate /
permissioned-chain workloads and care about the privacy guarantees the
product advertises, this is the deployment you want.

The authoritative manifest is `docker-compose.privacy.yml` at the
privacy-proxy repo root. Everything else in this folder is config
referenced by that manifest.

## Why this deployment exists — RD-855 in one paragraph

Prior to RD-855, the suite was deployed such that **privacy-proxy was not
a chokepoint**. The block-explorer ran its own api service, its own
postgres, and its own indexer alongside privacy-proxy; anything that could
reach the block-explorer's exposed surface could pull raw chain data that
should have been redacted. The privacy-mode deployment in this folder
fixes that structurally: the components that had direct access to raw
data are not deployed at all. There is no filter-based guard to get
wrong. See `docs/rd-855-behavioral-shifts.md` for the handful of
endpoints that degrade in privacy mode as a consequence.

## Trust boundary

```
              +--------------------------- trust-zone (internal) ---------+
              |                                                           |
              |  anvil / EVM node                                         |
              |       \                                                   |
              |        --> chain-indexer --> indexer-postgres             |
              |             |                                             |
              |             v                                             |
              |         (gRPC, no auth — shared trust zone)               |
              |             |                                             |
              |      privacy-proxy  --> privacy-postgres, redis           |
              |            |  ^                                           |
              |            |  |                                           |
              |      privacy-proxy  --> privacy-postgres, redis           |
              |            |  ^                                           |
              |            |  |                                           |
              |            v  |                                           |
              |    block-explorer-api (BFF, privacy-tagged build)         |
              |            |                                              |
              |            v                                              |
              |    block-explorer-postgres (verifications only)           |
              |                                                           |
              +------------|--|-------------------------------------------+
                           |  |
                           v  | REST/HTTP
              +-------------- public -----------------------------------+
              |                                                         |
              |  proxy-frontend (admin UI)                              |
              |  block-explorer-frontend (nginx + SPA, both networks)   |
              |                                                         |
              +---------------------------------------------------------+
                           |
                           v
                       Clients
```

**Rules:**

1. **privacy-proxy is the only service that spans both networks alongside
   block-explorer-frontend.** Other trust-zone services are not reachable
   from a client.
2. **The indexer listens on trust-zone only.** Its gRPC port is not
   published and no ingress points at it. Privacy-proxy is the sole
   consumer.
3. **Block-explorer runs as frontend + a thin Backend-for-Frontend (BFF)
   api.** The BFF terminates the OAuth flow, owns browser sessions
   (HttpOnly cookies), stores contract verifications, and forwards
   chain-data reads to privacy-proxy so redaction applies. See the
   "Block-explorer BFF" section below for the three-layer defense that
   keeps the BFF from bypassing privacy-proxy.
4. **No block-explorer indexer is deployed.** The chain-indexer owns the
   only chain-data store in the deployment.
5. **Frontend nginx routes `/api/*` to the BFF and returns 404 on
   `/ws`.** The runtime config is `deployments/privacy/nginx.privacy.conf`,
   mounted into the block-explorer-frontend nginx container at startup.

## What's deployed vs. what isn't

| Service | Deployed | Network | Exposed? |
|---|---|---|---|
| privacy-postgres | ✅ | trust-zone | no |
| redis | ✅ | trust-zone | no |
| anvil (EVM node, dev) | ✅ | trust-zone | no |
| chain-indexer | ✅ | trust-zone | no |
| indexer-postgres | ✅ | trust-zone | no |
| proxy-backend (privacy-proxy) | ✅ | both | yes |
| proxy-frontend | ✅ | public | yes |
| block-explorer-frontend | ✅ | both | yes |
| **block-explorer-api (BFF, privacy build)** | ✅ | trust-zone | no |
| **block-explorer-postgres (verifications only)** | ✅ | trust-zone | no |
| **block-explorer indexer** | ❌ | — | — |

## Running it

```bash
# From the privacy-proxy repo root.
docker compose -f docker-compose.privacy.yml up -d
```

Required env vars (all fail-closed — missing → compose aborts):

- `JWT_SECRET`, `JWT_REFRESH_SECRET` — privacy-proxy signing keys.
- `ADMIN_API_TOKEN` — initial admin token for bootstrap.
- `PRIVACY_POSTGRES_PASSWORD` — privacy-proxy's postgres.
- `INDEXER_POSTGRES_PASSWORD` — chain-indexer's postgres.
- `REDIS_PASSWORD` — privacy-proxy's redis.
- `BLOCK_EXPLORER_POSTGRES_PASSWORD` — BFF's postgres (verifications).
- `HOST_PORT_PROXY`, `HOST_PORT_UI`, `HOST_PORT_EXPLORER` — host ports for
  the proxy API, admin UI, and explorer UI respectively.
- `ENABLE_OP_DEPOSITS` — toggle OP-Stack indexing in the chain-indexer.
- `INDEXER_VERSION` (future) — registry tag for the chain-indexer image;
  currently the compose builds from `../chain-indexer`.

The compose expects `chain-indexer` and `block-explorer` cloned as
siblings of `privacy-proxy`. When the chain-indexer repo is published
and its image lives in a registry, replace the `build:` block under
`services.chain-indexer` with `image: ghcr.io/gateway-fm/chain-indexer:...`.

## What not to do

- **Do not stack this manifest with `docker-compose.yml` or
  `docker-compose.prod.yml`** (`docker compose -f docker-compose.yml -f
  docker-compose.privacy.yml up`). The non-privacy files reintroduce
  services (notably the `shared` network) that would let block-explorer
  components join and re-open the bypass path. If someone wants a hybrid
  deployment, they should say so explicitly and work out a bespoke
  compose; there's no supported hybrid.
- **Do not add an ingress rule for `chain-indexer:50051`** — if clients
  can reach the indexer directly, redaction is bypassed. There is no
  legitimate use case for external indexer access in privacy mode.
- **Do not mount the block-explorer repo's own nginx config** into the
  `block-explorer-frontend` container — it routes WS and `/api/*` to
  a service name (`api`) that doesn't exist in this compose, and does
  not know about the `/ws → 404` privacy-mode rule. The privacy-mode
  config in `deployments/privacy/nginx.privacy.conf` is the
  authoritative one.
- **Do not deploy `block-explorer-api` from an image built without
  `--target privacy`.** The default (standalone) build image links
  the chain-indexer gRPC client; with network egress to the indexer
  it would bypass redaction. The compose uses `target: privacy` for
  exactly this reason.

## Block-explorer BFF

Block-explorer in privacy mode runs as frontend **plus a thin
Backend-for-Frontend (BFF)** — `block-explorer-api`. A pure-SPA
deployment can't terminate OAuth against privacy-proxy (no place for
`/api/auth/callback`, no HttpOnly cookie setter, nowhere to persist
contract verifications); putting the access token in JavaScript would
fail OWASP ASVS L2+ and OAuth-for-Browser-Based-Apps BCP. So we run a
minimal server whose only job is session management + proxying.

The BFF's only legitimate chain-data source is privacy-proxy. Three
layers of defense keep it that way:

| Layer | Mechanism |
|---|---|
| Compile-time | BFF image is built with `go build -tags privacy` via Dockerfile `--target privacy`. The `indexerclient` package (chain-indexer gRPC client) is excluded at compile time; the resulting binary has no code path that can speak chain-indexer gRPC. Verifiable with `strings` on the image. |
| Runtime | `cmd/api/provider_privacy.go` in block-explorer `log.Fatal`s on startup if `INDEXER_URL` is set, or if `PRIVACY_PROXY_URL` is empty. |
| Network | `block-explorer-api` sits on `trust-zone` with no host-port publish. Only `block-explorer-frontend`'s nginx (which straddles both networks) can reach it. |

The BFF's postgres (`block-explorer-postgres`) holds only
contract-verification artifacts — user-submitted source code and ABIs.
No chain data. Trust-zone only.

## Trust model: no auth between trust-zone services

The privacy-mode deployment does **not** place application-level
authentication on the internal service-to-service hops:

- `privacy-proxy → chain-indexer` gRPC is plaintext, no mTLS, no bearer token.
- `privacy-proxy → privacy-postgres` uses password-only `sslmode=disable`.
- `privacy-proxy → redis` uses a shared password on the compose network.
- `chain-indexer → indexer-postgres` uses the same pattern.
- `chain-indexer → anvil` (or prod RPC) is plaintext.
- `block-explorer-api → privacy-proxy` is plaintext; the BFF is a
  client like any other, subject to OAuth/JWT for per-user authz.
- `block-explorer-api → block-explorer-postgres` uses password-only
  `sslmode=disable`.

This is **intentional**. The trust boundary is enforced at the
**network level**, not at the application level:

1. Trust-zone services live on a dedicated docker network with no
   host-port publishes. `docker-compose.privacy.yml` deliberately omits
   `ports:` on every trust-zone service.
2. `e2e/privacy_manifest_test.go` (static, PR-gated) fails the build
   if any trust-zone service sprouts a `ports:` block, or if a listed
   public service loses its publish.
3. `e2e/privacy_bypass_test.go` (runtime, weekly) brings the full
   stack up and verifies trust-zone ports are unreachable from the
   host.
4. `deployments/privacy/trust-zone.yaml` is the single source of truth
   for what counts as trust-zone vs public; both tests load it.

**Implication for operators** deploying outside compose (Kubernetes,
other orchestrators): you must preserve this network-level isolation,
e.g., with a `NetworkPolicy` that denies ingress to every trust-zone
service except from the allowed callers listed in `trust-zone.yaml`. Do
not expose `chain-indexer`, `*-postgres`, `redis`, or `block-explorer-api`
to any ingress, load balancer, or service-mesh gateway. If a future
target can't provide network isolation, mTLS + bearer auth on each
internal hop is the follow-up work; that is deliberately **not** in
scope for the compose-based deployment.

**Why no defense in depth here?** Adding tokens on internal hops
without network isolation is cargo-cult security — an attacker who can
reach those services can already read the token from any compromised
container. Adding tokens *with* network isolation is genuine
defense-in-depth, but the token rotation / distribution cost isn't
justified at this stage. Revisit if we gain multi-tenant trust-zone
deployments where a compromise of one tenant's privacy-proxy should
not give access to another tenant's indexer.

## Known gaps (see behavioral-shifts doc)

A few endpoints degrade gracefully in privacy mode vs. standalone. The
full list with rationale and suggested fixes lives at
`docs/rd-855-behavioral-shifts.md`. Highlights:

- Dashboard "Total txs" / "Total addresses" reflect network-wide counts,
  not per-viewer filtered counts. (Arguably correct product behavior.)
- Offset pagination totals on log / transfer / internal-tx list views
  show page-local counts, not DB-wide totals.
- `/transfers` (unfiltered global transfer feed) is not available.
- `/ws` returns 404. Subscriptions are deferred.

(Contract verification is available via the BFF; ABI / source / verified
status render on the contract detail page as in standalone mode.)

## Testing the boundary

An automated negative-network test verifies the trust boundary is closed.
It brings up the full compose, asserts trust-zone services are not
reachable from the host, and asserts the frontend's routing behavior.

Run locally:

```bash
# Requires chain-indexer and block-explorer cloned as siblings of
# privacy-proxy. Takes 1-2 minutes.
make test-privacy-bypass
```

Run in CI:

The test lives in `e2e/privacy_bypass_test.go` (build-tag gated to
`privacy_bypass`, so it stays out of the default test run and pre-push
hook). A dedicated GitHub Actions workflow runs it on a weekly schedule
and on manual dispatch — see `.github/workflows/privacy-bypass.yml`.
Dispatch it manually after any change to:

- `docker-compose.privacy.yml`
- `deployments/privacy/nginx.privacy.conf`
- The block-explorer or chain-indexer Dockerfiles
- The indexer gRPC service surface

What the test asserts:

1. Compose config does not publish any trust-zone service's ports
   (structural: parses `docker compose config --format json`).
2. After `up`, each trust-zone service's default port is NOT reachable
   from `127.0.0.1` — a TCP connect times out or is refused.
3. `proxy-backend`, `proxy-frontend`, and `block-explorer-frontend`
   ARE reachable (positive check — these are intentional).
4. Block-explorer frontend's `/ws` returns `404` (standalone config
   would have proxied to a local subscription endpoint; a 502 or a
   successful upgrade indicates the wrong nginx config was mounted).
5. Block-explorer frontend's `/api/*` is routed to `block-explorer-api`
   (the BFF) — any well-formed HTTP status other than `502` or `503`,
   which would mean the wrong nginx upstream.

Manual spot-check recipe (sanity, not a replacement for the test):

```bash
nc -zv <host> 50051               # chain-indexer gRPC — should fail
nc -zv <host> 5432                # postgres(s)        — should fail
nc -zv <host> 6379                # redis              — should fail
```

## Deploying outside compose (Kubernetes, Terraform, etc.)

`docker-compose.privacy.yml` is a **reference deployment**. Ops teams
typically translate it to their orchestrator. That's expected — what
must survive the translation are the invariants, not the tooling.

Invariants (source of truth: `trust-zone.yaml`):

1. The host-exposed service list matches the `public:` section
   verbatim. Every service in the `trust_zone:` section has no ingress,
   no load balancer, no NodePort.
2. `block-explorer-api` runs the privacy-tagged image
   (`... --target privacy` on the Dockerfile, or `-tags privacy` for a
   `go build`). Without this the compile-time defense is off.
3. `nginx.privacy.conf` is the active nginx config on the
   `block-explorer-frontend` pod (typically mounted from a ConfigMap).
   If ops write their own nginx config, it must preserve two rules:
   `/api/*` → the BFF service, `/ws` → 404.
4. All fail-closed env vars (`${VAR:?…}` list in the compose file) are
   sourced from a secret store (K8s Secrets, AWS Secrets Manager,
   etc.) — missing must prevent startup.
5. A NetworkPolicy (or equivalent) denies ingress to every trust-zone
   pod except from the callers declared in `trust-zone.yaml`.

Our PR-gated + weekly tests validate the compose deployment.
**Equivalent coverage is required in ops' own infra**: a cluster-
internal probe that TCP-connects from outside each trust-zone pod's
allowed caller set and expects refused. Run it on deployment and on a
schedule; file the result as an audit control. `trust-zone.yaml` is
machine-readable on purpose — generate the NetworkPolicy YAML and the
probe targets from it rather than maintaining parallel lists.

## Relationship with standalone mode

**Standalone mode** remains supported via the existing `docker-compose.yml`
in the block-explorer repo. In that deployment:

- block-explorer api + postgres + indexer are all present.
- Contract verification works.
- WS subscriptions work.
- There is no privacy-proxy; data is public by intent.

Privacy mode and standalone mode share the frontend SPA bundle but route
through different nginx configs at container start.
