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
              +------------|--|-------------------------------------------+
                           |  |
                           v  | REST/HTTP
              +-------------- public -----------------------------------+
              |                                                         |
              |  proxy-frontend (admin UI)                              |
              |  block-explorer-frontend (nginx + SPA)                  |
              |                                                         |
              +---------------------------------------------------------+
                           |
                           v
                       Clients
```

**Rules:**

1. **privacy-proxy is the only service that spans both networks.** Nothing
   else in the trust zone is reachable from a client.
2. **The indexer listens on trust-zone only.** Its gRPC port is not
   published and no ingress points at it. Privacy-proxy is the sole
   consumer.
3. **No block-explorer api service is deployed.** The feature set that
   service provided (REST reads, ABI verification, WS subscriptions) is
   served either by privacy-proxy (reads) or dropped (subscriptions,
   verification) in privacy mode. See `docs/rd-855-behavioral-shifts.md`.
4. **Block-explorer postgres and indexer are not deployed.** The chain-
   indexer owns the only chain-data store in the deployment.
5. **Frontend nginx routes `/api/*` to privacy-proxy and returns 404 on
   `/ws`.** The runtime config is `deployments/privacy/nginx.privacy.conf`.

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
| block-explorer-frontend | ✅ | public | yes |
| **block-explorer api** | ❌ | — | — |
| **block-explorer postgres** | ❌ | — | — |
| **block-explorer indexer** | ❌ | — | — |

## Running it

```bash
# From the privacy-proxy repo root.
docker compose -f docker-compose.privacy.yml up -d
```

Required env vars:

- `JWT_SECRET`, `JWT_REFRESH_SECRET` — bail out at startup if empty.
- `ADMIN_API_TOKEN` — initial admin token for bootstrap.

Optional:

- `PRIVACY_POSTGRES_PASSWORD`, `INDEXER_POSTGRES_PASSWORD`, `REDIS_PASSWORD`
  — defaults are dev-grade; override in production.
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
  `block-explorer-frontend` container — it routes WS and API to a local
  `api:8080` which doesn't exist here, and (before RD-855) served raw
  data. The privacy-mode config is the authoritative one.

## Known gaps (see behavioral-shifts doc)

A few endpoints degrade gracefully in privacy mode vs. standalone. The
full list with rationale and suggested fixes lives at
`docs/rd-855-behavioral-shifts.md`. Highlights:

- Dashboard "Total txs" / "Total addresses" reflect network-wide counts,
  not per-viewer filtered counts. (Arguably correct product behavior.)
- Offset pagination totals on log / transfer / internal-tx list views
  show page-local counts, not DB-wide totals.
- Contract detail page does not show ABI / source / verification metadata.
- `/transfers` (unfiltered global transfer feed) is not available.
- `/ws` returns 404. Subscriptions are deferred.

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
   would have proxied to a non-existent local api:8080; a 502 or a
   successful upgrade indicates the wrong nginx config was mounted).
5. Block-explorer frontend's `/api/*` is routed to `proxy-backend`
   (any well-formed HTTP status other than `502` or `503`, which
   would mean the wrong nginx upstream).

Manual spot-check recipe (sanity, not a replacement for the test):

```bash
nc -zv <host> 50051               # chain-indexer gRPC — should fail
nc -zv <host> 5432                # postgres(s)        — should fail
nc -zv <host> 6379                # redis              — should fail
```

## Relationship with standalone mode

**Standalone mode** remains supported via the existing `docker-compose.yml`
in the block-explorer repo. In that deployment:

- block-explorer api + postgres + indexer are all present.
- Contract verification works.
- WS subscriptions work.
- There is no privacy-proxy; data is public by intent.

Privacy mode and standalone mode share the frontend SPA bundle but route
through different nginx configs at container start.
