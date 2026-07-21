# Server E2E harness

`scripts/e2e-harness.sh` is the supported entry point for running E2E work on
a developer workstation, shared build server, or CI runner. It gives every run
its own Docker Compose project and artifact directory, and teardown targets
only resources owned by that run.

Run commands from the repository root. Do not invoke
`docker-compose.e2e.yml` directly on a shared machine; doing so bypasses the
run identity, cleanup traps, and per-run artifact paths.

## First full run

Verify the host before starting a long run:

```bash
make e2e-doctor
make e2e
```

`make e2e` is the finite, complete E2E gate: both Go lanes (default and
`mockauth`), the Dockerized Playwright suite, and the privacy-boundary suite.
The privacy lane builds the current Open Privacy Suite working tree plus pinned
public sources for ops-explorer (`v0.9.0-rc.1`) and ops-indexer
(`v0.4.0-rc.1`). The harness creates shallow, artifact-owned checkouts, so a
normal run does not require sibling repositories or registry credentials.
The doctor command reports missing local prerequisites without starting a test
stack.

## Modes

| Command | Purpose |
|---|---|
| `make e2e` | Run every finite E2E lane. |
| `make e2e-go` | Run the default and `mockauth` Go E2E lanes. |
| `make e2e-playwright` | Run the browser suite in the isolated Compose stack. |
| `make e2e-privacy` | Run the privacy-mode network-boundary suite. |
| `make e2e-chaos` | Run Playwright, fault every configured project-owned service at least once, and verify recovery (10-minute soft minimum by default). |
| `E2E_SOAK_DURATION=8h make e2e-soak` | Cold-cycle the finite `all` suite for eight hours, stopping after the first complete failing iteration. |
| `make e2e-doctor` | Check tools, daemon access, paths, and configuration. |
| `make e2e-down` | Tear down only the selected run's Compose projects. |

The same modes are available directly, for example
`./scripts/e2e-harness.sh playwright`. Run the script with `--help` for
advanced chaos/soak timing controls and dry-run support.

The Go lanes never assume shared services on the usual Postgres or Anvil
ports. The harness starts run-owned Postgres and Anvil containers, publishes
Docker-assigned ports on `127.0.0.1` only, passes their URLs to the test
process, and tears the project down before the next lane.

## Run identity and artifacts

The harness creates a unique `E2E_RUN_ID` by default, derives an isolated
`E2E_PROJECT`, and writes to `.tmp/e2e-runs/<run-id>/`. That directory contains
logs, metadata, summaries, and Playwright output and is ignored by Git.

For automation, set an explicit unique ID and absolute artifact path:

```bash
export E2E_RUN_ID="nightly-$(date -u +%Y%m%d-%H%M%S)"
export E2E_ARTIFACT_DIR="$PWD/.tmp/e2e-runs/$E2E_RUN_ID"
make e2e
```

The supported environment controls are:

- `E2E_RUN_ID`: unique operator-facing run identifier.
- `E2E_PROJECT`: optional explicit Compose project name.
- `E2E_ARTIFACT_DIR`: artifact directory for this run; use an absolute path
  when exporting it from CI or a server shell.
- `E2E_KEEP_STACK=1`: retain an owned Playwright/chaos stack for inspection.
- `E2E_SOAK_DURATION`: soak duration such as `30m`, `8h`, or `24h`.
- `E2E_GO_MAX_PROCS`: maximum Go runtime/compiler parallelism (default `2`).
- `E2E_GO_TEST_PARALLELISM`: maximum parallel Go tests (default `1`).
- `E2E_PLAYWRIGHT_WORKERS`: browser worker count (default `1`).
- `E2E_COMPOSE_PARALLEL_LIMIT`: concurrent Compose engine operations (default
  `1`).
- `E2E_BLOCK_EXPLORER_REPOSITORY`: ops-explorer clone URL (default
  `https://github.com/gateway-fm/ops-explorer.git`).
- `E2E_BLOCK_EXPLORER_REF`: ops-explorer Git ref (default `v0.9.0-rc.1`).
- `E2E_BLOCK_EXPLORER_PATH`: existing ops-explorer checkout to build instead
  of creating an artifact-owned shallow checkout.
- `E2E_CHAIN_INDEXER_REPOSITORY`: ops-indexer clone URL (default
  `https://github.com/gateway-fm/ops-indexer.git`).
- `E2E_CHAIN_INDEXER_REF`: ops-indexer Git ref (default `v0.4.0-rc.1`).
- `E2E_CHAIN_INDEXER_PATH`: existing ops-indexer checkout to build instead of
  creating an artifact-owned shallow checkout.

Never reuse an active run ID or project name for a concurrent run.

## Privacy source builds

The privacy lane keeps `docker-compose.privacy.yml` as the production-topology
source of truth. An E2E-only Compose overlay changes only the provenance of the
five first-party images: proxy backend and frontend are built from the current
working tree, while the explorer and indexer images are built from the pinned
public sources above. The explorer API explicitly uses its `privacy` build
target, preserving the compile-time removal of direct indexer access. Service
configuration, trust-zone networks, and the negative-network assertions remain
the production privacy topology.

When no `E2E_*_PATH` override is supplied, source checkouts live under the
run's artifact directory and are shallow clones of the configured repository
and ref. Repository and ref overrides are useful for testing an alternate
public fork or release; path overrides are useful for an existing local
checkout. Keep all three values paired with the component they name, and use a
unique run ID when comparing revisions concurrently.

Compose assigns run-project-local names to locally built images. Normal
success, failure, and interrupt cleanup removes those images together with the
run-owned containers, networks, and volumes. It does not prune the Docker
daemon, remove unrelated images, or delete a caller-supplied source checkout.
Artifact-owned source checkouts remain with the run artifacts for provenance
and debugging.

## Retaining and cleaning up a run

Ordinary success, failure, interrupt, and termination paths clean up
automatically. To inspect a failed or completed stack, retain it deliberately
and use the same identity when taking it down:

```bash
E2E_RUN_ID=investigation-42 E2E_KEEP_STACK=1 make e2e-playwright
E2E_RUN_ID=investigation-42 make e2e-down
```

`e2e-down` requires the original `E2E_RUN_ID` and its artifact ownership files.
If `E2E_PROJECT`, `E2E_PRIVACY_PROJECT`, or `E2E_ARTIFACT_DIR` was explicitly
set for the run, provide the same value for cleanup. Only projects marked as
actually acquired by that run are eligible for teardown. Cleanup never performs
daemon-wide pruning and must not be replaced with `docker system prune` on a
shared server.
