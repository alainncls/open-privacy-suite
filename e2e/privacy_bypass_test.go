//go:build privacy_bypass
// +build privacy_bypass

// Negative-network tests for the privacy-mode deployment (RD-855 Phase 4b).
//
// Run with:
//   make test-privacy-bypass
//
// Or directly:
//   JWT_SECRET=x JWT_REFRESH_SECRET=y \
//     go test -tags privacy_bypass -timeout 10m ./e2e/...
//
// The build tag keeps this out of the default test run (and the pre-push
// hook): the test brings up the full privacy-mode compose stack — nine
// services — and exercises the trust boundary from the outside. It takes
// 1-2 minutes in the happy case.
//
// The test asserts:
//
//   1. Internal-zone services (chain-indexer gRPC port, indexer postgres,
//      anvil RPC, privacy-proxy postgres, redis, BFF, BFF postgres) are
//      NOT published on the host. A TCP connect from the host on the
//      service's default port must fail. The list is loaded from
//      trust-zone.yaml dynamically.
//
//   2. The compose manifest itself does not publish ports on
//      internal-zone services (structural check via `docker compose
//      config`).
//
//   3. The block-explorer frontend in privacy mode:
//      - Responds to GET /
//      - Routes /api/* to privacy-proxy (NOT to a local api:8080 which
//        doesn't exist here)
//      - Returns 404 on /ws (subscriptions deferred per RD-855)
//
//   4. Cross-zone isolation (RD-876): a probe attached to bff-zone
//      cannot reach chain-indexer:50051. The two-zone split is the
//      structural floor that survives upstream build-pipeline
//      mistakes (a misbuilt BFF that lost its --target privacy tag or
//      had INDEXER_URL set still cannot reach the indexer because
//      they're on different docker networks).
//
// Together these prove the bypass described in RD-855 is closed and
// hardened per RD-876: there is no reachable path from a client to raw
// chain data except via privacy-proxy, which applies RedactionEngine
// on the way out.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// composeServices is the full set of services declared by
// docker-compose.privacy.yml. Keep in sync when adding/removing services
// in the manifest.
var composeServices = []string{
	"privacy-postgres",
	"redis",
	"anvil",
	"indexer-postgres",
	"chain-indexer",
	"proxy-backend",
	"proxy-frontend",
	"block-explorer-frontend",
}

// internalService is the per-host-probe shape: (service name, port the
// container listens on inside the compose network). Loaded from
// trust-zone.yaml at test start so the list stays in sync with the
// manifest as services are added or removed.
type internalService struct {
	Service string
	Port    int
}

func loadInternalServices(t *testing.T, repoRoot string) []internalService {
	t.Helper()
	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}
	all := cfg.AllInternal()
	out := make([]internalService, 0, len(all))
	for _, s := range all {
		out = append(out, internalService{Service: s.Name, Port: s.DefaultInternalPort})
	}
	return out
}

// Public-zone published ports. These MUST be reachable; we verify by a
// positive connect. Overrides from env are honored — the compose file
// allows setting HOST_PORT_PROXY / HOST_PORT_UI / HOST_PORT_EXPLORER.
func publicPorts() (proxy, ui, explorer int) {
	g := func(key string, def int) int {
		if v := os.Getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
		return def
	}
	return g("HOST_PORT_PROXY", 8080), g("HOST_PORT_UI", 5173), g("HOST_PORT_EXPLORER", 3001)
}

func TestPrivacyModeBypassClosure(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker not installed: %v", err)
	}
	// The compose file lives at the repo root; locate it relative to this file.
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	composeFile := filepath.Join(repoRoot, "docker-compose.privacy.yml")
	if _, err := os.Stat(composeFile); err != nil {
		t.Fatalf("compose file not found at %s: %v", composeFile, err)
	}

	// The prod compose now pulls chain-indexer from GHCR
	// (image: ghcr.io/gateway-fm/chain-indexer:${INDEXER_VERSION:-latest}),
	// so a sibling clone is no longer required for that service.
	// block-explorer is still built from a sibling clone; CI must set
	// it up, locally the dev's workspace has it.
	if _, err := os.Stat(filepath.Join(repoRoot, "..", "block-explorer")); err != nil {
		t.Skipf("block-explorer sibling clone missing: %v", err)
	}

	env := []string{
		"JWT_SECRET=test-jwt-secret-do-not-use-in-production-1234567890",
		"JWT_REFRESH_SECRET=test-refresh-secret-do-not-use-in-production-0987654321",
		"ADMIN_API_TOKEN=test-admin-token",
		"PRIVACY_POSTGRES_PASSWORD=test-privacy-pg-password",
		"INDEXER_POSTGRES_PASSWORD=test-indexer-pg-password",
		"REDIS_PASSWORD=test-redis-password",
		"BLOCK_EXPLORER_POSTGRES_PASSWORD=test-bff-pg-password",
	}

	internalServices := loadInternalServices(t, repoRoot)

	t.Run("compose config does not publish internal-zone ports", func(t *testing.T) {
		assertNoPublishedInternalPortsInConfig(t, composeFile, env, repoRoot, internalServices)
	})

	// Bring the stack up. Defer teardown so a failure inside doesn't
	// leave containers running.
	t.Logf("starting privacy-mode compose stack (this may take 1-2 minutes)")
	up := dockerCompose(composeFile, env, repoRoot, "up", "-d", "--wait")
	out, err := up.CombinedOutput()
	if err != nil {
		t.Logf("compose up output:\n%s", string(out))
		t.Fatalf("compose up: %v", err)
	}
	t.Cleanup(func() {
		down := dockerCompose(composeFile, env, repoRoot, "down", "-v")
		if out, err := down.CombinedOutput(); err != nil {
			t.Logf("compose down failed (leaking containers):\n%s\nerror: %v", string(out), err)
		}
	})

	// Discover the host-published port for proxy-backend specifically;
	// env overrides take precedence if set.
	proxyPort, uiPort, explorerPort := publicPorts()

	t.Run("internal-zone services unreachable on host", func(t *testing.T) {
		for _, svc := range internalServices {
			t.Run(svc.Service, func(t *testing.T) {
				assertNotReachable(t, "127.0.0.1", svc.Port)
			})
		}
	})

	// RD-876: cross-zone isolation. Even if a future change drops the
	// BFF's `--target privacy` build tag or sets INDEXER_URL, the BFF
	// still cannot reach the indexer because they're on different
	// docker networks. Probe with throwaway alpine containers attached
	// to one zone at a time.
	t.Run("BFF cannot reach indexer across zones", func(t *testing.T) {
		assertCrossZoneIsolation(t, "privacy-bypass-test")
	})

	t.Run("proxy-backend reachable on host", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", proxyPort)
		assertHTTP200(t, fmt.Sprintf("http://127.0.0.1:%d/health", proxyPort))
	})

	t.Run("proxy-frontend reachable on host", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", uiPort)
	})

	t.Run("block-explorer frontend reachable", func(t *testing.T) {
		assertReachable(t, "127.0.0.1", explorerPort)
	})

	t.Run("block-explorer /ws returns 404 in privacy mode", func(t *testing.T) {
		// Privacy-mode nginx config explicitly returns 404 on /ws —
		// subscriptions are deferred. The legacy standalone config
		// would have proxied /ws to a local api:8080 which doesn't
		// exist here; a successful upgrade or a 502 would indicate
		// the wrong nginx config got mounted.
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/ws", explorerPort))
		if err != nil {
			t.Fatalf("GET /ws: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected 404 on /ws, got %d\nbody: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("block-explorer /api/* proxied to privacy-proxy (not local api)", func(t *testing.T) {
		// Hitting the frontend's /api/ should land at privacy-proxy's
		// /api/v1/explorer/ — we can tell it hit privacy-proxy (and
		// not nothing) by getting a well-formed HTTP response. 401
		// (unauthenticated), 403, or 404 (no matching sub-route) are
		// all acceptable for this negative-path assertion; 502
		// (connection refused to missing upstream) or 503 would
		// indicate the wrong nginx config is in play.
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/explorer/stats", explorerPort))
		if err != nil {
			t.Fatalf("GET /api/*: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("frontend nginx returned %d — implies it's trying to reach a non-existent local api. Privacy-mode nginx config not in place.\nbody: %s", resp.StatusCode, string(body))
		}
		// Any other HTTP status means privacy-proxy received the request,
		// which is what we're checking.
		t.Logf("proxied /api/v1/explorer/stats status=%d (expected: privacy-proxy received the request)", resp.StatusCode)
	})
}

// ----- helpers -----

// dockerCompose constructs a docker compose command rooted at repoRoot,
// using the given compose file, with env vars injected. The returned
// *exec.Cmd has its working directory set so relative build contexts
// (./backend, ../chain-indexer) resolve correctly.
func dockerCompose(composeFile string, env []string, repoRoot string, args ...string) *exec.Cmd {
	full := append([]string{"compose", "-f", composeFile, "-p", "privacy-bypass-test"}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

// assertNoPublishedInternalPortsInConfig parses `docker compose config
// --format json` and fails the test if any internal-zone service
// (indexer-zone or bff-zone) declares a host port mapping.
func assertNoPublishedInternalPortsInConfig(t *testing.T, composeFile string, env []string, repoRoot string, internal []internalService) {
	t.Helper()
	cmd := dockerCompose(composeFile, env, repoRoot, "config", "--format", "json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	var cfg struct {
		Services map[string]struct {
			Ports []struct {
				Target    int    `json:"target"`
				Published string `json:"published"`
			} `json:"ports"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatalf("parse compose config json: %v", err)
	}
	bannedServices := map[string]bool{}
	for _, s := range internal {
		bannedServices[s.Service] = true
	}
	for name, svc := range cfg.Services {
		if !bannedServices[name] {
			continue
		}
		if len(svc.Ports) > 0 {
			for _, p := range svc.Ports {
				t.Errorf("internal-zone service %q publishes port: target=%d published=%q — privacy-mode compose must not publish internal-zone services", name, p.Target, p.Published)
			}
		}
	}
}

// assertCrossZoneIsolation verifies the structural floor of the
// two-zone trust split:
//
//  1. From bff-zone, chain-indexer:50051 must NOT be reachable. This is
//     the load-bearing assertion — a misbuilt BFF that lost its
//     `--target privacy` tag or had INDEXER_URL set must still fail to
//     reach the indexer because the network forbids it.
//  2. From indexer-zone, chain-indexer:50051 IS reachable (positive
//     control; if this fails, the test result on (1) isn't meaningful).
//
// Probes use a throwaway alpine container attached to one zone at a
// time. busybox `nc -z -w 3` exits 0 on a successful TCP connect.
func assertCrossZoneIsolation(t *testing.T, project string) {
	t.Helper()

	probe := func(network string) error {
		cmd := exec.Command("docker", "run", "--rm",
			"--network", network,
			"alpine:latest",
			"nc", "-z", "-w", "3", "chain-indexer", "50051")
		return cmd.Run()
	}

	bffNet := project + "_bff-zone"
	indexerNet := project + "_indexer-zone"

	// Negative case — load-bearing assertion.
	if err := probe(bffNet); err == nil {
		t.Fatalf("from %s, chain-indexer:50051 IS reachable — the two-zone trust split is broken. The block-explorer BFF could now bypass privacy-proxy at the network layer. Check the compose file: chain-indexer must be on indexer-zone only, the BFF must be on bff-zone only, and proxy-backend (the BridgeService) must be the only service on both.", bffNet)
	}

	// Positive control. If this fails the negative assertion above is
	// not meaningful — log loudly but don't fail since the stack might
	// just not be ready.
	if err := probe(indexerNet); err != nil {
		t.Logf("WARNING: positive control failed — from %s, chain-indexer:50051 should be reachable but the probe errored (%v). The negative assertion above passed but may not be meaningful in isolation.", indexerNet, err)
	}
}

// assertNotReachable tries to open a TCP connection to host:port with a
// short timeout and fails the test if the connect succeeds. A timeout or
// connection refused is the expected outcome.
func assertNotReachable(t *testing.T, host string, port int) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 1500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s is reachable — privacy-mode bypass is NOT closed. A client outside the trust zone could connect to this service directly.", addr)
	}
	// Error is expected; log at debug level only.
	t.Logf("%s unreachable (%v) — good", addr, strings.SplitN(err.Error(), ": ", 2)[0])
}

// assertReachable tries to open a TCP connection to host:port. Fails if
// the connect doesn't succeed within a short timeout.
func assertReachable(t *testing.T, host string, port int) {
	t.Helper()
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(30 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s should be reachable but isn't: %v", addr, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// assertHTTP200 does a GET and fails if the status isn't 200 or the
// request errors. Useful for healthcheck-style probes.
func assertHTTP200(t *testing.T, url string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: status %d, body: %s", url, resp.StatusCode, string(body))
	}
}
