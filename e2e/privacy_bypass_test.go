//go:build privacy_bypass
// +build privacy_bypass

// Negative-network tests for the privacy-mode deployment (RD-855 Phase 4b).
//
// Run with:
//
//	make e2e-privacy
//
// Each run uses a unique Compose project and Docker-assigned public ports by
// default. Set E2E_PRIVACY_PROJECT to give an external harness a stable project
// name. HOST_PORT_PROXY, HOST_PORT_UI, and HOST_PORT_EXPLORER remain available
// as explicit port overrides.
//
// The build tag keeps this out of the default test run (and the pre-push
// hook): the test brings up the full privacy-mode Compose stack and exercises
// the trust boundary from the outside. It takes 1-2 minutes in the happy case.
//
// The test asserts:
//
//  1. Internal-zone services (chain-indexer gRPC port, indexer postgres,
//     anvil RPC, Open Privacy Suite postgres, redis, BFF, BFF postgres) have
//     no host bindings owned by this Compose project. The list is loaded from
//     trust-zone.yaml dynamically.
//
//  2. The compose manifest itself does not publish ports on
//     internal-zone services (structural check via `docker compose
//     config`).
//
//  3. The block-explorer frontend in privacy mode:
//     - Responds to GET /
//     - Routes /api/* to Open Privacy Suite (NOT to a local api:8080 which
//     doesn't exist here)
//     - Returns 404 on /ws (subscriptions deferred per RD-855)
//
//  4. Cross-zone isolation (RD-876): a probe attached to bff-zone
//     cannot reach chain-indexer:50051. The two-zone split is the
//     structural floor that survives upstream build-pipeline
//     mistakes (a misbuilt BFF that lost its --target privacy tag or
//     had INDEXER_URL set still cannot reach the indexer because
//     they're on different docker networks).
//
// Together these prove the bypass described in RD-855 is closed and
// hardened per RD-876: there is no reachable path from a client to raw
// chain data except via Open Privacy Suite, which applies RedactionEngine
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

// internalService identifies a project-owned internal container and the port
// it listens on inside the Compose network. It is loaded from trust-zone.yaml
// so the binding oracle stays in sync as services are added or removed.
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

// privacyComposeProject returns an explicit harness-supplied project name or a
// per-process unique default. COMPOSE_PROJECT_NAME is deliberately ignored:
// this stack must not accidentally join (and later tear down) another Compose
// stack whose name happens to be present in the caller's environment.
func privacyComposeProject() string {
	if project := strings.TrimSpace(os.Getenv("E2E_PRIVACY_PROJECT")); project != "" {
		return project
	}
	// Kept as a compatibility alias for callers that predate the all-E2E
	// harness. New callers should use E2E_PRIVACY_PROJECT.
	if project := strings.TrimSpace(os.Getenv("PRIVACY_BYPASS_COMPOSE_PROJECT")); project != "" {
		return project
	}
	return fmt.Sprintf("privacy-bypass-%d-%d", os.Getpid(), time.Now().UnixNano())
}

// publicHostPort returns an explicit override or 0, which asks Docker to
// allocate a free ephemeral host port. The actual project-owned binding is
// discovered after Compose starts instead of assuming a machine-global port.
func publicHostPort(key string) string {
	if port := strings.TrimSpace(os.Getenv(key)); port != "" {
		return port
	}
	return "0"
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

	if override := privacyComposeOverride(repoRoot); override != "" {
		if _, err := os.Stat(override); err != nil {
			t.Fatalf("privacy Compose override not found at %s: %v", override, err)
		}
		t.Logf("using privacy Compose image-provenance override %s", override)
	}

	project := privacyComposeProject()
	env := []string{
		"JWT_SECRET=test-jwt-secret-do-not-use-in-production-1234567890",
		"JWT_REFRESH_SECRET=test-refresh-secret-do-not-use-in-production-0987654321",
		"ADMIN_API_TOKEN=test-admin-token",
		"PRIVACY_POSTGRES_PASSWORD=test-privacy-pg-password",
		"AUDIT_APP_PASSWORD=test-audit-app-password",
		"INDEXER_POSTGRES_PASSWORD=test-indexer-pg-password",
		"REDIS_PASSWORD=test-redis-password",
		"BLOCK_EXPLORER_POSTGRES_PASSWORD=test-bff-pg-password",
		"CORS_ALLOWED_ORIGINS=https://explorer.e2e.invalid,https://frontend.e2e.invalid",
		// Loopback-only, Docker-assigned ports prevent this test from
		// colliding with unrelated services on a shared host. Supplying a
		// HOST_PORT_* variable is an explicit request for a fixed port.
		"HOST_BIND=127.0.0.1",
		"HOST_PORT_PROXY=" + publicHostPort("HOST_PORT_PROXY"),
		"HOST_PORT_UI=" + publicHostPort("HOST_PORT_UI"),
		"HOST_PORT_EXPLORER=" + publicHostPort("HOST_PORT_EXPLORER"),
		// Dynamic published ports are not known until Docker starts. Use
		// valid HTTPS placeholders for browser-facing URL settings in this
		// network-boundary-only topology, rather than localhost:0. This test
		// does not exercise browser callbacks; Playwright owns that lane.
		"BASE_URL=https://proxy.e2e.invalid",
		"FRONTEND_URL=https://frontend.e2e.invalid",
		"VITE_BLOCK_EXPLORER_URL=https://explorer.e2e.invalid",
		"PRIVACY_PROXY_PUBLIC_URL=https://proxy.e2e.invalid",
		"SSO_REDIRECT_URI=https://explorer.e2e.invalid/api/auth/callback",
	}

	// Register teardown before `up`: Compose can create networks, volumes, and
	// some containers before returning a partial-start error.
	t.Cleanup(func() {
		capturePrivacyComposeArtifacts(t, composeFile, env, repoRoot, project)
		down := dockerCompose(composeFile, env, repoRoot, project, "down", "-v", "--remove-orphans", "--rmi", "local")
		if out, err := down.CombinedOutput(); err != nil {
			t.Errorf("compose down failed (project %s may have leaked resources):\n%s\nerror: %v", project, string(out), err)
		}
	})
	t.Logf("using isolated Compose project %q", project)

	internalServices := loadInternalServices(t, repoRoot)

	t.Run("compose config does not publish internal-zone ports", func(t *testing.T) {
		assertNoPublishedInternalPortsInConfig(t, composeFile, env, repoRoot, project, internalServices)
	})

	t.Logf("starting privacy-mode compose stack (this may take 1-2 minutes)")
	up := dockerCompose(composeFile, env, repoRoot, project, "up", "-d", "--wait")
	out, err := up.CombinedOutput()
	if err != nil {
		t.Logf("compose up output:\n%s", string(out))
		t.Fatalf("compose up: %v", err)
	}

	// Resolve the ports from this project's containers. This both handles
	// Docker-assigned ports and prevents a successful probe from being
	// accidentally attributed to an unrelated listener on the machine.
	proxyPort := composePublishedPort(t, composeFile, env, repoRoot, project, "proxy-backend", 8080)
	uiPort := composePublishedPort(t, composeFile, env, repoRoot, project, "proxy-frontend", 80)
	explorerPort := composePublishedPort(t, composeFile, env, repoRoot, project, "block-explorer-frontend", 80)

	t.Run("internal-zone services have no project-owned host bindings", func(t *testing.T) {
		for _, svc := range internalServices {
			t.Run(svc.Service, func(t *testing.T) {
				assertNoPublishedPortsOnProjectService(t, composeFile, env, repoRoot, project, svc)
			})
		}
	})

	// RD-876: cross-zone isolation. Even if a future change drops the
	// BFF's `--target privacy` build tag or sets INDEXER_URL, the BFF
	// still cannot reach the indexer because they're on different
	// docker networks. Probe with throwaway alpine containers attached
	// to one zone at a time.
	t.Run("BFF cannot reach indexer across zones", func(t *testing.T) {
		assertCrossZoneIsolation(t, project)
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

	t.Run("block-explorer /api/* proxied to Open Privacy Suite (not local api)", func(t *testing.T) {
		// Hitting the frontend's /api/ should land at Open Privacy Suite's
		// /api/v1/explorer/ — we can tell it hit Open Privacy Suite (and
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
		// Any other HTTP status means Open Privacy Suite received the request,
		// which is what we're checking.
		t.Logf("proxied /api/v1/explorer/stats status=%d (expected: Open Privacy Suite received the request)", resp.StatusCode)
	})
}

// ----- helpers -----

// privacyComposeOverride returns the optional harness-provided image
// provenance overlay. Relative paths are rooted at the repository so every
// Compose invocation resolves the same file regardless of the caller's cwd.
func privacyComposeOverride(repoRoot string) string {
	override := strings.TrimSpace(os.Getenv("E2E_PRIVACY_COMPOSE_OVERRIDE"))
	if override == "" {
		return ""
	}
	if !filepath.IsAbs(override) {
		override = filepath.Join(repoRoot, override)
	}
	return filepath.Clean(override)
}

// dockerCompose constructs a project-scoped docker compose command rooted at
// repoRoot, using the production manifest plus an optional image-provenance
// overlay, with env vars injected.
func dockerCompose(composeFile string, env []string, repoRoot, project string, args ...string) *exec.Cmd {
	full := []string{"compose", "-f", composeFile}
	if override := privacyComposeOverride(repoRoot); override != "" {
		full = append(full, "-f", override)
	}
	full = append(full, "-p", project)
	full = append(full, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = repoRoot
	cmd.Env = mergedEnv(os.Environ(), env)
	return cmd
}

// capturePrivacyComposeArtifacts preserves project state immediately before
// teardown when the harness supplied an artifact directory. Captures are
// best-effort diagnostics: a logging failure must not prevent Compose cleanup.
func capturePrivacyComposeArtifacts(t *testing.T, composeFile string, env []string, repoRoot, project string) {
	t.Helper()
	artifactDir := strings.TrimSpace(os.Getenv("E2E_ARTIFACT_DIR"))
	if artifactDir == "" {
		return
	}
	if !filepath.IsAbs(artifactDir) {
		artifactDir = filepath.Join(repoRoot, artifactDir)
	}
	artifactDir = filepath.Clean(artifactDir)
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		t.Logf("create privacy artifact directory %s: %v", artifactDir, err)
		return
	}

	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	captures := []struct {
		name string
		args []string
	}{
		{name: "ps", args: []string{"ps", "--all"}},
		{name: "logs", args: []string{"logs", "--no-color"}},
	}
	for _, capture := range captures {
		path := filepath.Join(artifactDir, fmt.Sprintf("privacy-compose-pre-down-%s-%s.log", stamp, capture.name))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			t.Logf("create privacy Compose artifact %s: %v", path, err)
			continue
		}
		cmd := dockerCompose(composeFile, env, repoRoot, project, capture.args...)
		cmd.Stdout = file
		cmd.Stderr = file
		runErr := cmd.Run()
		closeErr := file.Close()
		if runErr != nil {
			t.Logf("capture privacy Compose %s to %s: %v", capture.name, path, runErr)
		}
		if closeErr != nil {
			t.Logf("close privacy Compose artifact %s: %v", path, closeErr)
		}
	}
}

// mergedEnv gives explicit test values precedence even when the caller has the
// same variables set. Passing duplicate keys to a child process is ambiguous
// across platforms and can otherwise defeat isolation settings such as the
// loopback bind and dynamic host ports.
func mergedEnv(base, overrides []string) []string {
	overridden := make(map[string]bool, len(overrides))
	for _, entry := range overrides {
		if key, _, ok := strings.Cut(entry, "="); ok {
			overridden[key] = true
		}
	}

	out := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if ok && overridden[key] {
			continue
		}
		out = append(out, entry)
	}
	return append(out, overrides...)
}

// composePublishedPort discovers a public binding through the exact Compose
// project started by this test. Docker chooses the port when HOST_PORT_*=0, so
// no machine-global default or unrelated listener is trusted as the oracle.
func composePublishedPort(t *testing.T, composeFile string, env []string, repoRoot, project, service string, containerPort int) int {
	t.Helper()
	cmd := dockerCompose(composeFile, env, repoRoot, project, "port", service, strconv.Itoa(containerPort))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("resolve %s port %d for project %s: %v\n%s", service, containerPort, project, err, string(out))
	}

	bindings := strings.Fields(string(out))
	if len(bindings) != 1 {
		t.Fatalf("expected exactly one project-owned binding for %s:%d, got %q", service, containerPort, strings.TrimSpace(string(out)))
	}
	host, portText, err := net.SplitHostPort(bindings[0])
	if err != nil {
		t.Fatalf("parse project-owned binding %q for %s:%d: %v", bindings[0], service, containerPort, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		t.Fatalf("project %s published %s:%d on non-loopback host %q", project, service, containerPort, host)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		t.Fatalf("parse project-owned host port %q for %s:%d", portText, service, containerPort)
	}

	containers := inspectProjectService(t, composeFile, env, repoRoot, project, service)
	if len(containers) != 1 {
		t.Fatalf("expected one container to own public binding %s:%d, got %d", service, containerPort, len(containers))
	}
	containerPortKey := fmt.Sprintf("%d/tcp", containerPort)
	owned := false
	for _, binding := range containers[0].NetworkSettings.Ports[containerPortKey] {
		if binding.HostPort == portText && binding.HostIP == host {
			owned = true
			break
		}
	}
	if !owned {
		t.Fatalf("binding %s for %s:%d is not attributed to project %s container %s", bindings[0], service, containerPort, project, containers[0].Name)
	}
	return port
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type dockerContainerInspection struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	NetworkSettings struct {
		Ports map[string][]dockerPortBinding `json:"Ports"`
	} `json:"NetworkSettings"`
}

// inspectProjectService resolves containers through Compose and then verifies
// the ownership labels before returning any runtime state to an assertion.
func inspectProjectService(t *testing.T, composeFile string, env []string, repoRoot, project, service string) []dockerContainerInspection {
	t.Helper()
	ps := dockerCompose(composeFile, env, repoRoot, project, "ps", "--all", "--quiet", service)
	out, err := ps.CombinedOutput()
	if err != nil {
		t.Fatalf("list containers for project %s service %s: %v\n%s", project, service, err, string(out))
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		t.Fatalf("project %s has no container for service %s", project, service)
	}

	inspect := exec.Command("docker", append([]string{"inspect"}, ids...)...)
	inspect.Dir = repoRoot
	inspectOut, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatalf("inspect project %s service %s: %v\n%s", project, service, err, string(inspectOut))
	}
	var containers []dockerContainerInspection
	if err := json.Unmarshal(inspectOut, &containers); err != nil {
		t.Fatalf("parse docker inspect for project %s service %s: %v", project, service, err)
	}
	if len(containers) != len(ids) {
		t.Fatalf("inspect returned %d containers for %d project-owned IDs (%s/%s)", len(containers), len(ids), project, service)
	}
	for _, container := range containers {
		if got := container.Config.Labels["com.docker.compose.project"]; got != project {
			t.Fatalf("container %s resolved for %s/%s has Compose project label %q", container.Name, project, service, got)
		}
		if got := container.Config.Labels["com.docker.compose.service"]; got != service {
			t.Fatalf("container %s resolved for %s/%s has Compose service label %q", container.Name, project, service, got)
		}
	}
	return containers
}

func assertNoPublishedPortsOnProjectService(t *testing.T, composeFile string, env []string, repoRoot, project string, service internalService) {
	t.Helper()
	containers := inspectProjectService(t, composeFile, env, repoRoot, project, service.Service)
	for _, container := range containers {
		for containerPort, bindings := range container.NetworkSettings.Ports {
			if len(bindings) == 0 {
				continue
			}
			t.Errorf("project %s internal service %s container %s publishes %s via %+v; expected internal port %d and every other port to remain project-internal", project, service.Service, container.Name, containerPort, bindings, service.Port)
		}
	}
}

// assertNoPublishedInternalPortsInConfig parses `docker compose config
// --format json` and fails the test if any internal-zone service
// (indexer-zone or bff-zone) declares a host port mapping.
func assertNoPublishedInternalPortsInConfig(t *testing.T, composeFile string, env []string, repoRoot, project string, internal []internalService) {
	t.Helper()
	cmd := dockerCompose(composeFile, env, repoRoot, project, "config", "--format", "json")
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
//  1. From indexer-zone, chain-indexer:50051 IS reachable. This positive
//     control gates the negative assertion so a broken probe or target cannot
//     produce a vacuous pass.
//  2. From bff-zone, chain-indexer:50051 must NOT be reachable. This is
//     the load-bearing assertion — a misbuilt BFF that lost its
//     `--target privacy` tag or had INDEXER_URL set must still fail to
//     reach the indexer because the network forbids it.
//
// Probes use a throwaway alpine container attached to one zone at a
// time. busybox `nc -z -w 3` exits 0 on a successful TCP connect.
func assertCrossZoneIsolation(t *testing.T, project string) {
	t.Helper()

	probe := func(network string) ([]byte, error) {
		cmd := exec.Command("docker", "run", "--rm",
			"--network", network,
			"alpine:latest",
			"nc", "-z", "-w", "3", "chain-indexer", "50051")
		return cmd.CombinedOutput()
	}

	bffNet := project + "_bff-zone"
	indexerNet := project + "_indexer-zone"

	// A failing positive control invalidates the negative oracle. Retry because
	// chain-indexer has no Compose healthcheck and may only just have started.
	deadline := time.Now().Add(30 * time.Second)
	for {
		out, err := probe(indexerNet)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("positive control failed: from %s, chain-indexer:50051 should be reachable: %v\n%s", indexerNet, err, string(out))
		}
		time.Sleep(time.Second)
	}

	// Negative case — load-bearing assertion, now gated by the control above.
	if _, err := probe(bffNet); err == nil {
		t.Fatalf("from %s, chain-indexer:50051 IS reachable — the two-zone trust split is broken. The block-explorer BFF could now bypass Open Privacy Suite at the network layer. Check the compose file: chain-indexer must be on indexer-zone only, the BFF must be on bff-zone only, and proxy-backend (the BridgeService) must be the only service on both.", bffNet)
	}
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
