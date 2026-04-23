package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestPrivacyManifest_NoTrustZonePortsPublished is the fast, always-on
// static check that goes with the heavier runtime negative-network test
// in privacy_bypass_test.go.
//
// It parses docker-compose.privacy.yml directly (no Docker required) and
// asserts that every service listed in deployments/privacy/trust-zone.yaml
// does not declare a `ports:` block. Catches the regression where
// someone adds `ports: ["50051:50051"]` to the indexer service — which
// would reopen the bypass — at the PR level, not later via the weekly
// runtime test.
//
// Runs as part of the regular `make test-e2e` and therefore the pre-push
// hook and CI.
func TestPrivacyManifest_NoTrustZonePortsPublished(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}
	trustZoneNames := map[string]bool{}
	for _, s := range cfg.TrustZone {
		trustZoneNames[s.Name] = true
	}

	composePath := filepath.Join(repoRoot, "docker-compose.privacy.yml")
	b, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}

	// Parse the compose YAML loosely — we only need services.<name>.ports.
	var compose struct {
		Services map[string]struct {
			Ports []any `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &compose); err != nil {
		t.Fatalf("parse compose yaml: %v", err)
	}

	missingServices := []string{}
	for name := range trustZoneNames {
		if _, ok := compose.Services[name]; !ok {
			missingServices = append(missingServices, name)
		}
	}
	if len(missingServices) > 0 {
		t.Fatalf("trust-zone.yaml lists services that are not in docker-compose.privacy.yml: %s. Either add them to the compose file or remove them from trust-zone.yaml.",
			strings.Join(missingServices, ", "))
	}

	for name, svc := range compose.Services {
		if !trustZoneNames[name] {
			continue
		}
		if len(svc.Ports) > 0 {
			t.Errorf("service %q is in trust_zone but declares %d port mapping(s) in docker-compose.privacy.yml — this reopens the RD-855 bypass. Either remove the ports: block or remove %q from deployments/privacy/trust-zone.yaml.", name, len(svc.Ports), name)
		}
	}
}

// TestPrivacyManifest_PublicServicesArePublished is the positive
// counterpart: services listed under `public:` MUST declare a ports
// block. Catches the regression where someone removes port publishing
// from proxy-frontend, silently making the product unreachable.
func TestPrivacyManifest_PublicServicesArePublished(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}

	cfg, err := LoadTrustZone(repoRoot)
	if err != nil {
		t.Fatalf("load trust-zone.yaml: %v", err)
	}

	composePath := filepath.Join(repoRoot, "docker-compose.privacy.yml")
	b, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("read %s: %v", composePath, err)
	}
	var compose struct {
		Services map[string]struct {
			Ports []any `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(b, &compose); err != nil {
		t.Fatalf("parse compose: %v", err)
	}

	for _, pub := range cfg.Public {
		svc, ok := compose.Services[pub.Name]
		if !ok {
			t.Errorf("public service %q missing from docker-compose.privacy.yml", pub.Name)
			continue
		}
		if len(svc.Ports) == 0 {
			t.Errorf("public service %q declares no ports in compose — users will not be able to reach it", pub.Name)
		}
	}
}
