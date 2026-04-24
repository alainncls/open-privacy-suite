package e2e

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// TrustZoneConfig mirrors deployments/privacy/trust-zone.yaml — the single
// source of truth for what counts as trust-zone vs. public in privacy mode.
// Consumed by both the static compose-manifest test (PR-gated) and the
// runtime negative-network test (schedule-gated).
type TrustZoneConfig struct {
	Version int `yaml:"version"`

	TrustZone []TrustZoneService `yaml:"trust_zone"`
	Public    []PublicService    `yaml:"public"`
}

type TrustZoneService struct {
	Name                string `yaml:"name"`
	DefaultInternalPort int    `yaml:"default_internal_port"`
	Description         string `yaml:"description"`
}

type PublicService struct {
	Name            string `yaml:"name"`
	HostPortEnv     string `yaml:"host_port_env"`
	DefaultHostPort int    `yaml:"default_host_port"`
	Description     string `yaml:"description"`
}

// LoadTrustZone reads deployments/privacy/trust-zone.yaml relative to the
// privacy-proxy repo root. repoRoot should be an absolute path.
func LoadTrustZone(repoRoot string) (*TrustZoneConfig, error) {
	path := filepath.Join(repoRoot, "deployments", "privacy", "trust-zone.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg TrustZoneConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("%s: unsupported version %d (expected 1)", path, cfg.Version)
	}
	if len(cfg.TrustZone) == 0 {
		return nil, fmt.Errorf("%s: trust_zone list is empty — misconfiguration", path)
	}
	return &cfg, nil
}
