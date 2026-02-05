// Package config provides TOML configuration loading for privacy-cli.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config represents the privacy-cli configuration.
type Config struct {
	// API configuration
	API APIConfig `toml:"api"`

	// Organization configuration
	Org OrgConfig `toml:"org"`

	// CREATE3 factory configuration
	Create3 Create3Config `toml:"create3"`
}

// APIConfig contains API connection settings.
type APIConfig struct {
	// BaseURL is the privacy proxy API URL (e.g., "http://localhost:8080")
	BaseURL string `toml:"base_url"`
	// Token is the Bearer token for authentication
	Token string `toml:"token"`
}

// OrgConfig contains organization settings.
type OrgConfig struct {
	// ID is the organization ID to use for operations
	ID string `toml:"id"`
}

// Create3Config contains CREATE3 factory settings.
type Create3Config struct {
	// Factory is the CREATE3 factory contract address
	Factory string `toml:"factory"`
	// SaltPrefix is the default prefix for salt generation
	SaltPrefix string `toml:"salt_prefix"`
}

// DefaultConfigPath is the default configuration file path.
const DefaultConfigPath = "privacy.toml"

// envVarRegex matches environment variable references like ${VAR} or $VAR
var envVarRegex = regexp.MustCompile(`\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expandEnvVars expands environment variable references in a string.
// Supports both ${VAR} and $VAR syntax.
// If a variable is not set, it is replaced with an empty string.
func expandEnvVars(s string) string {
	return envVarRegex.ReplaceAllStringFunc(s, func(match string) string {
		var varName string
		if strings.HasPrefix(match, "${") {
			// ${VAR} syntax
			varName = match[2 : len(match)-1]
		} else {
			// $VAR syntax
			varName = match[1:]
		}
		return os.Getenv(varName)
	})
}

// Load loads configuration from the specified path.
// If path is empty, it uses DefaultConfigPath.
// Environment variables in values are expanded using ${VAR} or $VAR syntax.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultConfigPath
	}

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables in the content
	content := expandEnvVars(string(data))

	// Parse TOML
	var cfg Config
	if _, err := toml.Decode(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return &cfg, nil
}

// LoadOrDefault loads configuration from the specified path.
// If the file doesn't exist, returns a default configuration without error.
func LoadOrDefault(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "not found") {
			return &Config{}, nil
		}
		return nil, err
	}
	return cfg, nil
}

// Validate checks that required configuration values are set.
func (c *Config) Validate() error {
	var missing []string

	if c.API.BaseURL == "" {
		missing = append(missing, "api.base_url")
	}
	if c.API.Token == "" {
		missing = append(missing, "api.token")
	}
	if c.Org.ID == "" {
		missing = append(missing, "org.id")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	return nil
}

// ValidateForPreregister checks that configuration required for preregistration is set.
func (c *Config) ValidateForPreregister() error {
	if err := c.Validate(); err != nil {
		return err
	}

	if c.Create3.Factory == "" {
		return fmt.Errorf("missing required configuration: create3.factory")
	}

	return nil
}

// Example returns an example configuration file content.
func Example() string {
	return `# Privacy CLI Configuration
# Environment variables can be used with ${VAR} or $VAR syntax

[api]
# Privacy proxy API URL
base_url = "http://localhost:8080"
# Bearer token for authentication (use env var for security)
token = "${PRIVACY_API_TOKEN}"

[org]
# Organization ID
id = "your-org-id"

[create3]
# CREATE3 factory contract address
factory = "0x0000000000ffe8b47b3e2130213b802212439497"
# Default salt prefix for address generation
salt_prefix = "my-project"
`
}
