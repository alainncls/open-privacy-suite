package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear relevant environment variables
	envVars := []string{
		"NODE_URL", "DATABASE_URL", "PRIVADO_RPC_URL",
		"IPFS_GATEWAY", "JWT_SECRET", "JWT_REFRESH_SECRET", "VERIFIER_ID",
		"BASE_URL", "PORT", "ENVIRONMENT", "BILLIONS_ISSUER_DID",
		"REQUIRE_PROOF_OF_HUMANITY",
	}

	// Save and clear env vars
	savedEnv := make(map[string]string)
	for _, env := range envVars {
		savedEnv[env] = os.Getenv(env)
		os.Unsetenv(env)
	}

	// Restore env vars after test
	defer func() {
		for env, val := range savedEnv {
			if val != "" {
				os.Setenv(env, val)
			}
		}
	}()

	cfg := Load()

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"NodeURL", cfg.NodeURL, "http://localhost:8545"},
		{"DatabaseURL", cfg.DatabaseURL, "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"},
		{"PrivadoRPCURL", cfg.PrivadoRPCURL, "https://rpc-mainnet.privado.id"},
		{"IPFSGateway", cfg.IPFSGateway, "https://ipfs-proxy-cache.privado.id"},
		{"JWTSecret", cfg.JWTSecret, ""},
		{"JWTRefreshSecret", cfg.JWTRefreshSecret, ""},
		{"VerifierID", cfg.VerifierID, ""},
		{"BaseURL", cfg.BaseURL, "http://localhost:8080"},
		{"Port", cfg.Port, "8080"},
		{"Environment", cfg.Environment, "development"},
		{"BillionsIssuerDID", cfg.BillionsIssuerDID, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}

	// In development mode, RequireProofOfHumanity defaults to false
	if cfg.RequireProofOfHumanity {
		t.Error("RequireProofOfHumanity should default to false in development")
	}
}

func TestLoad_EnvOverride(t *testing.T) {
	// Set environment variables
	testEnv := map[string]string{
		"NODE_URL":            "http://custom-node:8545",
		"DATABASE_URL":        "postgres://user:pass@db:5432/test",
		"PRIVADO_RPC_URL":     "https://custom-rpc.privado.id",
		"IPFS_GATEWAY":        "https://custom-ipfs.io",
		"ADMIN_API_TOKEN":     "admin-token",
		"JWT_SECRET":          "super-secret-jwt",
		"JWT_REFRESH_SECRET":  "super-secret-refresh",
		"VERIFIER_ID":         "did:test:verifier",
		"BASE_URL":            "https://api.example.com",
		"PORT":                "3000",
		"ENVIRONMENT":         "staging",
		"BILLIONS_ISSUER_DID": "did:test:billions",
	}

	// Save current env and set test values
	savedEnv := make(map[string]string)
	for key, val := range testEnv {
		savedEnv[key] = os.Getenv(key)
		os.Setenv(key, val)
	}

	// Restore env vars after test
	defer func() {
		for key, val := range savedEnv {
			if val != "" {
				os.Setenv(key, val)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	cfg := Load()

	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{"NodeURL", cfg.NodeURL, testEnv["NODE_URL"]},
		{"DatabaseURL", cfg.DatabaseURL, testEnv["DATABASE_URL"]},
		{"PrivadoRPCURL", cfg.PrivadoRPCURL, testEnv["PRIVADO_RPC_URL"]},
		{"IPFSGateway", cfg.IPFSGateway, testEnv["IPFS_GATEWAY"]},
		{"AdminAPIToken", cfg.AdminAPIToken, testEnv["ADMIN_API_TOKEN"]},
		{"JWTSecret", cfg.JWTSecret, testEnv["JWT_SECRET"]},
		{"JWTRefreshSecret", cfg.JWTRefreshSecret, testEnv["JWT_REFRESH_SECRET"]},
		{"VerifierID", cfg.VerifierID, testEnv["VERIFIER_ID"]},
		{"BaseURL", cfg.BaseURL, testEnv["BASE_URL"]},
		{"Port", cfg.Port, testEnv["PORT"]},
		{"Environment", cfg.Environment, testEnv["ENVIRONMENT"]},
		{"BillionsIssuerDID", cfg.BillionsIssuerDID, testEnv["BILLIONS_ISSUER_DID"]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %q, want %q", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestLoad_ProductionMode(t *testing.T) {
	// Save and set env vars
	savedEnv := os.Getenv("ENVIRONMENT")
	savedPoH := os.Getenv("REQUIRE_PROOF_OF_HUMANITY")
	os.Setenv("ENVIRONMENT", "production")
	os.Unsetenv("REQUIRE_PROOF_OF_HUMANITY")

	defer func() {
		if savedEnv != "" {
			os.Setenv("ENVIRONMENT", savedEnv)
		} else {
			os.Unsetenv("ENVIRONMENT")
		}
		if savedPoH != "" {
			os.Setenv("REQUIRE_PROOF_OF_HUMANITY", savedPoH)
		}
	}()

	cfg := Load()

	if cfg.Environment != "production" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "production")
	}

	// In production mode, RequireProofOfHumanity defaults to true
	if !cfg.RequireProofOfHumanity {
		t.Error("RequireProofOfHumanity should default to true in production")
	}
}

func TestLoad_RequireProofOfHumanity_ExplicitOverride(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		pohSetting  string
		expected    bool
	}{
		{
			name:        "production with explicit false",
			environment: "production",
			pohSetting:  "false",
			expected:    false,
		},
		{
			name:        "development with explicit true",
			environment: "development",
			pohSetting:  "true",
			expected:    true,
		},
		{
			name:        "production with explicit true",
			environment: "production",
			pohSetting:  "true",
			expected:    true,
		},
		{
			name:        "development with explicit false",
			environment: "development",
			pohSetting:  "false",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save env vars
			savedEnv := os.Getenv("ENVIRONMENT")
			savedPoH := os.Getenv("REQUIRE_PROOF_OF_HUMANITY")

			os.Setenv("ENVIRONMENT", tt.environment)
			os.Setenv("REQUIRE_PROOF_OF_HUMANITY", tt.pohSetting)

			defer func() {
				if savedEnv != "" {
					os.Setenv("ENVIRONMENT", savedEnv)
				} else {
					os.Unsetenv("ENVIRONMENT")
				}
				if savedPoH != "" {
					os.Setenv("REQUIRE_PROOF_OF_HUMANITY", savedPoH)
				} else {
					os.Unsetenv("REQUIRE_PROOF_OF_HUMANITY")
				}
			}()

			cfg := Load()

			if cfg.RequireProofOfHumanity != tt.expected {
				t.Errorf("RequireProofOfHumanity = %v, want %v", cfg.RequireProofOfHumanity, tt.expected)
			}
		})
	}
}

func TestConfig_IsProduction(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		expected    bool
	}{
		{"production", "production", true},
		{"development", "development", false},
		{"staging", "staging", false},
		{"empty", "", false},
		{"prod (partial)", "prod", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Environment: tt.environment,
			}

			if got := cfg.IsProduction(); got != tt.expected {
				t.Errorf("IsProduction() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "development mode allows empty secrets",
			config: &Config{
				Environment:      "development",
				JWTSecret:        "",
				JWTRefreshSecret: "",
				AdminAPIToken:    "",
				VerifierID:       "",
			},
			expectError: false,
		},
		{
			name: "production mode requires JWT_SECRET",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "",
				JWTRefreshSecret: "secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "JWT_SECRET is required in production",
		},
		{
			name: "production mode requires JWT_REFRESH_SECRET",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "JWT_REFRESH_SECRET is required in production",
		},
		{
			name: "production mode requires VERIFIER_ID",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "",
			},
			expectError: true,
			errorMsg:    "VERIFIER_ID is required in production for authentication",
		},
		{
			name: "production mode requires ADMIN_API_TOKEN",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "",
				VerifierID:       "did:test:verifier",
			},
			expectError: true,
			errorMsg:    "ADMIN_API_TOKEN is required in production for admin API authentication",
		},
		{
			name: "production mode requires NODE_URL",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "",
			},
			expectError: true,
			errorMsg:    "NODE_URL is required in production (Ethereum node JSON-RPC endpoint)",
		},
		{
			name: "production mode requires BASE_URL",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "http://node:8545",
				BaseURL:          "",
			},
			expectError: true,
			errorMsg:    "BASE_URL is required in production (public URL for OAuth callbacks)",
		},
		{
			name: "production mode with all required values passes",
			config: &Config{
				Environment:      "production",
				JWTSecret:        "secret",
				JWTRefreshSecret: "refresh-secret",
				AdminAPIToken:    "admin-token",
				VerifierID:       "did:test:verifier",
				NodeURL:          "http://node:8545",
				BaseURL:          "https://proxy.example.com",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.errorMsg)
				} else if err.Error() != tt.errorMsg {
					t.Errorf("Validate() error = %q, want %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		setEnv       bool
		expected     string
	}{
		{
			name:         "returns env value when set",
			key:          "TEST_VAR_1",
			defaultValue: "default",
			envValue:     "custom",
			setEnv:       true,
			expected:     "custom",
		},
		{
			name:         "returns default when not set",
			key:          "TEST_VAR_2",
			defaultValue: "default",
			envValue:     "",
			setEnv:       false,
			expected:     "default",
		},
		{
			name:         "returns env value even if empty string when explicitly set",
			key:          "TEST_VAR_3",
			defaultValue: "default",
			envValue:     "",
			setEnv:       true,
			expected:     "default", // Empty string counts as unset
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env var first
			os.Unsetenv(tt.key)

			if tt.setEnv && tt.envValue != "" {
				os.Setenv(tt.key, tt.envValue)
			}

			defer os.Unsetenv(tt.key)

			got := getEnv(tt.key, tt.defaultValue)
			if got != tt.expected {
				t.Errorf("getEnv(%q, %q) = %q, want %q", tt.key, tt.defaultValue, got, tt.expected)
			}
		})
	}
}

func TestExtraRPCNamespaces_UnmarshalJSON(t *testing.T) {
	t.Run("valid config with aliases", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [
					{"method": "linea_estimateGas", "alias": "eth_estimateGas"},
					{"method": "linea_getProof", "alias": "eth_getProof"}
				]
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Version != 1 {
			t.Errorf("Version = %d, want 1", cfg.Version)
		}
		methods := cfg.Namespaces["Linea"]
		if len(methods) != 2 {
			t.Fatalf("expected 2 methods, got %d", len(methods))
		}
		if methods[0].Method != "linea_estimateGas" || methods[0].Alias != "eth_estimateGas" {
			t.Errorf("method[0] = %+v, want linea_estimateGas/eth_estimateGas", methods[0])
		}
	})

	t.Run("plain string rejected — alias required", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": ["linea_estimateGas"]
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil {
			t.Fatal("expected error for plain string method (no alias), got nil")
		}
	})

	t.Run("object without alias rejected", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [{"method": "linea_estimateGas"}]
			}
		}`
		var cfg ExtraRPCNamespaces
		err := cfg.UnmarshalJSON([]byte(input))
		if err == nil {
			t.Fatal("expected error for method without alias, got nil")
		}
		if !strings.Contains(err.Error(), "missing 'alias'") {
			t.Errorf("error should mention missing alias, got: %v", err)
		}
	})

	t.Run("aliases helper", func(t *testing.T) {
		input := `{
			"version": 1,
			"namespaces": {
				"Linea": [
					{"method": "linea_estimateGas", "alias": "eth_estimateGas"},
					{"method": "linea_getProof", "alias": "eth_getProof"}
				]
			}
		}`
		var cfg ExtraRPCNamespaces
		if err := cfg.UnmarshalJSON([]byte(input)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		aliases := cfg.Aliases()
		if aliases["linea_estimateGas"] != "eth_estimateGas" {
			t.Errorf("alias for linea_estimateGas = %q, want eth_estimateGas", aliases["linea_estimateGas"])
		}
		if aliases["linea_getProof"] != "eth_getProof" {
			t.Errorf("alias for linea_getProof = %q, want eth_getProof", aliases["linea_getProof"])
		}
	})
}
