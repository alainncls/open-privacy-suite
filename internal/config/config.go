package config

import (
	"os"
)

type Config struct {
	NodeURL                    string
	DatabaseURL                string
	PrivadoRPCURL              string
	IPFSGateway                string
	JWTSecret                  string
	JWTRefreshSecret           string
	VerifierID                 string // DID or identifier of the verifier
	BaseURL                    string // Base URL for callback (e.g., https://api.example.com)
	Port                       string // Server port (e.g., "8080")
	Environment                string // "production" or "development"
	BillionsIssuerDID          string // Billions issuer DID for ProofOfHumanity verification
	RequireProofOfHumanity     bool   // Whether to require ProofOfHumanity credential (default: true in prod)
	AllowUnregisteredAddresses bool   // If true, addresses not in RBAC bypass permission checks (default: true)
	ENSResolverURL             string // Ethereum mainnet RPC URL for ENS resolution
}

func Load() *Config {
	env := getEnv("ENVIRONMENT", "development")
	// Default RequireProofOfHumanity to true in production, false in development
	requirePoH := getEnv("REQUIRE_PROOF_OF_HUMANITY", "")
	requirePoHBool := env == "production" // Default based on environment
	if requirePoH == "true" {
		requirePoHBool = true
	} else if requirePoH == "false" {
		requirePoHBool = false
	}

	// Default AllowUnregisteredAddresses to true (addresses not in RBAC bypass permission checks)
	allowUnregistered := getEnv("ALLOW_UNREGISTERED_ADDRESSES", "")
	allowUnregisteredBool := true // Default to true (bypass enabled)
	if allowUnregistered == "false" {
		allowUnregisteredBool = false
	}

	return &Config{
		NodeURL:                getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL:            getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"),
		PrivadoRPCURL:          getEnv("PRIVADO_RPC_URL", "https://rpc-mainnet.privado.id"),
		IPFSGateway:            getEnv("IPFS_GATEWAY", "https://ipfs-proxy-cache.privado.id"), // IPFS gateway for schema resolution
		JWTSecret:              getEnv("JWT_SECRET", ""),                                      // If empty, will be auto-generated (dev only)
		JWTRefreshSecret:       getEnv("JWT_REFRESH_SECRET", ""),                              // If empty, will be auto-generated (dev only)
		VerifierID:             getEnv("VERIFIER_ID", ""),                                     // Required in production
		BaseURL:                getEnv("BASE_URL", "http://localhost:8080"),                   // Base URL for callback
		Port:                   getEnv("PORT", "8080"),                                        // Server port
		Environment:                env,
		BillionsIssuerDID:          getEnv("BILLIONS_ISSUER_DID", ""),                  // Billions issuer DID for PoH
		RequireProofOfHumanity:     requirePoHBool,
		AllowUnregisteredAddresses: allowUnregisteredBool,
		ENSResolverURL:             getEnv("ENS_RESOLVER_URL", "https://eth.llamarpc.com"), // Public mainnet RPC
	}
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
