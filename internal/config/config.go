package config

import (
	"os"
)

type Config struct {
	NodeURL          string
	DatabaseURL      string
	BillionsURL      string
	PrivadoRPCURL    string
	IPFSGateway      string
	JWTSecret        string
	JWTRefreshSecret string
}

func Load() *Config {
	return &Config{
		NodeURL:          getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL:      getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"),
		BillionsURL:      getEnv("BILLIONS_URL", "http://localhost:9000"), // Mock service (deprecated, kept for compatibility)
		PrivadoRPCURL:    getEnv("PRIVADO_RPC_URL", "https://rpc-mainnet.privado.id"),
		IPFSGateway:      getEnv("IPFS_GATEWAY", "https://ipfs-proxy-cache.privado.id"), // IPFS gateway for schema resolution
		JWTSecret:        getEnv("JWT_SECRET", ""), // If empty, will be auto-generated (dev only)
		JWTRefreshSecret: getEnv("JWT_REFRESH_SECRET", ""), // If empty, will be auto-generated (dev only)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
