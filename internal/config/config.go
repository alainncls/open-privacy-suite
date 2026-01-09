package config

import (
	"os"
)

type Config struct {
	NodeURL     string
	DatabaseURL string
	BillionsURL string
}

func Load() *Config {
	return &Config{
		NodeURL:     getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"),
		BillionsURL: getEnv("BILLIONS_URL", "http://localhost:9000"), // Mock service
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
