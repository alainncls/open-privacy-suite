package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/proxy"
)

// ExtraRPCNamespaces defines additional JSON-RPC method namespaces
// that the proxy should accept and forward to the node.
// This allows operators to support chain-specific methods (e.g. Linea's linea_*)
// without code changes.
//
// Schema versions:
//
//   - v1: each namespace value is an array of {method, alias} entries (explicit only).
//   - v2: each namespace value is either an array (same as v1) or an object
//     {"explicit": [...], "wildcard": {"prefix": "...", "deny": [...]}}. The
//     wildcard block lets operators allow any method matching the prefix to pass
//     through without alias-based redaction; see WildcardConfig.
type ExtraRPCNamespaces struct {
	Version    int                        `json:"version"`
	Namespaces map[string]NamespaceConfig `json:"-"` // parsed from mixed JSON shape
}

// NamespaceConfig holds the explicit and (optional) wildcard configuration for
// one chain-specific namespace. v1 arrays parse into Explicit only; v2 objects
// may also set Wildcard.
type NamespaceConfig struct {
	Explicit []ExtraRPCMethod
	Wildcard *WildcardConfig
}

// ExtraRPCMethod represents a single explicit chain-specific RPC method entry.
// Every entry must have an alias to a standard Ethereum method so contract
// access checks and response redaction inherit a known shape.
type ExtraRPCMethod struct {
	Method string `json:"method"`          // The chain-specific method name (e.g. "linea_estimateGas")
	Alias  string `json:"alias,omitempty"` // Standard method to inherit access control from (e.g. "eth_estimateGas")
}

// WildcardConfig opts a namespace into prefix-wildcard mode (v2+). Methods that
// start with Prefix and don't match any Deny glob are forwarded to the upstream
// node as-is — no contract access check, no field-level redaction. The proxy
// trusts the operator's deny list + the global blocklist; the operator owns
// responsibility for what the upstream may expose under this prefix.
type WildcardConfig struct {
	// Prefix is matched verbatim against the start of the method name (e.g. "linea_").
	// Required; must be non-empty.
	Prefix string `json:"prefix"`

	// Deny is a list of glob patterns (suffix-* supported) that block specific
	// methods even when they match Prefix. Evaluated before the prefix allow.
	// Examples: "linea_sendTransaction", "linea_sign*".
	Deny []string `json:"deny,omitempty"`
}

// UnmarshalJSON dispatches on the JSON shape of each namespace value:
//   - array → v1-style explicit list
//   - object → v2-style {explicit, wildcard}
//
// The object form is rejected when the file declares Version < 2.
func (e *ExtraRPCNamespaces) UnmarshalJSON(data []byte) error {
	var raw struct {
		Version    int                          `json:"version"`
		Namespaces map[string]json.RawMessage   `json:"namespaces"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.Version = raw.Version
	e.Namespaces = make(map[string]NamespaceConfig, len(raw.Namespaces))
	for ns, entry := range raw.Namespaces {
		nc, err := parseNamespaceConfig(ns, entry, raw.Version)
		if err != nil {
			return err
		}
		e.Namespaces[ns] = nc
	}
	return nil
}

func parseNamespaceConfig(ns string, raw json.RawMessage, version int) (NamespaceConfig, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return NamespaceConfig{}, fmt.Errorf("namespace %q: empty value", ns)
	}
	switch trimmed[0] {
	case '[':
		entries, err := parseExplicitMethods(ns, trimmed)
		if err != nil {
			return NamespaceConfig{}, err
		}
		return NamespaceConfig{Explicit: entries}, nil
	case '{':
		if version < 2 {
			return NamespaceConfig{}, fmt.Errorf("namespace %q: object form (with wildcard) requires version >= 2 in the EXTRA_RPC_NAMESPACES file", ns)
		}
		var obj struct {
			Explicit []json.RawMessage `json:"explicit"`
			Wildcard *WildcardConfig   `json:"wildcard,omitempty"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return NamespaceConfig{}, fmt.Errorf("namespace %q: invalid object: %w", ns, err)
		}
		// Re-marshal explicit entries through parseExplicitMethods so validation
		// stays in one place. Build a synthetic JSON array for it.
		var explicit []ExtraRPCMethod
		if len(obj.Explicit) > 0 {
			arrBytes, err := json.Marshal(obj.Explicit)
			if err != nil {
				return NamespaceConfig{}, fmt.Errorf("namespace %q: failed to re-marshal explicit list: %w", ns, err)
			}
			explicit, err = parseExplicitMethods(ns, arrBytes)
			if err != nil {
				return NamespaceConfig{}, err
			}
		}
		if obj.Wildcard != nil {
			if err := obj.Wildcard.validate(ns); err != nil {
				return NamespaceConfig{}, err
			}
		}
		return NamespaceConfig{Explicit: explicit, Wildcard: obj.Wildcard}, nil
	default:
		return NamespaceConfig{}, fmt.Errorf("namespace %q: value must be a v1-style array or v2-style object, got: %s", ns, string(trimmed))
	}
}

func parseExplicitMethods(ns string, data []byte) ([]ExtraRPCMethod, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("namespace %q: invalid array: %w", ns, err)
	}
	methods := make([]ExtraRPCMethod, 0, len(entries))
	for _, entry := range entries {
		var m ExtraRPCMethod
		if err := json.Unmarshal(entry, &m); err != nil {
			return nil, fmt.Errorf("namespace %q: invalid entry (must be {\"method\":..., \"alias\":...}): %s", ns, string(entry))
		}
		if m.Method == "" {
			return nil, fmt.Errorf("namespace %q: entry missing 'method' field: %s", ns, string(entry))
		}
		if m.Alias == "" {
			return nil, fmt.Errorf("namespace %q: method %q missing 'alias' field — all extra methods must have an alias to a standard Ethereum method for access control and response filtering", ns, m.Method)
		}
		methods = append(methods, m)
	}
	return methods, nil
}

func (w *WildcardConfig) validate(ns string) error {
	if strings.TrimSpace(w.Prefix) == "" {
		return fmt.Errorf("namespace %q wildcard: 'prefix' is required and must be non-empty (e.g. \"linea_\")", ns)
	}
	for _, deny := range w.Deny {
		if strings.TrimSpace(deny) == "" {
			return fmt.Errorf("namespace %q wildcard: 'deny' entries must be non-empty", ns)
		}
	}
	return nil
}

// MethodNames returns a flat list of explicit method names per namespace
// (for the status API; wildcard methods are not enumerated since they are open-ended).
func (e *ExtraRPCNamespaces) MethodNames() map[string][]string {
	result := make(map[string][]string, len(e.Namespaces))
	for ns, nc := range e.Namespaces {
		names := make([]string, len(nc.Explicit))
		for i, m := range nc.Explicit {
			names[i] = m.Method
		}
		result[ns] = names
	}
	return result
}

// Aliases returns a map of method→alias for every explicit chain-specific method.
func (e *ExtraRPCNamespaces) Aliases() map[string]string {
	aliases := make(map[string]string)
	for _, nc := range e.Namespaces {
		for _, m := range nc.Explicit {
			if m.Alias != "" {
				aliases[m.Method] = m.Alias
			}
		}
	}
	return aliases
}

// Wildcards returns the namespace→wildcard config map for namespaces that opt in.
// Used by the rbac registration step at startup.
func (e *ExtraRPCNamespaces) Wildcards() map[string]*WildcardConfig {
	out := make(map[string]*WildcardConfig)
	for ns, nc := range e.Namespaces {
		if nc.Wildcard != nil {
			out[ns] = nc.Wildcard
		}
	}
	return out
}

type Config struct {
	Version                    string // Set by cmd/server/main.go from build-time constant
	NodeURL                    string
	DatabaseURL                string
	ExplorerDatabaseURL        string
	// IndexerURL, when non-empty, enables the gRPC chain-indexer backend for
	// explorer reads. Methods not yet ported to gRPC fall back to direct
	// SQL on the explorer postgres. Leave empty to use SQL exclusively.
	// Set this (and point it at the chain-indexer service) to start the
	// RD-855 Phase 3 cutover.
	IndexerURL                 string
	PrivadoRPCURL              string
	IPFSGateway                string
	JWTSecret                  string
	JWTRefreshSecret           string
	VerifierID                 string        // DID or identifier of the verifier
	BaseURL                    string        // Base URL for callback (e.g., https://api.example.com)
	Port                       string        // Server port (e.g., "8080")
	Environment                string        // "production" or "development"
	BillionsIssuerDID          string        // Billions issuer DID for ProofOfHumanity verification
	RequireProofOfHumanity     bool          // Opt-in enforcement of Path B (credential check). Default: false in every environment.

	// Path B (ProofOfHumanity / Billions) configuration. Only consulted when RequireProofOfHumanity=true.
	PrivadoStateContract        string         // env PRIVADO_STATE_CONTRACT — on-chain identity state contract
	PrivadoCircuitID            string         // env PRIVADO_CIRCUIT_ID — iden3 circuit (e.g. credentialAtomicQueryMTPV2)
	BillionsCredentialSchemaURL string         // env BILLIONS_CREDENTIAL_SCHEMA_URL — JSON-LD schema URL for the credential
	BillionsCredentialType      string         // env BILLIONS_CREDENTIAL_TYPE — credential type name declared by the schema
	BillionsCredentialQueryFile string         // env BILLIONS_CREDENTIAL_QUERY_FILE — path to JSON file with the credential query
	BillionsCredentialQuery     map[string]any // Parsed from BillionsCredentialQueryFile at startup

	AdminAPIToken              string        // Shared token required for admin API access (required in production)
	ENSResolverURL             string        // Ethereum mainnet RPC URL for ENS resolution
	CORSAllowedOrigins         string        // Comma-separated list of allowed origins, or "*" for all (default: "*" in dev)
	MockSignatures             bool          // If true, accept any signature without verification (dev/demo only, NEVER in production)
	AllowMockLogin             bool          // If true, accept mock JWZ tokens for testing (dev/demo only, NEVER in production)
	DemoAutoAuthDelay          time.Duration // Auto-complete auth sessions for demo recording (0 = disabled, forced off in production)
	ExtraRPCNamespacesFile     string                // Path to JSON file with additional RPC method namespaces (e.g. Linea's linea_*)
	ExtraRPCNamespaces         *ExtraRPCNamespaces   // Parsed from ExtraRPCNamespacesFile

	// Runtime tracing configuration
	TraceCacheTTL         time.Duration // TTL for trace result cache (default: 10s)
	TraceTimeout          time.Duration // Timeout for debug_traceCall requests (default: 30s)
	TraceTieredValidation bool          // If true, skip trace for known org addresses (default: true)
	// RuntimeTracingEthCallEnabled controls runtime tracing of eth_call
	// requests for cross-org isolation (RD-915). Default true; only flip
	// to false as a documented sev-1 rollback path. Has no effect when
	// runtime tracing is globally off.
	RuntimeTracingEthCallEnabled bool
	// EthCallTraceTimeout caps how long the proxy will wait for the
	// upstream debug_traceCall on the eth_call validation path. Distinct
	// from the send-side TraceTimeout so a slow upstream cannot fill the
	// concurrency-limiter quota for read-heavy callers (RD-915 KD on
	// per-call timeout). Default 5s.
	EthCallTraceTimeout time.Duration

	// Travel rule compliance configuration
	EnableTravelRule   bool          // If true, enable travel rule enforcement (default: false)
	TravelRecordExpiry time.Duration // How long travel rule records stay valid (default: 24h)

	// Token price fetching configuration
	PriceFetchInterval      time.Duration // How often to fetch prices from CoinGecko (default: 5m)
	PriceStalenessThreshold time.Duration // After this duration, prices are considered stale (default: 15m)
	DisableCoinGecko        bool          // If true, disable CoinGecko price fetching (default: false)

	// Audit configuration
	AuditLogParams bool // If true, log redacted request parameters in access_logs (default: false)

	// Retention policy configuration (0 = keep forever)
	RetentionAccessLogs      time.Duration // Retention for access_logs (default: 90 days)
	RetentionComplianceLogs  time.Duration // Retention for compliance_logs (default: 7 years)
	RetentionRBACAuditLogs   time.Duration // Retention for rbac_audit_log (default: 1 year)
	RetentionTravelRecords   time.Duration // Retention for used travel_rule_records (default: 7 years)
	RetentionCleanupInterval time.Duration // How often retention cleanup runs (default: 1 hour)
	// MaxAccessLogRows caps the access_logs table at this row count using a
	// FIFO sweep that runs alongside the time-based prune. 0 = unlimited
	// (time-based retention only). The hash chain anchor table preserves the
	// chain seed across both prune paths.
	MaxAccessLogRows int64

	// SIEM webhook configuration
	SIEMWebhookURL      string        // SIEM webhook endpoint (empty = disabled)
	SIEMAuthHeader      string        // Authorization header for SIEM webhook
	SIEMBatchSize       int           // Events per SIEM batch (default: 100)
	SIEMFlushInterval   time.Duration // Max time before flushing SIEM batch (default: 10s)
	SIEMFallbackLogPath string        // If set, failed SIEM batches written here as JSON lines (M4 fix)

	// Audit hash-chain integrity worker (RD-858)
	AuditIntegrityVerifyInterval time.Duration // How often the scheduled verifier walks the chains (default: 15m; 0 = disabled).
	AuditTamperWebhookURL        string        // Optional generic webhook POSTed when the verifier detects tampering. Subject to the same SSRF guard as SIEMWebhookURL. Empty = disabled (SIEM-only notification path).

	// Hide the auto-created dev-admin org from the admin dashboard (for demos)
	HideDevAdminOrg bool

	// Tunnel URL file path — cloudflared writes the public URL here (auto-detected)
	TunnelURLFile string

	// Trusted Proxies for X-Forwarded-For trust
	TrustedProxies []string // List of IPs/CIDRs to trust for client IP extraction

	// Additional CIDRs allowed to access internal APIs (explorer, admin).
	// Appended to the default private-network allowlist (localhost, Docker, RFC1918, Tailscale).
	// Use for Kubernetes pod CIDRs, cloud VPC ranges, or custom networks.
	TrustedInternalCIDRs []string

	// Frontend URL for OAuth redirect (e.g., http://localhost:5173)
	// When set, /oauth/authorize redirects browsers to the React login page instead of serving inline HTML.
	FrontendURL string

	// RPC API key for upstream RPC proxy authentication
	RPCAPIKey              string // RPC_API_KEY — global fallback when no group-specific key is set
	RPCAPIKeyHeader        string // RPC_API_KEY_HEADER — header name used to send the RPC API key (default "Authorization", which sends "Bearer <key>"); any other value sends the raw key under that header
	RPCAPIKeyEncryptionKey []byte // RPC_API_KEY_ENCRYPTION_KEY — 32-byte hex key for AES-256 encryption of RPC API keys at rest
	MaxConcurrentRequests  int    // MAX_CONCURRENT_REQUESTS — per-user concurrency cap (default: 50)

	// Azure AD / Microsoft Entra ID authentication
	AzureADClientID     string // AZURE_AD_CLIENT_ID
	AzureADClientSecret string // AZURE_AD_CLIENT_SECRET
	AzureADTenantID     string // AZURE_AD_TENANT_ID (default: "common" for multi-tenant)

	// Redis URL for shared state stores (e.g., "redis://localhost:6379").
	// Empty means fall back to in-memory stores.
	RedisURL string
}

func Load() *Config {
	env := getEnv("ENVIRONMENT", "development")
	// RequireProofOfHumanity is opt-in in every environment. Admin must explicitly
	// set REQUIRE_PROOF_OF_HUMANITY=true AND fill the Path B config (issuer DID,
	// schema URL, credential type, circuit ID, query file). Until then, login is
	// plain DID-ownership proof (Path A). This keeps prod from booting with
	// placeholder credential values that would break login for every user.
	requirePoHBool := getEnv("REQUIRE_PROOF_OF_HUMANITY", "") == "true"

	// Default CORS origins: "*" in dev, must be configured in production
	corsOrigins := getEnv("CORS_ALLOWED_ORIGINS", "")
	if corsOrigins == "" {
		if env == "production" {
			corsOrigins = "" // Empty means no origins allowed - must be configured
		} else {
			corsOrigins = "*" // Allow all in development
		}
	}

	// MockSignatures: Only allow in non-production environments
	// This skips cryptographic signature verification for wallet linking (demo/dev only)
	mockSigs := getEnv("MOCK_SIGNATURES", "false") == "true"
	if mockSigs && env == "production" {
		// Force disable in production - this is a critical security setting
		mockSigs = false
	}

	// AllowMockLogin: Only allow in non-production environments
	// This allows mock JWZ tokens for testing without Privado wallet (demo/dev only)
	allowMockLogin := getEnv("ALLOW_MOCK_LOGIN", "false") == "true"
	if allowMockLogin && env == "production" {
		// Force disable in production - this is a critical security setting
		allowMockLogin = false
	}

	// DemoAutoAuthDelay: Auto-complete auth sessions for demo recording
	// Value in seconds, 0 or empty = disabled. Forced off in production.
	demoDelayStr := getEnv("DEMO_AUTO_AUTH_DELAY", "")
	var demoDelay time.Duration
	if demoDelayStr != "" {
		if secs, err := strconv.Atoi(demoDelayStr); err == nil && secs > 0 {
			demoDelay = time.Duration(secs) * time.Second
		}
	}
	if env == "production" {
		demoDelay = 0 // Force disable in production
	}

	// Extra RPC namespaces (chain-specific method extensions, loaded from file)
	extraRPCNamespacesFile := getEnv("EXTRA_RPC_NAMESPACES_FILE", "")
	var extraRPCNamespaces *ExtraRPCNamespaces
	if extraRPCNamespacesFile != "" {
		raw, err := os.ReadFile(extraRPCNamespacesFile)
		if err != nil {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: failed to read %s: %v", extraRPCNamespacesFile, err))
		}
		var parsed ExtraRPCNamespaces
		if err := json.Unmarshal(raw, &parsed); err != nil {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: invalid JSON in %s: %v", extraRPCNamespacesFile, err))
		}
		if parsed.Version != 1 && parsed.Version != 2 {
			panic(fmt.Sprintf("EXTRA_RPC_NAMESPACES_FILE: unsupported version %d in %s (expected 1 or 2)", parsed.Version, extraRPCNamespacesFile))
		}
		extraRPCNamespaces = &parsed
	}

	// Runtime tracing configuration
	traceCacheTTL := 10 * time.Second
	if ttlStr := getEnv("TRACE_CACHE_TTL", ""); ttlStr != "" {
		if d, err := time.ParseDuration(ttlStr); err == nil {
			traceCacheTTL = d
		}
	}
	traceTimeout := 30 * time.Second
	if timeoutStr := getEnv("TRACE_TIMEOUT", ""); timeoutStr != "" {
		if d, err := time.ParseDuration(timeoutStr); err == nil {
			traceTimeout = d
		}
	}
	traceTiered := getEnv("TRACE_TIERED_VALIDATION", "true") != "false"
	ethCallTracingEnabled := getEnv("RUNTIME_TRACING_ETH_CALL_ENABLED", "true") != "false"
	ethCallTraceTimeout := 5 * time.Second
	if t := getEnv("ETH_CALL_TRACE_TIMEOUT", ""); t != "" {
		if d, err := time.ParseDuration(t); err == nil {
			ethCallTraceTimeout = d
		}
	}

	// Travel rule compliance configuration
	enableTravelRule := getEnv("ENABLE_TRAVEL_RULE", "false") == "true"
	travelRecordExpiry := 24 * time.Hour
	if expiryStr := getEnv("TRAVEL_RECORD_EXPIRY", ""); expiryStr != "" {
		if d, err := time.ParseDuration(expiryStr); err == nil {
			travelRecordExpiry = d
		}
	}

	// Token price fetching configuration
	priceFetchInterval := 5 * time.Minute
	if intervalStr := getEnv("PRICE_FETCH_INTERVAL", ""); intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			priceFetchInterval = d
		}
	}
	if priceFetchInterval < 1*time.Minute {
		priceFetchInterval = 1 * time.Minute
	}
	priceStalenessThreshold := 15 * time.Minute
	if staleStr := getEnv("PRICE_STALENESS_THRESHOLD", ""); staleStr != "" {
		if d, err := time.ParseDuration(staleStr); err == nil {
			priceStalenessThreshold = d
		}
	}

	disableCoinGecko := getEnv("DISABLE_COINGECKO", "false") == "true"

	// Audit configuration
	auditLogParams := getEnv("AUDIT_LOG_PARAMS", "false") == "true"

	// Retention policy configuration
	retentionAccessLogs := parseDurationEnv("RETENTION_ACCESS_LOGS", 90*24*time.Hour)            // 90 days
	retentionComplianceLogs := parseDurationEnv("RETENTION_COMPLIANCE_LOGS", 7*365*24*time.Hour) // ~7 years
	retentionRBACAuditLogs := parseDurationEnv("RETENTION_RBAC_AUDIT_LOGS", 365*24*time.Hour)    // 1 year
	retentionTravelRecords := parseDurationEnv("RETENTION_TRAVEL_RECORDS", 7*365*24*time.Hour)   // ~7 years
	retentionCleanupInterval := parseDurationEnv("RETENTION_CLEANUP_INTERVAL", 1*time.Hour)

	// FIFO row cap on access_logs (0 = unlimited).
	var maxAccessLogRows int64
	if maxStr := getEnv("MAX_ACCESS_LOG_ROWS", ""); maxStr != "" {
		if n, err := strconv.ParseInt(maxStr, 10, 64); err == nil && n >= 0 {
			maxAccessLogRows = n
		}
	}

	// SIEM webhook configuration
	siemWebhookURL := getEnv("SIEM_WEBHOOK_URL", "")
	siemAuthHeader := getEnv("SIEM_AUTH_HEADER", "")
	siemBatchSize := 100
	if bsStr := getEnv("SIEM_BATCH_SIZE", ""); bsStr != "" {
		if n, err := strconv.Atoi(bsStr); err == nil && n > 0 {
			siemBatchSize = n
		}
	}
	siemFlushInterval := parseDurationEnv("SIEM_FLUSH_INTERVAL", 10*time.Second)

	// RD-858: scheduled audit-chain integrity verifier.
	auditIntegrityInterval := parseDurationEnv("AUDIT_INTEGRITY_VERIFY_INTERVAL", 15*time.Minute)
	auditTamperWebhookURL := getEnv("AUDIT_TAMPER_WEBHOOK_URL", "")

	// Per-user concurrency cap (default 50)
	maxConcurrentRequests := 50
	if mcStr := getEnv("MAX_CONCURRENT_REQUESTS", ""); mcStr != "" {
		if n, err := strconv.Atoi(mcStr); err == nil && n > 0 {
			maxConcurrentRequests = n
		}
	}

	// Path B (ProofOfHumanity) configuration with current hardcoded values as defaults.
	privadoStateContract := getEnv("PRIVADO_STATE_CONTRACT", auth.PrivadoMainnetStateContract)
	privadoCircuitID := getEnv("PRIVADO_CIRCUIT_ID", "credentialAtomicQueryMTPV2")
	billionsSchemaURL := getEnv("BILLIONS_CREDENTIAL_SCHEMA_URL", "https://raw.githubusercontent.com/0xPolygonID/tutorial-examples/main/credential-schema/schemas-examples/proof-of-humanity/proof-of-humanity.jsonld")
	billionsCredType := getEnv("BILLIONS_CREDENTIAL_TYPE", "ProofOfHumanity")

	// Credential query loaded from a JSON file — supports multi-field predicates.
	// Failure to read/parse when the env var is set is a hard error: misconfigured
	// prod should not boot silently.
	billionsQueryFile := getEnv("BILLIONS_CREDENTIAL_QUERY_FILE", "")
	var billionsQuery map[string]any
	if billionsQueryFile != "" {
		raw, err := os.ReadFile(billionsQueryFile)
		if err != nil {
			panic(fmt.Sprintf("BILLIONS_CREDENTIAL_QUERY_FILE: failed to read %s: %v", billionsQueryFile, err))
		}
		if err := json.Unmarshal(raw, &billionsQuery); err != nil {
			panic(fmt.Sprintf("BILLIONS_CREDENTIAL_QUERY_FILE: invalid JSON in %s: %v", billionsQueryFile, err))
		}
	}

	// RPC API key encryption key (hex-encoded 32 bytes for AES-256)
	var rpcAPIKeyEncKey []byte
	if hexKey := getEnv("RPC_API_KEY_ENCRYPTION_KEY", ""); hexKey != "" {
		decoded, err := hex.DecodeString(hexKey)
		if err == nil && len(decoded) == 32 {
			rpcAPIKeyEncKey = decoded
		}
	}

	// RPC API key header name. Default "Authorization" preserves Bearer token
	// behaviour. Any other value (e.g. "X-API-Key") is sent verbatim. We
	// validate the format here so a misconfigured value cannot inject CRLF
	// or arbitrary header content downstream.
	rpcAPIKeyHeader := getEnv("RPC_API_KEY_HEADER", proxy.DefaultAPIKeyHeader)
	if !proxy.ValidAPIKeyHeader(rpcAPIKeyHeader) {
		panic(fmt.Sprintf("RPC_API_KEY_HEADER %q is invalid: must match ^[A-Za-z0-9-]+$", rpcAPIKeyHeader))
	}

	return &Config{
		NodeURL:                  getEnv("NODE_URL", "http://localhost:8545"),
		DatabaseURL:              getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/privacy_proxy?sslmode=disable"),
		PrivadoRPCURL:            getEnv("PRIVADO_RPC_URL", "https://rpc-mainnet.privado.id"),
		IPFSGateway:              getEnv("IPFS_GATEWAY", "https://ipfs-proxy-cache.privado.id"), // IPFS gateway for schema resolution
		JWTSecret:                getEnv("JWT_SECRET", ""),                                      // If empty, will be auto-generated (dev only)
		JWTRefreshSecret:         getEnv("JWT_REFRESH_SECRET", ""),                              // If empty, will be auto-generated (dev only)
		VerifierID:               getEnv("VERIFIER_ID", ""),                                     // Required in production
		BaseURL:                  getEnv("BASE_URL", "http://localhost:8080"),                   // Base URL for callback
		Port:                     getEnv("PORT", "8080"),                                        // Server port
		Environment:              env,
		BillionsIssuerDID:           getEnv("BILLIONS_ISSUER_DID", ""), // Billions issuer DID for PoH
		RequireProofOfHumanity:      requirePoHBool,
		PrivadoStateContract:        privadoStateContract,
		PrivadoCircuitID:            privadoCircuitID,
		BillionsCredentialSchemaURL: billionsSchemaURL,
		BillionsCredentialType:      billionsCredType,
		BillionsCredentialQueryFile: billionsQueryFile,
		BillionsCredentialQuery:     billionsQuery,
		AdminAPIToken:            getEnv("ADMIN_API_TOKEN", ""),
		ENSResolverURL:           getEnv("ENS_RESOLVER_URL", "https://eth.llamarpc.com"), // Public mainnet RPC
		CORSAllowedOrigins:       corsOrigins,
		MockSignatures:           mockSigs,
		AllowMockLogin:           allowMockLogin,
		DemoAutoAuthDelay:        demoDelay,
		ExtraRPCNamespacesFile:   extraRPCNamespacesFile,
		ExtraRPCNamespaces:       extraRPCNamespaces,
		TraceCacheTTL:                traceCacheTTL,
		TraceTimeout:                 traceTimeout,
		TraceTieredValidation:        traceTiered,
		RuntimeTracingEthCallEnabled: ethCallTracingEnabled,
		EthCallTraceTimeout:          ethCallTraceTimeout,
		EnableTravelRule:         enableTravelRule,
		TravelRecordExpiry:       travelRecordExpiry,
		PriceFetchInterval:       priceFetchInterval,
		PriceStalenessThreshold:  priceStalenessThreshold,
		DisableCoinGecko:         disableCoinGecko,
		AuditLogParams:           auditLogParams,
		RetentionAccessLogs:      retentionAccessLogs,
		RetentionComplianceLogs:  retentionComplianceLogs,
		RetentionRBACAuditLogs:   retentionRBACAuditLogs,
		RetentionTravelRecords:   retentionTravelRecords,
		RetentionCleanupInterval: retentionCleanupInterval,
		MaxAccessLogRows:         maxAccessLogRows,
		SIEMWebhookURL:           siemWebhookURL,
		SIEMAuthHeader:           siemAuthHeader,
		SIEMBatchSize:            siemBatchSize,
		SIEMFlushInterval:        siemFlushInterval,
		SIEMFallbackLogPath:      getEnv("SIEM_FALLBACK_LOG_PATH", ""),
		AuditIntegrityVerifyInterval: auditIntegrityInterval,
		AuditTamperWebhookURL:        auditTamperWebhookURL,
		ExplorerDatabaseURL:      getEnv("EXPLORER_DATABASE_URL", ""),
		IndexerURL:               getEnv("INDEXER_URL", ""),
		TunnelURLFile:            getEnv("TUNNEL_URL_FILE", ""),
		HideDevAdminOrg:          getEnv("HIDE_DEV_ADMIN_ORG", "false") == "true",
		TrustedProxies:           getSliceEnv("TRUSTED_PROXIES", ","),
		TrustedInternalCIDRs:    getSliceEnv("TRUSTED_INTERNAL_CIDRS", ","),
		FrontendURL:              getEnv("FRONTEND_URL", ""),
		RPCAPIKey:                getEnv("RPC_API_KEY", ""),
		RPCAPIKeyHeader:          rpcAPIKeyHeader,
		RPCAPIKeyEncryptionKey:   rpcAPIKeyEncKey,
		MaxConcurrentRequests:    maxConcurrentRequests,
		AzureADClientID:          getEnv("AZURE_AD_CLIENT_ID", ""),
		AzureADClientSecret:      getEnv("AZURE_AD_CLIENT_SECRET", ""),
		AzureADTenantID:          getEnv("AZURE_AD_TENANT_ID", "common"),
		RedisURL:                 getEnv("REDIS_URL", ""),
	}
}

func getSliceEnv(key, sep string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	parts := strings.Split(val, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// IsProduction returns true if running in production mode
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// AzureADEnabled returns true if Azure AD authentication is configured.
// Requires all three: client ID, client secret, and tenant ID.
func (c *Config) AzureADEnabled() bool {
	return c.AzureADClientID != "" && c.AzureADClientSecret != "" && c.AzureADTenantID != ""
}

// Validate checks that required configuration is present.
// In production, certain values must be explicitly configured.
// When RequireProofOfHumanity is enabled, Path B configuration is validated
// regardless of environment — misconfiguring Path B breaks login for everyone.
func (c *Config) Validate() error {
	if c.RequireProofOfHumanity {
		if err := c.validateProofOfHumanity(); err != nil {
			return err
		}
	}

	if !c.IsProduction() {
		return nil // Development mode allows auto-generated values
	}

	// In production, JWT secrets must be explicitly configured
	if c.JWTSecret == "" {
		return errors.New("JWT_SECRET is required in production")
	}
	if c.JWTRefreshSecret == "" {
		return errors.New("JWT_REFRESH_SECRET is required in production")
	}

	// Warn about other important production settings
	if c.VerifierID == "" {
		return errors.New("VERIFIER_ID is required in production for authentication")
	}
	if c.AdminAPIToken == "" {
		return errors.New("ADMIN_API_TOKEN is required in production for admin API authentication")
	}
	if c.NodeURL == "" {
		return errors.New("NODE_URL is required in production (Ethereum node JSON-RPC endpoint)")
	}
	if c.BaseURL == "" {
		return errors.New("BASE_URL is required in production (public URL for OAuth callbacks)")
	}

	// Validate SIEM webhook URL against SSRF if configured.
	if c.SIEMWebhookURL != "" {
		if err := audit.ValidateWebhookURL(c.SIEMWebhookURL); err != nil {
			return err
		}
	}

	// RD-858: same SSRF guard for the audit tamper webhook.
	if c.AuditTamperWebhookURL != "" {
		if err := audit.ValidateWebhookURL(c.AuditTamperWebhookURL); err != nil {
			return fmt.Errorf("AUDIT_TAMPER_WEBHOOK_URL: %w", err)
		}
	}

	// Validate FrontendURL if set: must be HTTPS in production (localhost exempt).
	if c.FrontendURL != "" {
		parsed, err := url.Parse(c.FrontendURL)
		if err != nil || parsed.Host == "" {
			return errors.New("FRONTEND_URL must be a valid URL (e.g. https://proxy.example.com)")
		}
		isLocal := isPrivateOrLocalhost(parsed.Hostname())
		if parsed.Scheme != "https" && !isLocal {
			return errors.New("FRONTEND_URL must use HTTPS in production (localhost and private networks are exempt)")
		}
	}

	return nil
}

// validateProofOfHumanity checks Path B configuration required when
// RequireProofOfHumanity=true. All values must be non-empty and the parsed
// credential query must contain a non-empty 'credentialSubject' object.
func (c *Config) validateProofOfHumanity() error {
	if c.BillionsIssuerDID == "" {
		return errors.New("BILLIONS_ISSUER_DID is required when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.PrivadoStateContract == "" {
		return errors.New("PRIVADO_STATE_CONTRACT must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.PrivadoCircuitID == "" {
		return errors.New("PRIVADO_CIRCUIT_ID must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialSchemaURL == "" {
		return errors.New("BILLIONS_CREDENTIAL_SCHEMA_URL must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialType == "" {
		return errors.New("BILLIONS_CREDENTIAL_TYPE must not be empty when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	if c.BillionsCredentialQueryFile == "" {
		return errors.New("BILLIONS_CREDENTIAL_QUERY_FILE is required when REQUIRE_PROOF_OF_HUMANITY=true")
	}
	cs, ok := c.BillionsCredentialQuery["credentialSubject"].(map[string]any)
	if !ok || len(cs) == 0 {
		return fmt.Errorf("BILLIONS_CREDENTIAL_QUERY_FILE %q must contain a non-empty 'credentialSubject' object", c.BillionsCredentialQueryFile)
	}
	return nil
}

// isPrivateOrLocalhost returns true if the hostname is localhost, loopback, or a private network IP.
// HTTP is safe on these networks — no public internet transit.
func isPrivateOrLocalhost(hostname string) bool {
	if hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1" {
		return true
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		return false
	}
	// RFC1918 + RFC4193 (IPv6 ULA) + link-local
	privateRanges := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"100.64.0.0/10", // Tailscale / CGNAT
		"fc00::/7",      // IPv6 ULA
		"fe80::/10",     // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDurationEnv reads an environment variable as a time.Duration.
// Returns the default value if the variable is empty or unparseable.
// A value of "0" returns 0 (keep forever for retention settings).
func parseDurationEnv(key string, defaultValue time.Duration) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return defaultValue
	}
	if s == "0" {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultValue
	}
	return d
}
