package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/ens"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/explorer/indexerclient"
	"privacy-proxy/internal/metrics"
	"privacy-proxy/internal/nodehttp"
	"privacy-proxy/internal/pricing"
	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/rbac"
	privacyredis "privacy-proxy/internal/redis"
	"privacy-proxy/internal/tracer"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AccessTokenTTL is intentionally short. We do not implement immediate token
// revocation for access tokens (no per-request DB lookup). This means a banned
// user stays active until their current access token expires and they attempt a
// refresh — at which point handleRefresh checks the ban flag and rejects them.
// The 5-minute window is the maximum time a banned user can continue acting.
// Do not increase this value without adding an access-token revocation mechanism.
// Dev builds (mockauth) override this to 30 minutes via init().
var AccessTokenTTL = 5 * time.Minute

// TTL constants for various components
const (
	RefreshTokenTTL = 7 * 24 * time.Hour

	// Cache and store TTLs
	RBACCacheTTL             = 5 * time.Minute
	SessionTTL               = 10 * time.Minute
	SessionCleanupInterval   = 1 * time.Minute
	ChallengeTTL             = 5 * time.Minute
	ChallengeCleanupInterval = 1 * time.Minute

	// Rate limiter cleanup interval
	RateLimiterCleanupInterval = 10 * time.Second

	// ENS resolution timeout
	ENSResolutionTimeout = 30 * time.Second

	// devVerifierDID is a valid placeholder DID used in dev mode when VERIFIER_ID is not configured.
	// Uses did:pkh (public key hash) which the Privado wallet can parse without on-chain resolution.
	devVerifierDID = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001"
)

// Server represents the API server
// Server represents the API server
type Server struct {
	db                   *db.DB
	rbacAccessCtrl       *rbac.AccessController
	proxy                *proxy.Proxy
	privadoVerifier      PrivadoVerifier
	jwtService           *auth.JWTService
	sessionStore         SessionManager
	oauthSessionStore    OAuthSessionManager
	challengeStore       ChallengeManager
	rateLimiter          RateLimiterInterface
	authRateLimiter      *AuthRateLimiter
	disclosureService    *disclosure.DefaultService
	complianceChecker    *compliance.Checker
	priceService         *pricing.Service
	config               *config.Config
	ensResolver          *ens.Resolver
	jsonrpcProcessor     *JSONRPCProcessor
	zkRoleExtractor      *auth.ZKRoleExtractor
	runtimeTracer        *tracer.RuntimeTracer
	azureAuthenticator   *auth.AzureADAuthenticator
	azureStateStore      AzureStateManager
	metrics              *metrics.Metrics
	explorerStore        explorer.ExplorerBackend
	explorerMu           sync.RWMutex // protects explorerStore + explorerRedactor during background reconnect
	explorerRedactor     *explorer.RedactionEngine
	siemForwarder        *audit.SIEMForwarder
	retentionCleaner     *audit.RetentionCleaner
	auditIntegrityWorker *audit.IntegrityWorker
	visibilityReconciler *VisibilityReconciler // M7 outbox drain
	redisCloser          io.Closer
	// RD-1112 async access-log auditing (nil when AUDIT_BUFFER_DIR unset).
	auditBuffer       *buffer.Buffer
	auditSealer       *sealer.Sealer
	auditSealerCancel context.CancelFunc
	// RD-1112 #8 signed truncation-detection checkpoints (nil when disabled).
	auditCheckpointWorker *audit.CheckpointWorker
	auditCheckpointCancel context.CancelFunc
}

// checkpointAdapter bridges *db.DB to the audit package's CheckpointStore and
// CheckpointReader interfaces (the audit package deliberately does not import
// db; this adapter, in the server layer which imports both, does the mapping).
type checkpointAdapter struct{ db *db.DB }

func (a checkpointAdapter) ChainStats(ctx context.Context, chainName string) (int64, int64, string, error) {
	return a.db.GetAccessLogChainStats(ctx, chainName)
}

func (a checkpointAdapter) WriteCheckpoint(ctx context.Context, c audit.Checkpoint) error {
	return a.db.WriteAuditChainCheckpoint(ctx, db.AuditChainCheckpointRow{
		ChainName: c.ChainName, HeadID: c.HeadID, HeadHash: c.HeadHash,
		RowCount: c.RowCount, KeyID: c.KeyID, Signature: c.Signature, CreatedAt: c.CreatedAt,
	})
}

func (a checkpointAdapter) LatestCheckpoint(ctx context.Context, chainName string) (*audit.Checkpoint, error) {
	row, err := a.db.GetLatestAuditChainCheckpoint(ctx, chainName)
	if err != nil || row == nil {
		return nil, err
	}
	return &audit.Checkpoint{
		ChainName: row.ChainName, HeadID: row.HeadID, HeadHash: row.HeadHash,
		RowCount: row.RowCount, KeyID: row.KeyID, Signature: row.Signature, CreatedAt: row.CreatedAt,
	}, nil
}

// SetAnchor + WriteReAnchor let checkpointAdapter also satisfy
// audit.ReAnchorStore, so the break-glass re-anchor operation
// (audit.BreakGlassReAnchor) can run against the live database (RD-1112 #8).
func (a checkpointAdapter) SetAnchor(ctx context.Context, chainName string, lastID int64, lastHash string) error {
	return a.db.UpsertAuditChainAnchor(ctx, chainName, lastID, lastHash)
}

func (a checkpointAdapter) WriteReAnchor(ctx context.Context, r audit.ReAnchor) error {
	return a.db.WriteAuditChainReAnchor(ctx, r.ChainName, r.Reason, r.Actor,
		r.FromHeadID, r.FromHash, r.ToHeadID, r.ToHash, r.KeyID, r.Signature, r.CreatedAt)
}

// DB returns the database instance (for testing)
func (s *Server) DB() *db.DB {
	return s.db
}

// Stop gracefully stops all background goroutines.
// Should be called before server shutdown.
func (s *Server) Stop() {
	if s.sessionStore != nil {
		s.sessionStore.Stop()
	}
	if s.oauthSessionStore != nil {
		s.oauthSessionStore.Stop()
	}
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	if s.authRateLimiter != nil {
		s.authRateLimiter.Stop()
	}
	if s.challengeStore != nil {
		s.challengeStore.Stop()
	}
	if s.rbacAccessCtrl != nil {
		s.rbacAccessCtrl.Stop()
	}
	if s.priceService != nil {
		s.priceService.Stop()
	}
	if s.runtimeTracer != nil {
		s.runtimeTracer.Stop()
	}
	if s.siemForwarder != nil {
		s.siemForwarder.Stop()
	}
	if s.retentionCleaner != nil {
		s.retentionCleaner.Stop()
	}
	if s.auditIntegrityWorker != nil {
		s.auditIntegrityWorker.Stop()
	}
	if s.visibilityReconciler != nil {
		s.visibilityReconciler.Stop()
	}
	// RD-1112: stop the audit sealer's drain loop and wait for the in-flight
	// tick to finish before closing its buffer, so Close never races a tick.
	if s.auditSealerCancel != nil {
		s.auditSealerCancel()
	}
	if s.auditSealer != nil {
		s.auditSealer.Wait()
	}
	if s.auditCheckpointCancel != nil {
		s.auditCheckpointCancel()
	}
	if s.auditCheckpointWorker != nil {
		s.auditCheckpointWorker.Wait()
	}
	if s.auditBuffer != nil {
		if err := s.auditBuffer.Close(); err != nil {
			slog.Warn("audit buffer close failed", "error", err)
		}
	}
	if s.azureStateStore != nil {
		s.azureStateStore.Stop()
	}
	if s.redisCloser != nil {
		s.redisCloser.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

// explorerReconnectLoop retries connecting to the explorer database every 30 seconds.
// Once connected, it sets the explorer store and redaction engine so explorer endpoints become available.
func (s *Server) explorerReconnectLoop(dbURL string, rbacDB *db.DB, indexerURL string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sqlStore, err := explorer.NewStore(dbURL)
		if err != nil {
			slog.Debug("explorer DB reconnect attempt failed", "error", err)
			continue
		}
		backend, err := buildExplorerBackend(sqlStore, indexerURL)
		if err != nil {
			slog.Warn("explorer gRPC backend dial failed, falling back to SQL store", "error", err)
			backend = sqlStore
		}
		s.explorerMu.Lock()
		s.explorerStore = backend
		s.explorerRedactor = explorer.NewRedactionEngine(backend, rbacDB)
		// Wire ABI / admin / event-rule / log-participant resolvers so the
		// explorer redactor mirrors RPC-layer decisions (RD-875 / RD-889 /
		// RD-890 / RD-939 / event-rule wiring fix). One call site, one
		// helper — see wireExplorerRedactor for why this is consolidated.
		wireExplorerRedactor(s.explorerRedactor, rbacDB, s.rbacAccessCtrl, backend)
		s.explorerMu.Unlock()
		slog.Info("explorer backend connected — explorer endpoints now available")
		return
	}
}

// buildExplorerBackend returns the gRPC-backed explorer Backend when
// indexerURL is set, otherwise returns the SQL store unchanged. The
// gRPC backend embeds the SQL store so unmigrated methods keep working.
func buildExplorerBackend(sqlStore *explorer.Store, indexerURL string) (explorer.ExplorerBackend, error) {
	if indexerURL == "" {
		return sqlStore, nil
	}
	b, err := indexerclient.New(indexerclient.Config{IndexerURL: indexerURL}, sqlStore)
	if err != nil {
		return nil, err
	}
	slog.Info("explorer backend: using chain-indexer gRPC for ported methods, SQL store fallback otherwise", "indexer_url", indexerURL)
	return b, nil
}

// PrivadoVerifier interface for Privado ID operations
type PrivadoVerifier interface {
	CreateAuthorizationRequest(verifierID, callbackURL, reason string) (*protocol.AuthorizationRequestMessage, error)
	CreateHumanityAuthRequest(verifierID, callbackURL, reason, issuerDID string, hc auth.HumanityRequestConfig) (*protocol.AuthorizationRequestMessage, error)
	VerifyJWZ(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (string, error)
	VerifyJWZWithProofData(ctx context.Context, jwzToken string, authRequest *protocol.AuthorizationRequestMessage, verifierID string) (*auth.VerificationResult, error)
}

func New(cfg *config.Config) (*Server, error) {
	return NewWithVerifier(cfg, nil)
}

// NewWithVerifier creates a new server with an optional PrivadoVerifier
// If verifier is nil, creates a real PrivadoVerifier from config
// This allows injecting a mock verifier for testing
func NewWithVerifier(cfg *config.Config, verifier PrivadoVerifier) (*Server, error) {
	database, err := db.New(cfg.DatabaseURL, db.WithPool(cfg.DBMaxOpenConns, cfg.DBMaxIdleConns, cfg.DBConnMaxLifetime))
	if err != nil {
		return nil, fmt.Errorf("failed to create database: %w", err)
	}

	var explorerSQL *explorer.Store
	if cfg.ExplorerDatabaseURL != "" {
		explorerSQL, err = explorer.NewStore(cfg.ExplorerDatabaseURL)
		if err != nil {
			slog.Warn("explorer database unavailable — explorer endpoints will return 503 until connected", "error", err)
			// Don't crash — background retry will connect when the DB is ready.
		}
	}
	var explorerBackend explorer.ExplorerBackend
	if explorerSQL != nil {
		explorerBackend, err = buildExplorerBackend(explorerSQL, cfg.IndexerURL)
		if err != nil {
			slog.Warn("explorer gRPC backend dial failed, falling back to SQL store", "error", err)
			explorerBackend = explorerSQL
		}
	}

	// Initialize Privado ID verifier
	var privadoVerifier PrivadoVerifier
	if verifier != nil {
		privadoVerifier = verifier
	} else {
		// Register billions:main alongside privado:main so DIDs created in the
		// Billions app verify too — without it the iden3 library rejects them
		// with "billions:main resolver not found" (RD-943).
		privadoVerifier, err = auth.NewPrivadoVerifier(
			cfg.PrivadoRPCURL, cfg.IPFSGateway, cfg.PrivadoStateContract,
			auth.NetworkResolver{
				Key:           "billions:main",
				RPCURL:        cfg.BillionsRPCURL,
				StateContract: cfg.BillionsStateContract,
			},
		)
		if err != nil {
			database.Close()
			return nil, fmt.Errorf("failed to create Privado verifier: %w", err)
		}
	}

	// Initialize JWT service
	jwtService, err := auth.NewJWTService(
		cfg.JWTSecret,
		cfg.JWTRefreshSecret,
		AccessTokenTTL,
		RefreshTokenTTL,
	)
	if err != nil {
		database.Close()
		return nil, fmt.Errorf("failed to create JWT service: %w", err)
	}

	// Upstream node connection-pool sizing (RD-1112), shared by the forwarder
	// and the runtime tracer (both talk to the single node host).
	nodeTransport := nodehttp.TransportConfig{
		MaxIdleConns:        cfg.NodeMaxIdleConns,
		MaxIdleConnsPerHost: cfg.NodeMaxIdleConnsPerHost,
		MaxConnsPerHost:     cfg.NodeMaxConnsPerHost,
		IdleConnTimeout:     cfg.NodeIdleConnTimeout,
	}
	proxySvc := proxy.NewWithTransport(cfg.NodeURL, nodeTransport)

	// Initialize state stores: Redis-backed when REDIS_URL is set, in-memory otherwise.
	var sessionStore SessionManager
	var challengeStore ChallengeManager
	var rateLimiter RateLimiterInterface
	var oauthSessionStore OAuthSessionManager
	var rbacAccessCtrl *rbac.AccessController
	var redisCloser io.Closer
	var redisClient *privacyredis.Client

	if cfg.RedisURL != "" {
		var redisErr error
		redisClient, redisErr = privacyredis.NewClient(cfg.RedisURL)
		if redisErr != nil {
			database.Close()
			return nil, fmt.Errorf("redis: %w", redisErr)
		}
		redisCloser = redisClient
		slog.Info("using Redis-backed state stores", "url", redactRedisURL(cfg.RedisURL))

		sessionStore = privacyredis.NewSessionStore(redisClient, SessionTTL, auth.DefaultMaxSessions)
		challengeStore = privacyredis.NewChallengeStore(redisClient, ChallengeTTL)
		// Rate limiter is always in-memory: per-user RPC rate limiting was removed
		// in PR #120 (moved to the upstream RPC proxy). The remaining rate limiter
		// is only used for trace-endpoint throttling, which is single-instance safe.
		rateLimiter = NewRateLimiter(RateLimiterCleanupInterval)
		oauthSessionStore = privacyredis.NewOAuthSessionStore(redisClient, OAuthSessionTTL, DefaultMaxOAuthSessions)
		rbacCache := privacyredis.NewPermissionCache(redisClient, RBACCacheTTL)
		rbacAccessCtrl = rbac.NewAccessControllerWithCache(database, RBACCacheTTL, rbacCache)
	} else {
		slog.Info("using in-memory state stores")
		sessionStore = auth.NewSessionStore(SessionTTL, SessionCleanupInterval)
		challengeStore = NewChallengeStore(ChallengeTTL, ChallengeCleanupInterval)
		rateLimiter = NewRateLimiter(RateLimiterCleanupInterval)
		oauthSessionStore = NewOAuthSessionStore(OAuthSessionTTL, OAuthCleanupInterval, DefaultMaxOAuthSessions)
		rbacAccessCtrl = rbac.NewAccessController(database, RBACCacheTTL)
	}

	// Register extra RPC namespaces (chain-specific method extensions, including
	// any v2 wildcard passthroughs).
	if cfg.ExtraRPCNamespaces != nil && len(cfg.ExtraRPCNamespaces.Namespaces) > 0 {
		wildcardCfgs := cfg.ExtraRPCNamespaces.Wildcards()
		wildcards := make([]*rbac.WildcardNamespace, 0, len(wildcardCfgs))
		for ns, w := range wildcardCfgs {
			wildcards = append(wildcards, &rbac.WildcardNamespace{
				Namespace: ns,
				Prefix:    w.Prefix,
				Deny:      w.Deny,
			})
		}
		rbac.RegisterExtraNamespaces(cfg.ExtraRPCNamespaces.MethodNames(), cfg.ExtraRPCNamespaces.Aliases(), wildcards)
		slog.Info("extra RPC namespaces registered",
			"namespaces", len(cfg.ExtraRPCNamespaces.Namespaces),
			"aliases", len(cfg.ExtraRPCNamespaces.Aliases()),
			"wildcards", len(wildcards))
	}

	// Configure RPC API key encryption for decrypting keys from the database
	if len(cfg.RPCAPIKeyEncryptionKey) > 0 {
		rbacAccessCtrl.SetEncryptionKey(cfg.RPCAPIKeyEncryptionKey)
	}

	// Initialize auth rate limiter for protecting auth endpoints from brute force
	// Use relaxed limits in development/testing to avoid issues during E2E tests
	var authRateLimiterCfg AuthRateLimiterConfig
	if cfg.IsProduction() {
		authRateLimiterCfg = DefaultAuthRateLimiterConfig()
	} else {
		authRateLimiterCfg = DevAuthRateLimiterConfig()
	}
	authRateLimiter := NewAuthRateLimiter(authRateLimiterCfg)

	// Initialize ENS resolver (optional - may fail if no mainnet RPC available)
	var ensResolver *ens.Resolver
	if cfg.ENSResolverURL != "" {
		ensResolver, err = ens.NewResolver(cfg.ENSResolverURL)
		if err != nil {
			// Log warning but don't fail - ENS resolution is optional
			slog.Warn("failed to create ENS resolver", "error", err)
		}
	}

	// Initialize Azure AD authenticator (optional — only when credentials are configured)
	var azureAuthenticator *auth.AzureADAuthenticator
	var azureStateStore AzureStateManager
	if cfg.AzureADEnabled() {
		azureAuthenticator, err = auth.NewAzureADAuthenticator(cfg.AzureADClientID, cfg.AzureADClientSecret, cfg.AzureADTenantID)
		if err != nil {
			// Log warning but don't fail — Azure AD is optional
			slog.Warn("failed to initialize Azure AD authenticator", "error", err)
		} else {
			// RD-1120: expected audience for service-principal access tokens
			// (empty → defaults to the client ID inside VerifyAccessToken).
			azureAuthenticator.SetServicePrincipalAudience(cfg.AzureADSPAudience)
			if redisClient != nil {
				azureStateStore = privacyredis.NewAzureStateStore(redisClient, AzureStateTTL)
			} else {
				azureStateStore = NewAzureStateStore(AzureStateTTL, AzureStateCleanupInterval)
			}
			slog.Info("Azure AD authentication enabled", "tenant", cfg.AzureADTenantID)
		}
	}

	// Initialize ZK role extractor for extracting role claims from Privado proofs
	zkRoleExtractor := auth.NewZKRoleExtractor(database)

	// Initialize disclosure service
	disclosureService := disclosure.NewService(database)

	// Initialize runtime tracer for cross-org isolation validation
	runtimeTracer := tracer.NewRuntimeTracer(tracer.RuntimeTracerConfig{
		NodeURL:       cfg.NodeURL,
		Enabled:       true,
		CacheTTL:      cfg.TraceCacheTTL,
		Timeout:       cfg.TraceTimeout,
		TieredEnabled: cfg.TraceTieredValidation,
		Transport:     nodeTransport,
	})
	traceValidator := rbac.NewTraceValidator(database)
	// M5 (security audit follow-up to RD-915): wire the runtime tracer
	// as the CodeHashFetcher so the validator can codehash-pin
	// shared_infrastructure entries.
	traceValidator.SetCodeHashFetcher(runtimeTracer)
	slog.Info("runtime tracing enabled", "cache_ttl", cfg.TraceCacheTTL, "timeout", cfg.TraceTimeout, "tiered", cfg.TraceTieredValidation)

	// Initialize Prometheus metrics
	m := metrics.New(cfg.Version)
	metrics.RegisterDBStatsCollector(m.Registry, database.Conn())

	s := &Server{
		db:                 database,
		rbacAccessCtrl:     rbacAccessCtrl,
		proxy:              proxySvc,
		privadoVerifier:    privadoVerifier,
		jwtService:         jwtService,
		sessionStore:       sessionStore,
		oauthSessionStore:  oauthSessionStore,
		challengeStore:     challengeStore,
		rateLimiter:        rateLimiter,
		authRateLimiter:    authRateLimiter,
		disclosureService:  disclosureService,
		config:             cfg,
		ensResolver:        ensResolver,
		zkRoleExtractor:    zkRoleExtractor,
		runtimeTracer:      runtimeTracer,
		azureAuthenticator: azureAuthenticator,
		azureStateStore:    azureStateStore,
		metrics:            m,
		explorerStore:      explorerBackend,
		explorerRedactor:   explorer.NewRedactionEngine(explorerBackend, database),
		redisCloser:        redisCloser,
	}
	// RD-889: wire the unified ABI resolver so the explorer redactor
	// (a) honours the built-in registry fallback for ABI lookups and
	// (b) applies the deny-when-no-ABI gate that mirrors RPC behaviour
	// from RD-875. Without this, the explorer endpoints would still
	// leak non-indexed addresses from event data on contracts without
	// a custom ABI.
	//
	// RD-939 Stage A: also wires the log-participant store so the
	// redactor recognises viewers as tx participants when they appear
	// in indexed address topics of accepted event signatures (Transfer,
	// Approval, ApprovalForAll, TransferSingle/Batch, Deposit,
	// Withdrawal). Closes the over-redaction bug where custom-selector
	// mints to the viewer left them unable to see their own tx.
	wireExplorerRedactor(s.explorerRedactor, database, s.rbacAccessCtrl, explorerBackend)

	// Start background explorer DB reconnection if initial connection failed
	if cfg.ExplorerDatabaseURL != "" && explorerSQL == nil {
		go s.explorerReconnectLoop(cfg.ExplorerDatabaseURL, database, cfg.IndexerURL)
	}

	// Initialize circuit breaker and concurrency limiter for upstream RPC proxy
	circuitBreaker := NewCircuitBreaker()
	concurrencyLimiter := NewConcurrencyLimiter(cfg.MaxConcurrentRequests)

	// Initialize JSON-RPC processor with dependencies
	if runtimeTracer != nil {
		s.jsonrpcProcessor = NewJSONRPCProcessorWithTracing(rbacAccessCtrl, rateLimiter, proxySvc, database, runtimeTracer, traceValidator, circuitBreaker, concurrencyLimiter, cfg.RPCAPIKey)
	} else {
		s.jsonrpcProcessor = NewJSONRPCProcessor(rbacAccessCtrl, rateLimiter, proxySvc, database, circuitBreaker, concurrencyLimiter, cfg.RPCAPIKey)
	}
	s.jsonrpcProcessor.SetMetrics(m)
	s.jsonrpcProcessor.SetTxVisibilityStore(database)
	s.jsonrpcProcessor.SetDefaultRPCAPIKeyHeader(cfg.RPCAPIKeyHeader)
	s.jsonrpcProcessor.SetEthCallTracing(cfg.RuntimeTracingEthCallEnabled, cfg.EthCallTraceTimeout)
	s.jsonrpcProcessor.SetIntraOrgGrantTracing(cfg.RuntimeTracingIntraOrgGrantsEnabled)

	// Initialize compliance checker for travel rule enforcement
	if cfg.EnableTravelRule {
		checker := compliance.NewChecker(database, cfg.TravelRecordExpiry, cfg.PriceStalenessThreshold)
		// RD-1044: cluster-wide default enforce/monitor mode for orgs without a
		// per-org setting. Per-org compliance config overrides this.
		checker.SetDefaultEnforcementMode(compliance.EnforcementMode(cfg.ComplianceDefaultMode))
		s.complianceChecker = checker
		s.jsonrpcProcessor.SetComplianceChecker(checker)
		slog.Info("travel rule compliance enabled", "record_expiry", cfg.TravelRecordExpiry, "default_enforcement_mode", cfg.ComplianceDefaultMode)

		// Start background CoinGecko price fetcher (unless disabled)
		if !cfg.DisableCoinGecko {
			priceSvc := pricing.NewService(database, database, cfg.PriceFetchInterval)
			priceSvc.SetMetrics(m.PricingFetchesTotal, m.PricingFetchDuration, m.PricingConsecutiveFailures)
			priceSvc.Start()
			s.priceService = priceSvc
		} else {
			slog.Info("CoinGecko price fetching is DISABLED")
		}
	} else {
		slog.Warn("travel rule compliance is DISABLED (ENABLE_TRAVEL_RULE=false) - value transfers will NOT be checked against thresholds or sanctions lists")
	}

	// Initialize enhanced audit: hash chain, SIEM forwarder, retention cleaner
	hashChainSeed, err := database.GetLatestAccessLogHashForChain(context.Background(), cfg.AuditChainName)
	if err != nil {
		slog.Warn("failed to seed hash chain from DB, starting fresh", "error", err)
	}
	hashChain := audit.NewHashChain(hashChainSeed)

	// RD-858: rbac_audit_log gets its own chain, seeded independently
	// of access_logs. Both chains share the audit.HashChain
	// implementation and are verifiable via the same Verifier — they
	// just live behind different `chain_name` entries in
	// audit_chain_anchor. Installed onto the DB so every CreateAuditLog
	// from anywhere in the codebase advances it atomically with the
	// row write.
	rbacAuditSeed, rbacSeedErr := database.GetLatestRBACAuditLogHash(context.Background())
	if rbacSeedErr != nil {
		slog.Warn("failed to seed rbac_audit_log hash chain from DB, starting fresh", "error", rbacSeedErr)
	}
	rbacAuditChain := audit.NewHashChain(rbacAuditSeed)
	database.SetRBACAuditChain(rbacAuditChain)

	// Initialize SIEM forwarder if webhook URL is configured.
	// RD-950: NewSIEMForwarder now applies the SSRF guard at construction
	// time and returns an error on a malformed/private URL. In production
	// mode the same guard already runs in config.Validate (strict: HTTPS
	// only, no loopback / RFC-1918 / link-local / CGNAT) — this is the
	// defence-in-depth second line. In non-prod we relax to allow HTTP on
	// loopback / private networks so local docker-compose dev with a
	// stub SIEM still works.
	var siemForwarder *audit.SIEMForwarder
	if cfg.SIEMWebhookURL != "" {
		var siemErr error
		siemForwarder, siemErr = audit.NewSIEMForwarder(audit.SIEMConfig{
			WebhookURL:      cfg.SIEMWebhookURL,
			AuthHeader:      cfg.SIEMAuthHeader,
			BatchSize:       cfg.SIEMBatchSize,
			FlushInterval:   cfg.SIEMFlushInterval,
			FallbackLogPath: cfg.SIEMFallbackLogPath,
			AllowInsecure:   !cfg.IsProduction(),
		})
		if siemErr != nil {
			return nil, fmt.Errorf("init SIEM forwarder: %w", siemErr)
		}
		siemForwarder.SetMetrics(m.SIEMBatchesTotal, m.SIEMEventsDroppedTotal)
		siemForwarder.Start()
		s.siemForwarder = siemForwarder
		slog.Info("SIEM forwarding enabled", "webhook", cfg.SIEMWebhookURL, "batch_size", cfg.SIEMBatchSize, "flush_interval", cfg.SIEMFlushInterval)
	}

	// Wire enhanced audit into JSON-RPC processor
	s.jsonrpcProcessor.SetEnhancedAudit(database, hashChain, siemForwarder, cfg.AuditLogParams)

	// RD-1112: async access-log auditing. When AUDIT_BUFFER_DIR is set, the hot
	// path appends each entry to a durable Pebble buffer and a single background
	// sealer drains it into the access_logs chain off the request path — removing
	// the per-request chain mutex + 2 PG round-trips that capped throughput. A
	// single-writer sealer means no chain fork. Empty dir = synchronous legacy path.
	if cfg.AuditBufferDir != "" {
		auditBuf, bufErr := buffer.Open(cfg.AuditBufferDir)
		if bufErr != nil {
			return nil, fmt.Errorf("open audit buffer at %q: %w", cfg.AuditBufferDir, bufErr)
		}
		s.auditBuffer = auditBuf

		sealFn := func(ctx context.Context, seq uint64, data []byte) error {
			var rec db.AccessLogRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				// A corrupt buffered record must not wedge the sealer. Log loudly
				// and skip it; the high-water advances past it on the next drain.
				slog.Error("audit sealer: corrupt buffered record skipped", "seq", seq, "error", err)
				return nil
			}
			hash, err := database.SealBufferedAccessLog(ctx, hashChain, rec, seq, cfg.AuditChainName)
			if err != nil {
				return err
			}
			// SIEM forwarding moved here from logAccess (off the hot path).
			if siemForwarder != nil {
				outcome := "success"
				if rec.StatusCode >= 400 {
					outcome = "denied"
				}
				if rec.StatusCode >= 500 {
					outcome = "error"
				}
				respStatus := rec.StatusCode
				if rec.ResponseStatus != nil {
					respStatus = *rec.ResponseStatus
				}
				ev := audit.SIEMEvent{
					Timestamp:     time.Now().UTC(),
					EventType:     "access",
					CorrelationID: rec.CorrelationID,
					ActorID:       rec.ExternalID,
					Action:        rec.Method,
					Outcome:       outcome,
					Details:       fmt.Sprintf("decision=%d response=%d", rec.StatusCode, respStatus),
					SourceIP:      rec.IPAddress,
					EntryHash:     hash,
				}
				if w := rbac.MatchWildcard(rec.Method); w != nil {
					ev.MatchedVia = "wildcard"
					ev.MatchedPrefix = w.Prefix
				}
				siemForwarder.Send(ev)
			}
			return nil
		}
		highWater := func(ctx context.Context) (uint64, error) {
			return database.GetMaxAccessLogBufferSeq(ctx, cfg.AuditChainName)
		}
		s.auditSealer = sealer.New(auditBuf, sealFn, highWater, sealer.Config{})
		sealerCtx, sealerCancel := context.WithCancel(context.Background())
		s.auditSealerCancel = sealerCancel
		go s.auditSealer.Run(sealerCtx)

		s.jsonrpcProcessor.SetAuditBuffer(auditBuf)
		slog.Info("async access-log auditing enabled (RD-1112)", "buffer_dir", cfg.AuditBufferDir)
	}

	// RD-1112 #8: signed truncation-detection checkpoints. The worker periodically
	// signs each chain's head + row count; the integrity verifier (below) uses the
	// latest signed checkpoint to detect tail truncation that a plain hash-walk
	// cannot see. Enabled when AUDIT_CHECKPOINT_KEY is set; the key must come from a
	// secret distinct from the DB credential (security review #2).
	var checkpointSigner audit.Signer
	var checkpointReader audit.CheckpointReader
	if cfg.AuditCheckpointKey != "" {
		checkpointSigner = audit.NewHMACSigner("default", []byte(cfg.AuditCheckpointKey))
		adapter := checkpointAdapter{db: database}
		checkpointReader = adapter
		s.auditCheckpointWorker = audit.NewCheckpointWorker(adapter, checkpointSigner,
			[]audit.ChainName{audit.ChainName(cfg.AuditChainName)}, cfg.AuditCheckpointInterval)
		ckptCtx, ckptCancel := context.WithCancel(context.Background())
		s.auditCheckpointCancel = ckptCancel
		go s.auditCheckpointWorker.Run(ckptCtx)
		slog.Info("audit chain checkpointing enabled (RD-1112 #8)", "interval", cfg.AuditCheckpointInterval)
	}

	// Initialize retention cleaner
	retentionCleaner := audit.NewRetentionCleaner(audit.RetentionConfig{
		AccessLogs:       cfg.RetentionAccessLogs,
		ComplianceLogs:   cfg.RetentionComplianceLogs,
		RBACAuditLogs:    cfg.RetentionRBACAuditLogs,
		TravelRecords:    cfg.RetentionTravelRecords,
		CleanupInterval:  cfg.RetentionCleanupInterval,
		MaxAccessLogRows: cfg.MaxAccessLogRows,
	}, database, cfg.EnableTravelRule)
	s.retentionCleaner = retentionCleaner
	slog.Info("retention cleaner started",
		"access", cfg.RetentionAccessLogs,
		"compliance", cfg.RetentionComplianceLogs,
		"rbac", cfg.RetentionRBACAuditLogs,
		"travel", cfg.RetentionTravelRecords,
		"interval", cfg.RetentionCleanupInterval,
		"max_access_log_rows", cfg.MaxAccessLogRows)

	// M7 (security audit follow-up): visibility outbox reconciler. Drains
	// pending_tx_visibility rows into tx_visible_to. Survives DB hiccups
	// in the hot JSON-RPC write path; rows are retried until promoted or
	// dead-lettered (attempt_count >= 10).
	s.visibilityReconciler = NewVisibilityReconciler(database, DefaultVisibilityReconcilerConfig())
	s.visibilityReconciler.Start(context.Background())
	slog.Info("visibility reconciler started", "interval", "5s", "batch", 100)

	// RD-858: scheduled audit hash-chain integrity verifier. Default
	// interval 15m (config: AUDIT_INTEGRITY_VERIFY_INTERVAL). On
	// detection: structured slog.Error, Prometheus
	// audit_chain_integrity_violations_total counter increment, SIEM
	// event via the existing forwarder, and (optional) generic webhook
	// POST to AUDIT_TAMPER_WEBHOOK_URL. The SSRF guard on the webhook
	// URL is enforced in config.Validate.
	if cfg.AuditIntegrityVerifyInterval > 0 {
		verifier := audit.NewVerifier(database.Conn(), database)
		// RD-1112 #8: enable the signed-checkpoint tail-truncation guard.
		if checkpointSigner != nil && checkpointReader != nil {
			verifier.SetCheckpointVerification(checkpointReader, checkpointSigner)
		}
		notifiers := &audit.MultiNotifier{}
		if siemForwarder != nil {
			notifiers.Notifiers = append(notifiers.Notifiers, &audit.SIEMNotifier{Forwarder: siemForwarder})
		}
		if cfg.AuditTamperWebhookURL != "" {
			webhookNotifier, whErr := audit.NewWebhookNotifier(cfg.AuditTamperWebhookURL)
			if whErr != nil {
				slog.Error("audit tamper webhook init failed; continuing without webhook notification", "err", whErr)
			} else if webhookNotifier != nil {
				notifiers.Notifiers = append(notifiers.Notifiers, webhookNotifier)
			}
		}
		s.auditIntegrityWorker = audit.NewIntegrityWorker(verifier, notifiers, audit.IntegrityWorkerConfig{
			Interval:   cfg.AuditIntegrityVerifyInterval,
			Violations: m.AuditChainIntegrityViolations,
		})
		s.auditIntegrityWorker.Start(context.Background())
		slog.Info("audit chain integrity verifier started",
			"interval", cfg.AuditIntegrityVerifyInterval,
			"siem_notify", siemForwarder != nil,
			"webhook_notify", cfg.AuditTamperWebhookURL != "")
	} else {
		slog.Warn("AUDIT_INTEGRITY_VERIFY_INTERVAL=0: scheduled audit-chain verifier DISABLED. Run privacy-cli audit verify manually or via cron.")
	}

	// Security: warn loudly if admin API has no token configured.
	// Without a token, admin endpoints are open to the entire private network.
	if cfg.AdminAPIToken == "" {
		slog.Warn("ADMIN_API_TOKEN is not set - admin API is unprotected, any request from the private network will be accepted without authentication")
	}

	return s, nil
}

func (s *Server) Run(addr string) error {
	router := s.setupRouter()
	return router.Run(addr)
}

// RunWithServer runs the server with a custom http.Server for graceful shutdown support.
func (s *Server) RunWithServer(httpServer *http.Server) error {
	router := s.setupRouter()
	httpServer.Handler = router
	return httpServer.ListenAndServe()
}

func (s *Server) setupRouter() *gin.Engine {
	router := gin.Default()

	// Trust Docker network proxies (allows X-Forwarded-For to work correctly)
	// This enables localhost detection when accessing from host to Docker container
	// SECURITY: Only requests FROM these IPs can set X-Forwarded-For headers.
	// External attackers cannot spoof X-Forwarded-For because their IP won't be trusted.
	// Trusted proxy IPs that can set X-Forwarded-For headers
	// Includes default private ranges + user-configured trusted proxies
	trustedProxies := []string{
		"127.0.0.1",
		"::1",
		"172.16.0.0/12",  // Docker bridge networks
		"192.168.0.0/16", // Docker custom networks / private networks
		"10.0.0.0/8",     // Private networks
		"100.64.0.0/10",  // Tailscale / CGNAT
	}
	if len(s.config.TrustedProxies) > 0 {
		trustedProxies = append(trustedProxies, s.config.TrustedProxies...)
	}
	router.SetTrustedProxies(trustedProxies)

	// Prometheus HTTP metrics middleware
	router.Use(s.metrics.HTTPMiddleware())

	// Correlation ID middleware (generates/propagates request IDs for audit trail)
	router.Use(correlationIDMiddleware())

	// CORS middleware for frontend
	router.Use(s.corsMiddleware())

	// Health check endpoint (no auth required)
	// Support both GET and HEAD for healthchecks (wget --spider uses HEAD)
	healthHandler := func(c *gin.Context) {
		if c.Request.Method == http.MethodHead {
			c.Status(http.StatusOK)
		} else {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		}
	}
	router.GET("/health", healthHandler)
	router.HEAD("/health", healthHandler)

	// Prometheus metrics endpoint — restricted to private network
	metricsHandler := promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{})
	router.GET("/metrics", s.localhostOnlyMiddleware(), gin.WrapH(metricsHandler))

	// Authentication endpoints (no auth required)
	// Rate limited to prevent brute force attacks
	authRL := s.authRateLimiter.Middleware()

	// Register at both root level (for direct access) and under /api (for frontend proxy)
	router.POST("/auth/request", authRL, s.handleAuthRequest)
	router.POST("/auth/callback", authRL, s.handleAuthCallback)
	router.POST("/refresh", authRL, s.handleRefresh)
	router.POST("/revoke", authRL, s.handleRevoke)
	router.POST("/introspect", authRL, s.handleIntrospect)

	// Versioned API auth endpoints (v1) - primary path
	router.POST("/api/v1/auth/request", authRL, s.handleAuthRequest)
	router.POST("/api/v1/auth/callback", authRL, s.handleAuthCallback)
	router.GET("/api/v1/auth/session/:id/status", s.handleAuthSessionStatus)
	router.POST("/api/v1/refresh", authRL, s.handleRefresh)
	router.POST("/api/v1/revoke", authRL, s.handleRevoke)
	router.POST("/api/v1/introspect", authRL, s.handleIntrospect)

	// Legacy API auth endpoints (unversioned) - deprecated, for backwards compatibility
	deprecation := s.deprecationMiddleware("/api", "/api/v1")
	router.POST("/api/auth/request", authRL, deprecation, s.handleAuthRequest)
	router.POST("/api/auth/callback", authRL, deprecation, s.handleAuthCallback)
	router.GET("/api/auth/session/:id/status", deprecation, s.handleAuthSessionStatus)
	router.POST("/api/refresh", authRL, deprecation, s.handleRefresh)
	router.POST("/api/revoke", authRL, deprecation, s.handleRevoke)
	router.POST("/api/introspect", authRL, deprecation, s.handleIntrospect)

	// Azure AD / Microsoft Entra ID authentication endpoints
	// Always registered; handlers return 404 when Azure AD is not configured.
	router.GET("/api/v1/auth/azure/url", authRL, s.handleAzureAuthURL)
	router.POST("/api/v1/auth/azure/callback", authRL, s.handleAzureCallback)
	// RD-1120: service-principal (client-credentials) M2M login — exchange an
	// Azure AD access token for our local tokens. Self-gates on nil authenticator.
	router.POST("/api/v1/auth/azure/service-principal", authRL, s.handleAzureServicePrincipal)
	router.GET("/api/v1/auth/providers", s.handleAuthProviders)

	// Dev identity picker endpoint (development/testing only, mockauth builds)
	if !s.config.IsProduction() && s.config.AllowMockLogin {
		router.GET("/api/v1/dev/test-identities", s.handleGetTestIdentities)
	}

	// Manual verification endpoint (development/testing only)
	if !s.config.IsProduction() {
		router.POST("/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/v1/auth/verify", authRL, s.handleAuthVerify)
		router.POST("/api/auth/verify", authRL, deprecation, s.handleAuthVerify)
	}

	// OAuth 2.0 endpoints - enables privacy-proxy as an Identity Provider
	// Used by block explorer for Single Sign-On with Privado ID authentication
	// Rate limited to prevent brute force attacks.
	//
	// /authorize uses OptionalJWTAuthMiddleware so RD-993 silent-SSO can
	// record the initiator's DID on the session when the caller already
	// has a PP JWT. Anonymous callers go through the normal interactive
	// flow with an empty InitiatorDID; silent-complete then refuses to
	// auto-complete that session for anyone.
	router.GET("/oauth/authorize", authRL, auth.OptionalJWTAuthMiddleware(s.jwtService, s.db), s.handleOAuthAuthorize)
	router.POST("/oauth/callback", authRL, s.handleOAuthCallback)
	router.POST("/oauth/token", authRL, s.handleOAuthToken)
	router.GET("/oauth/session/:id/info", authRL, s.handleOAuthSessionInfo)
	router.GET("/oauth/session/:id/status", s.handleOAuthSessionStatus) // no rate limit: read-only polling during QR scan
	router.POST("/oauth/session/:id/mock-complete", authRL, s.handleOAuthMockComplete)
	// RD-993: silent-SSO endpoint. JWT-gated; the handler also enforces
	// the first-party-client + same-initiator checks.
	router.POST("/oauth/session/:id/silent-complete", authRL, auth.JWTAuthMiddleware(s.jwtService, s.db), s.handleOAuthSilentComplete)

	// ETH address linking endpoints - available at multiple paths for flexibility:
	// - /api/v1/eth/* - versioned API (primary)
	// - /api/eth/* - legacy unversioned (deprecated)
	// - /eth/* - for direct API access (mobile apps, CLI tools)
	// All require JWT authentication.
	ethEndpoints := func(group *gin.RouterGroup) {
		group.POST("/link/challenge", s.handleEthLinkChallenge)
		group.POST("/link/verify", s.handleEthLinkVerify)
		group.GET("/addresses", s.handleGetEthAddresses)
		group.DELETE("/addresses/:address", s.handleDeleteEthAddress)
		group.POST("/addresses/:address/refresh-ens", s.handleRefreshENS)
	}

	// Versioned API eth endpoints (v1) - primary
	apiV1Eth := router.Group("/api/v1/eth")
	apiV1Eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(apiV1Eth)

	// Legacy API eth endpoints (unversioned) - deprecated
	apiEth := router.Group("/api/eth")
	apiEth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	apiEth.Use(deprecation)
	ethEndpoints(apiEth)

	// Direct eth endpoints (no /api prefix)
	eth := router.Group("/eth")
	eth.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	ethEndpoints(eth)

	// JSON-RPC proxy endpoint - protected by optional JWT
	// Support both "/" (direct access) and "/rpc" (frontend proxy)
	// For users with multiple org memberships, use "/rpc/:org_id" to specify org
	router.POST("/", auth.OptionalJWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)
	router.POST("/rpc", auth.OptionalJWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)
	router.POST("/rpc/:org_id", auth.OptionalJWTAuthMiddleware(s.jwtService, s.db), s.handleJSONRPC)

	// User disclosure endpoints - protected by JWT but accessible from external IPs
	s.registerUserDisclosureRoutes(router)

	// User profile endpoints - protected by JWT but accessible from external IPs
	s.registerUserProfileRoutes(router)

	// Explorer API endpoints - internal APIs for block explorer integration
	// Protected by localhost-only middleware (called by explorer backend)
	s.registerExplorerRoutes(router)

	// API endpoints for UI - protected by localhost-only middleware
	// Register versioned API (v1) - primary path
	adminAuth := s.adminAuthMiddleware()
	orgScope := s.orgScopingMiddleware()
	apiV1 := router.Group("/api/v1")
	{
		// Admin endpoints - private network + token auth + org scoping
		admin := apiV1.Group("/admin")
		admin.Use(s.localhostOnlyMiddleware(), adminAuth, orgScope)
		{
			admin.GET("/logs", s.getLogs)
			admin.GET("/status", s.getStatus)
			admin.POST("/test-request", s.handleTestRequest)
			admin.GET("/eth-addresses/collisions", s.getEthAddressCollisions)

			// RBAC endpoints
			s.registerRBACRoutes(admin)

			// Disclosure admin endpoints
			s.registerDisclosureRoutes(admin)

			// Compliance endpoints (travel rule)
			s.registerComplianceRoutes(admin)

			// RD-928 / RD-994: "View as user" impersonation surface. Mounted
			// under /api/v1/admin/impersonate/:target_did/in/:org_id/{explorer,rpc}/...
			// with its own middleware that re-enforces tier-2 admin (rejecting
			// super-admin and read-only admin), verifies the explicit :org_id
			// is one of the caller's orgs (403 otherwise) and that the target
			// is a member of it (404 otherwise), GET-only, and per-request
			// impersonation_log writes. The bare route (no /in/:org_id) is 400.
			s.registerImpersonationRoutes(admin)

			// Dev-only endpoints
			admin.POST("/dev/deploy-demo-erc20", s.handleDeployDemoERC20)
		}

		// System-wide settings — fleet-level toggles, NOT org-scoped.
		// Separate group so we can omit orgScope (system settings have
		// no :org_id) while keeping the localhost + admin-auth gates.
		// Per-route super-admin checks happen inside the handlers.
		system := apiV1.Group("/admin/system")
		system.Use(s.localhostOnlyMiddleware(), adminAuth)
		{
			system.GET("/eth-call-tracing", s.handleGetEthCallTracing)
			system.POST("/eth-call-tracing", s.handlePostEthCallTracing)

			// RD-1053: intra-org contract-grant scoping on internal trace
			// frames. Same super-admin-write / any-admin-read posture as
			// eth-call-tracing above.
			system.GET("/intra-org-grant-tracing", s.handleGetIntraOrgGrantTracing)
			system.POST("/intra-org-grant-tracing", s.handlePostIntraOrgGrantTracing)

			// RD-1023: build identity of the running binary. Read-only,
			// admin-gated; intentionally not on /health or web3_clientVersion.
			system.GET("/version", s.handleGetVersion)
		}
	}

	// Legacy API (unversioned) - deprecated, for backwards compatibility
	// Adds X-Deprecated header to responses
	api := router.Group("/api")
	{
		adminLegacy := api.Group("/admin")
		adminLegacy.Use(s.localhostOnlyMiddleware(), adminAuth, orgScope)
		adminLegacy.Use(s.deprecationMiddleware("/api/admin", "/api/v1/admin"))
		{
			adminLegacy.GET("/logs", s.getLogs)
			adminLegacy.GET("/status", s.getStatus)
			adminLegacy.POST("/test-request", s.handleTestRequest)

			// RBAC endpoints
			s.registerRBACRoutes(adminLegacy)

			// Disclosure admin endpoints
			s.registerDisclosureRoutes(adminLegacy)

			// Compliance endpoints (travel rule)
			s.registerComplianceRoutes(adminLegacy)
		}
	}

	return router
}

// MaxRequestBodySize is the maximum allowed request body size (1MB).
const MaxRequestBodySize = 1 << 20 // 1MB

func (s *Server) handleJSONRPC(c *gin.Context) {
	// Extract identity. Under the RD-928 impersonation surface this is the
	// target user's DID set by impersonationGateMiddleware; otherwise it's
	// the JWT subject from OptionalJWTAuthMiddleware. getEffectiveViewerDID
	// encapsulates the priority order.
	subjectStr := getEffectiveViewerDID(c)
	impersonating := isImpersonating(c)

	// Read request body with size limit to prevent DoS
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, MaxRequestBodySize+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	// Parse and validate the request body
	method, params, parseErr := ParseAndValidateBody(body)
	if parseErr != nil {
		c.JSON(parseErr.StatusCode, gin.H{"error": parseErr.Message})
		return
	}

	// Extract optional org_id from path (for the production /rpc/:org_id
	// route).
	orgID := c.Param("org_id")
	// RD-994: under impersonation the org is the explicit :org_id the gate
	// validated and pinned in the context. It is authoritative — we anchor
	// to it unconditionally, ignoring any /rpc/:nested_org_id segment a
	// caller might tack on. This guarantees the impersonated read is scoped
	// to exactly the org the admin named in the URL (and was authorised for
	// + the target was verified a member of), not some other org reachable
	// via the nested param.
	if impersonating {
		if oid, ok := c.Get(impersonationOrgIDContextKey); ok {
			if s, ok := oid.(string); ok && s != "" {
				orgID = s
			}
		}
	}

	// Process the request through the business logic layer
	result := s.jsonrpcProcessor.Process(c.Request.Context(), &ProcessRequest{
		UserID:           subjectStr,
		OrgID:            orgID,
		Method:           method,
		Params:           params,
		Body:             body,
		ClientIP:         c.ClientIP(),
		CorrelationID:    getCorrelationID(c),
		BypassPermsCache: impersonating,
	})

	// Handle errors from processing
	if result.Error != nil {
		c.JSON(result.Error.StatusCode, gin.H{"error": result.Error.Message})
		return
	}

	// Return response from node
	c.Data(result.StatusCode, "application/json", result.ResponseBody)
}

func (s *Server) getLogs(c *gin.Context) {
	filter := db.AccessLogFilter{
		ExternalID:    strings.TrimSpace(c.Query("external_id")),
		Method:        strings.TrimSpace(c.Query("method")),
		CorrelationID: strings.TrimSpace(c.Query("correlation_id")),
	}

	statusStr := strings.TrimSpace(c.Query("status_code"))
	outcomeStr := strings.TrimSpace(c.Query("outcome"))

	// status_code (exact) and outcome (range) are mutually exclusive — operators
	// pick one or the other to avoid contradictions like ?status_code=200&outcome=denied.
	if statusStr != "" && outcomeStr != "" && outcomeStr != "all" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "use status_code OR outcome, not both"})
		return
	}

	if statusStr != "" {
		if n, err := strconv.Atoi(statusStr); err == nil && n > 0 {
			filter.StatusCode = n
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid status_code"})
			return
		}
	}

	switch outcomeStr {
	case "", "all":
		// no class filter
	case "success":
		filter.StatusClass = "2xx"
	case "denied":
		filter.StatusClass = "4xx"
	case "error":
		filter.StatusClass = "5xx"
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid outcome; expected one of: success, denied, error, all"})
		return
	}

	if fromStr := strings.TrimSpace(c.Query("from")); fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from timestamp; expected RFC3339"})
			return
		}
		filter.From = t
	}
	if toStr := strings.TrimSpace(c.Query("to")); toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to timestamp; expected RFC3339"})
			return
		}
		filter.To = t
	}

	limit := 100
	if limitStr := strings.TrimSpace(c.Query("limit")); limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > db.MaxAccessLogQueryLimit {
		limit = db.MaxAccessLogQueryLimit
	}
	filter.Limit = limit

	if offsetStr := strings.TrimSpace(c.Query("offset")); offsetStr != "" {
		if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
			filter.Offset = n
		}
	}

	ctx := c.Request.Context()
	logs, err := s.db.GetAccessLogs(ctx, filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read access logs"})
		return
	}
	total, err := s.db.CountAccessLogs(ctx, filter)
	if err != nil {
		// Don't fail the whole request if the count fails; return -1 as a
		// sentinel so the UI can fall back to "load more".
		total = -1
	}

	c.JSON(http.StatusOK, gin.H{
		"data":   logs,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// corsMiddleware returns a CORS middleware configured from server settings.
// In development (or with CORSAllowedOrigins="*"), allows all origins.
// In production, only allows configured origins.
func (s *Server) corsMiddleware() gin.HandlerFunc {
	allowedOrigins := s.config.CORSAllowedOrigins

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Determine if this origin should be allowed
		var allowOrigin string
		if allowedOrigins == "*" {
			allowOrigin = "*"
		} else if allowedOrigins != "" {
			// Check if origin is in the allowed list
			for _, allowed := range strings.Split(allowedOrigins, ",") {
				if strings.TrimSpace(allowed) == origin {
					allowOrigin = origin
					break
				}
			}
		}

		if allowOrigin != "" {
			c.Writer.Header().Set("Access-Control-Allow-Origin", allowOrigin)
			if allowOrigin != "*" {
				c.Writer.Header().Set("Vary", "Origin")
				c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// adminAuthMiddleware enforces authentication for admin APIs.
// Accepts EITHER:
//   - X-Admin-Token header (M2M / bootstrap / scripts)
//   - Authorization: Bearer <JWT> where the user has the "admin" RBAC claim
//
// If no admin token is configured AND no JWT is provided, the middleware is a
// no-op (dev mode) — localhost/network controls remain the only gate.
func (s *Server) adminAuthMiddleware() gin.HandlerFunc {
	expectedToken := strings.TrimSpace(s.config.AdminAPIToken)

	return func(c *gin.Context) {
		// --- Path 1: X-Admin-Token (M2M / bootstrap) ---
		if provided := strings.TrimSpace(c.GetHeader("X-Admin-Token")); provided != "" {
			if expectedToken != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(expectedToken)) == 1 {
				c.Set("auth_method", "admin_token")
				c.Next()
				return
			}
			// Token provided but wrong — reject immediately.
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing X-Admin-Token"})
			c.Abort()
			return
		}

		// --- Path 2: JWT Bearer with admin claim ---
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && parts[0] == "Bearer" {
				tokenString := parts[1]

				// Validate the JWT (reuses the same logic as JWTAuthMiddleware).
				claims, err := s.jwtService.ValidateAccessToken(tokenString)
				if err != nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
					c.Abort()
					return
				}

				// Check revocation.
				if s.db != nil {
					tokenID := auth.HashToken(tokenString)
					revoked, revErr := s.db.IsAccessTokenRevoked(c.Request.Context(), tokenID)
					if revErr != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check token revocation"})
						c.Abort()
						return
					}
					if revoked {
						c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
						c.Abort()
						return
					}
				}

				// Look up user by external ID (DID / subject).
				user, err := s.db.GetUserByExternalID(c.Request.Context(), claims.Subject)
				if err != nil || user == nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
					c.Abort()
					return
				}

				if user.Banned {
					c.JSON(http.StatusForbidden, gin.H{"error": "user is banned"})
					c.Abort()
					return
				}

				// Check if the user is an org admin (is_org_admin = true on their group).
				// This is tier 2 in the 3-tier admin model. Contract admins (tier 3,
				// who have 'admin' in group_access.claims but NOT is_org_admin) are
				// denied admin dashboard access.
				isOrgAdmin, adminOrgIDs, err := s.db.IsOrgAdmin(c.Request.Context(), user.ID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check admin status"})
					c.Abort()
					return
				}

				isReadonlyAdmin, readonlyAdminOrgIDs, err := s.db.IsOrgReadonlyAdmin(c.Request.Context(), user.ID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check readonly admin status"})
					c.Abort()
					return
				}

				if !isOrgAdmin && !isReadonlyAdmin {
					c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions: org admin or read-only admin required"})
					c.Abort()
					return
				}

				c.Set("auth_method", "jwt_admin")
				c.Set("admin_subject", claims.Subject)
				c.Set("admin_user_id", user.ID)                      // Internal Postgres UUID
				c.Set("admin_org_ids", adminOrgIDs)                  // Org IDs where user is org admin
				c.Set("admin_readonly_org_ids", readonlyAdminOrgIDs) // Org IDs where user is read-only org admin
				c.Next()
				return
			}
		}

		// --- Path 3: No credentials supplied ---
		if expectedToken == "" {
			// Dev mode: no token configured, allow through (existing no-op behaviour).
			c.Next()
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		c.Abort()
	}
}

// orgScopingMiddleware enforces that JWT-based org admins (tier 2) can only
// access resources within their own organizations. Super admins (X-Admin-Token)
// bypass this check entirely.
//
// For routes with :org_id in the path, the middleware verifies the org_id matches
// one of the admin's org IDs stored in context by adminAuthMiddleware.
//
// For routes without :org_id (e.g., cross-org lookups, user management), super
// admin is required — JWT admins get 403.
func (s *Server) orgScopingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authMethod := c.GetString("auth_method")

		// Super admin (X-Admin-Token) bypasses org scoping entirely.
		if authMethod == "admin_token" {
			c.Next()
			return
		}

		// Dev mode: no auth configured, allow through.
		if authMethod == "" {
			c.Next()
			return
		}

		// JWT admin: enforce org scoping.
		orgID := c.Param("org_id")
		if orgID == "" {
			// Routes without :org_id are either generic (status, logs, users,
			// my admin status) or user-specific (user detail, memberships).
			// These are safe for any authenticated org admin — they don't expose
			// cross-org data. The individual handlers enforce further scoping
			// where needed (e.g., user list filters by org).

			// For global routes without org_id, if they are mutating (POST/PUT/DELETE)
			// the user must have full admin rights in at least one org.
			if c.Request.Method != http.MethodGet {
				adminOrgIDsRaw, existsAdmin := c.Get("admin_org_ids")
				hasFullAdmin := false
				if existsAdmin {
					if ids, ok := adminOrgIDsRaw.([]string); ok && len(ids) > 0 {
						hasFullAdmin = true
					}
				}
				if !hasFullAdmin {
					c.JSON(http.StatusForbidden, gin.H{"error": "mutating actions are restricted for read-only admins"})
					c.Abort()
					return
				}
			}

			c.Next()
			return
		}

		// Check if the org_id is in the admin's scoped org list or read-only list.
		adminOrgIDsRaw, existsAdmin := c.Get("admin_org_ids")
		readonlyOrgIDsRaw, existsReadonly := c.Get("admin_readonly_org_ids")

		if !existsAdmin && !existsReadonly {
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied"})
			c.Abort()
			return
		}

		var allowedOrgIDs []string
		if existsAdmin {
			if ids, ok := adminOrgIDsRaw.([]string); ok {
				allowedOrgIDs = append(allowedOrgIDs, ids...)
			}
		}
		if existsReadonly {
			if ids, ok := readonlyOrgIDsRaw.([]string); ok {
				allowedOrgIDs = append(allowedOrgIDs, ids...)
			}
		}

		for _, id := range allowedOrgIDs {
			if id == orgID {
				// Enforce read-only restriction for mutating endpoints for this specific org.
				if c.Request.Method != http.MethodGet {
					isFullAdmin := false
					if existsAdmin {
						if ids, ok := adminOrgIDsRaw.([]string); ok {
							for _, aid := range ids {
								if aid == orgID {
									isFullAdmin = true
									break
								}
							}
						}
					}
					if !isFullAdmin {
						c.JSON(http.StatusForbidden, gin.H{"error": "mutating actions are restricted for read-only admins"})
						c.Abort()
						return
					}
				}

				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "access denied to this organization"})
		c.Abort()
	}
}

// deprecationMiddleware adds deprecation headers to responses.
// It signals to clients that they should migrate to the versioned API.
func (s *Server) deprecationMiddleware(oldPath, newPath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Add deprecation headers per RFC 8594
		c.Header("Deprecation", "true")
		c.Header("Sunset", "2027-01-01T00:00:00Z") // Give clients a year to migrate
		c.Header("Link", fmt.Sprintf("<%s%s>; rel=\"successor-version\"", newPath, strings.TrimPrefix(c.Request.URL.Path, oldPath)))
		c.Next()
	}
}

// localhostOnlyMiddleware restricts admin API access to requests arriving over the local
// network — localhost, Docker bridge networks, LAN, or Tailscale.
//
// SECURITY MODEL:
// We check the *direct TCP peer* (c.Request.RemoteAddr), NOT the logical client IP
// resolved through X-Forwarded-For. This is intentional:
//
//   - When Caddy (or any reverse proxy) sits in front of the backend, the TCP peer is
//     always the proxy container's IP (e.g., 172.18.0.x) — which IS in the allowed range.
//   - The browser's real IP arrives in X-Forwarded-For, but we deliberately ignore it here.
//     The goal is to ensure the request physically traversed the private Docker network,
//     not to verify where the browser is geographically.
//   - If the backend port is accidentally exposed to the public internet, an attacker's
//     direct TCP connection will have a public source IP → blocked by this middleware,
//     even before the token check.
//
// Defense in depth: network boundary check (this middleware) + token auth (adminAuth).
func (s *Server) localhostOnlyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Use the raw TCP peer address, not the proxy-resolved client IP.
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid remote address"})
			c.Abort()
			return
		}
		ip := net.ParseIP(host)
		if ip == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "invalid client IP"})
			c.Abort()
			return
		}

		// Allowed private networks:
		// - 127.0.0.1/32: Localhost IPv4
		// - ::1/128: Localhost IPv6
		// - 172.16.0.0/12: Docker bridge networks (RFC1918)
		// - 192.168.0.0/16: Docker custom networks / WiFi (RFC1918)
		// - 100.64.0.0/10: Tailscale / CGNAT
		allowedCIDRs := []string{
			"127.0.0.1/32",
			"::1/128",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"10.0.0.0/8",
			"100.64.0.0/10",
		}
		// Append custom CIDRs from TRUSTED_INTERNAL_CIDRS env var
		if s.config != nil {
			allowedCIDRs = append(allowedCIDRs, s.config.TrustedInternalCIDRs...)
		}

		isAllowed := false
		for _, cidr := range allowedCIDRs {
			_, subnet, _ := net.ParseCIDR(cidr)
			if subnet != nil && subnet.Contains(ip) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "management API is only accessible from localhost, private networks, or Tailscale",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// StatusResponse represents the system status
type StatusResponse struct {
	Proxy    ProxyStatus    `json:"proxy"`
	Node     NodeStatus     `json:"node"`
	Security SecurityStatus `json:"security"`
	Methods  MethodsStatus  `json:"methods"`
}

// MethodsStatus exposes available RPC methods to the admin frontend.
type MethodsStatus struct {
	ExtraNamespaces map[string][]string          `json:"extra_namespaces,omitempty"`
	ExtraWildcards  map[string]ExtraWildcardInfo `json:"extra_wildcards,omitempty"`
}

// ExtraWildcardInfo describes a chain namespace running in prefix-wildcard mode.
// The frontend uses this to render a single togglable picker entry per
// wildcard-enabled namespace, plus a read-only view of the deny list.
type ExtraWildcardInfo struct {
	Prefix string   `json:"prefix"`
	Deny   []string `json:"deny,omitempty"`
}

// buildExtraWildcardsResponse projects the rbac.Wildcards registry into the
// status response shape (namespace name → prefix + deny list). Returns nil when
// no wildcards are registered so the JSON omits the field.
func buildExtraWildcardsResponse() map[string]ExtraWildcardInfo {
	if len(rbac.Wildcards) == 0 {
		return nil
	}
	out := make(map[string]ExtraWildcardInfo, len(rbac.Wildcards))
	for _, w := range rbac.Wildcards {
		out[w.Namespace] = ExtraWildcardInfo{
			Prefix: w.Prefix,
			Deny:   w.Deny,
		}
	}
	return out
}

// ProxyStatus represents the proxy status
type ProxyStatus struct {
	Status string `json:"status"`
	Port   string `json:"port"`
}

// SecurityStatus represents the security configuration status
type SecurityStatus struct {
	TravelRuleEnabled bool `json:"travel_rule_enabled"`
	// ComplianceDefaultMode is the cluster-wide default compliance enforcement
	// mode ("enforce" | "monitor"). Per-org config may override it. (RD-1044)
	ComplianceDefaultMode string `json:"compliance_default_mode"`
}

// NodeStatus represents the node status
type NodeStatus struct {
	Status    string `json:"status"`
	URL       string `json:"url"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (s *Server) getStatus(c *gin.Context) {
	// Check node health
	nodeHealth := s.proxy.CheckHealth()

	proxyPort := "8080"
	if s.config != nil && s.config.Port != "" {
		proxyPort = s.config.Port
	}

	// RD-1044: surface the cluster-wide default compliance enforcement mode.
	complianceMode := "enforce"
	if s.config != nil && s.config.ComplianceDefaultMode != "" {
		complianceMode = s.config.ComplianceDefaultMode
	}

	status := StatusResponse{
		Proxy: ProxyStatus{
			Status: "running",
			Port:   proxyPort,
		},
		Node: NodeStatus{
			Status:    nodeHealth.Status,
			URL:       nodeHealth.URL,
			LatencyMs: nodeHealth.LatencyMs,
			Error:     nodeHealth.Error,
		},
		Security: SecurityStatus{
			TravelRuleEnabled:     s.complianceChecker != nil,
			ComplianceDefaultMode: complianceMode,
		},
		Methods: MethodsStatus{
			ExtraNamespaces: rbac.ExtraNamespaces,
			ExtraWildcards:  buildExtraWildcardsResponse(),
		},
	}

	c.JSON(http.StatusOK, status)
}

// TestRequestInput represents the input for test request
type TestRequestInput struct {
	Method   string        `json:"method"`
	Params   []interface{} `json:"params"`
	JWTToken string        `json:"jwt_token,omitempty"`
	OrgID    string        `json:"org_id,omitempty"`
}

// TestRequestResponse represents the response for test request
type TestRequestResponse struct {
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	LatencyMs int64       `json:"latency_ms,omitempty"`
	Identity  string      `json:"identity,omitempty"` // The identity used for access control
}

func (s *Server) handleTestRequest(c *gin.Context) {
	var input TestRequestInput
	if err := c.ShouldBindJSON(&input); err != nil {
		// gin validator messages name struct fields — that's fine for a
		// localhost-only admin endpoint, but echo the error type only,
		// not err.Error() verbatim (which would also surface wrapped
		// chains on custom validators). RD-934.
		slog.Warn("test-request: invalid body", "err", err, "ip", c.ClientIP())
		respondBadRequest(c, "invalid request body")
		return
	}

	// Use synthetic identity for test requests or extract from JWT token
	testIdentity := "test:dashboard"
	if input.JWTToken != "" {
		claims, err := s.jwtService.ValidateAccessToken(input.JWTToken)
		if err != nil {
			// JWT validator errors can include token-shape internals; do
			// not echo. RD-934.
			slog.Warn("test-request: jwt validate failed", "err", err, "ip", c.ClientIP())
			respondBadRequest(c, "invalid JWT")
			return
		}
		testIdentity = claims.Subject
	}

	// Check access via RBAC
	var testRequiredClaims []rbac.Claim
	if claim := rbac.ClassifyOperation(input.Method, input.Params); claim != "" {
		testRequiredClaims = []rbac.Claim{claim}
	}
	accessReq := &rbac.AccessCheckRequest{
		UserExternalID:   testIdentity,
		OrgID:            input.OrgID,
		Method:           input.Method,
		Params:           input.Params,
		TargetAddress:    rbac.GetTargetAddress(input.Method, input.Params),
		FunctionSelector: rbac.GetFunctionSelector(input.Method, input.Params),
		RequiredClaims:   testRequiredClaims,
	}
	result, err := s.rbacAccessCtrl.CheckAccess(c.Request.Context(), accessReq)
	if err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusInternalServerError, c.ClientIP())
		// CheckAccess errors expose RBAC internals (DB shape, cache
		// state, store-layer codes) — operator-only. RD-934.
		slog.Error("test-request: CheckAccess errored", "identity", testIdentity, "method", input.Method, "err", err)
		c.JSON(http.StatusInternalServerError, TestRequestResponse{
			Error:    "access check failed",
			Identity: testIdentity,
		})
		return
	}
	if !result.Allowed {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
		// AccessCheckResult.Reason is operator-only by contract (see
		// the type's doc-comment in internal/rbac/models.go). The
		// previous behaviour echoed it verbatim, which would leak the
		// RD-877 cardinality-guard message ("multiple organizations…")
		// and similar diagnostics to admin scripts. RD-934.
		slog.Info("test-request: RBAC denied", "identity", testIdentity, "method", input.Method, "reason", result.Reason)
		c.JSON(http.StatusForbidden, TestRequestResponse{
			Error:    "access denied",
			Identity: testIdentity,
		})
		return
	}

	// Travel rule compliance check for eth_sendTransaction and eth_sendRawTransaction
	if s.complianceChecker != nil {
		var compFrom, compTo, compData, compValue string
		var needsCheck bool

		switch input.Method {
		case "eth_sendTransaction":
			compFrom, compTo, compData, compValue = extractTxParams(input.Params)
			needsCheck = true
		case "eth_sendRawTransaction":
			rawTxHex, extractErr := extractRawTxHex(input.Params)
			if extractErr != nil {
				c.JSON(http.StatusBadRequest, TestRequestResponse{
					Error:    "failed to extract raw transaction: " + extractErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			var decodeErr error
			compFrom, compTo, compData, compValue, _, decodeErr = decodeRawTransaction(rawTxHex)
			if decodeErr != nil {
				c.JSON(http.StatusBadRequest, TestRequestResponse{
					Error:    "failed to decode raw transaction: " + decodeErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			needsCheck = true
		}

		if needsCheck {
			compResult, compErr := s.complianceChecker.Check(c.Request.Context(), &compliance.CheckRequest{
				OrgID:         result.OrgID,
				UserID:        result.UserID,
				From:          compFrom,
				To:            compTo,
				Data:          compData,
				Value:         compValue,
				CorrelationID: getCorrelationID(c),
			})
			if compErr != nil {
				c.JSON(http.StatusInternalServerError, TestRequestResponse{
					Error:    "compliance check failed: " + compErr.Error(),
					Identity: testIdentity,
				})
				return
			}
			if !compResult.Allowed {
				s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusForbidden, c.ClientIP())
				c.JSON(http.StatusForbidden, TestRequestResponse{
					Error:    "compliance denied: " + compResult.Reason,
					Identity: testIdentity,
				})
				return
			}
		}
	}

	// Build JSON-RPC request
	rpcReq := proxy.JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  input.Method,
		Params:  input.Params,
		ID:      1,
	}
	reqBody, _ := json.Marshal(rpcReq)

	// Forward to node and measure latency
	start := time.Now()
	respBody, statusCode, err := s.proxy.Forward(reqBody)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, TestRequestResponse{
			Error:     err.Error(),
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	// Parse response
	var rpcResp proxy.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, http.StatusBadGateway, c.ClientIP())
		c.JSON(http.StatusBadGateway, TestRequestResponse{
			Error:     "invalid JSON-RPC response",
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	// Log successful access
	s.db.LogAccess(c.Request.Context(), testIdentity, input.Method, statusCode, c.ClientIP())

	// Return JSON-RPC response (may contain RPC-level error, that's fine - HTTP 200)
	if rpcResp.Error != nil {
		c.JSON(http.StatusOK, TestRequestResponse{
			Error:     rpcResp.Error.Message,
			LatencyMs: latency,
			Identity:  testIdentity,
		})
		return
	}

	c.JSON(http.StatusOK, TestRequestResponse{
		Result:    rpcResp.Result,
		LatencyMs: latency,
		Identity:  testIdentity,
	})
}

// registerUserProfileRoutes registers user profile endpoints (JWT-authenticated, accessible from external IPs).
func (s *Server) registerUserProfileRoutes(router *gin.Engine) {
	me := router.Group("/api/v1/me")
	me.Use(auth.JWTAuthMiddleware(s.jwtService, s.db))
	{
		me.GET("/orgs", s.getMyOrganizations)
		me.GET("/admin-status", s.getMyAdminStatus)
	}
}

// getMyAdminStatus returns whether the authenticated user has org admin privileges.
// Only users in groups with is_org_admin = true (tier 2) are considered admins
// for dashboard access purposes. Contract admins (tier 3, admin claim only) get
// is_admin: false because they have no admin dashboard access.
func (s *Server) getMyAdminStatus(c *gin.Context) {
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
		return
	}

	user, err := s.db.GetUserByExternalID(c.Request.Context(), subject.(string))
	if err != nil || user == nil {
		// User not in DB yet — not an admin.
		c.JSON(http.StatusOK, gin.H{"is_admin": false, "admin_org_ids": []string{}})
		return
	}

	isOrgAdmin, orgIDs, err := s.db.IsOrgAdmin(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check admin status"})
		return
	}

	isReadonlyAdmin, readonlyOrgIDs, err := s.db.IsOrgReadonlyAdmin(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check readonly admin status"})
		return
	}

	if orgIDs == nil {
		orgIDs = []string{}
	}
	if readonlyOrgIDs == nil {
		readonlyOrgIDs = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"is_admin":               isOrgAdmin || isReadonlyAdmin,
		"admin_org_ids":          orgIDs,
		"is_readonly_admin":      isReadonlyAdmin,
		"readonly_admin_org_ids": readonlyOrgIDs,
	})
}

// UserOrgResponse represents an organization the user belongs to.
type UserOrgResponse struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// getMyOrganizations returns the organizations the authenticated user belongs to.
func (s *Server) getMyOrganizations(c *gin.Context) {
	subject, exists := c.Get("subject")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing subject in context"})
		return
	}

	// Get user from database
	user, err := s.db.GetUserByExternalID(c.Request.Context(), subject.(string))
	if err != nil || user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	// Get user's memberships
	memberships, err := s.db.ListUserMembershipsWithDetails(c.Request.Context(), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get memberships"})
		return
	}

	// Collect unique orgs
	orgMap := make(map[string]*UserOrgResponse)
	for _, m := range memberships {
		if m.Group != nil && m.Group.OrgID != "" {
			if _, exists := orgMap[m.Group.OrgID]; !exists {
				org, err := s.db.GetOrganization(c.Request.Context(), m.Group.OrgID)
				if err == nil && org != nil {
					orgMap[org.ID] = &UserOrgResponse{
						ID:   org.ID,
						Slug: org.Slug,
						Name: org.Name,
					}
				}
			}
		}
	}

	// Convert to slice
	orgs := make([]*UserOrgResponse, 0, len(orgMap))
	for _, org := range orgMap {
		orgs = append(orgs, org)
	}

	c.JSON(http.StatusOK, gin.H{"organizations": orgs})
}

// recordAuthAttempt records an authentication attempt metric.
func (s *Server) recordAuthAttempt(provider, outcome string) {
	if s.metrics != nil {
		s.metrics.AuthAttemptsTotal.WithLabelValues(provider, outcome).Inc()
	}
}

// recordTokenRefresh records a token refresh attempt metric.
func (s *Server) recordTokenRefresh(outcome string) {
	if s.metrics != nil {
		s.metrics.AuthTokenRefreshesTotal.WithLabelValues(outcome).Inc()
	}
}

// redactRedisURL parses a Redis URL and masks any password so credentials
// are never written to logs. If the URL cannot be parsed, it returns
// "<redacted>" to avoid leaking a malformed but credential-bearing string.
func redactRedisURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<redacted>"
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}
