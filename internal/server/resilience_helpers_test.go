package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Shared Postgres container — started once via TestMain, reused by all DB tests
// ---------------------------------------------------------------------------

var sharedDBURL string
var sharedDBCleanup func()

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	// Check for external DB first
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		if err := db.EnsureTestDatabase(url); err != nil {
			fmt.Fprintf(os.Stderr, "TEST_DATABASE_URL set but unavailable: %v\n", err)
			os.Exit(1)
		}
		sharedDBURL = url
	} else {
		// Start one container for the entire test run
		url, cleanup := db.StartTestContainer()
		if url != "" {
			sharedDBURL = url
			sharedDBCleanup = cleanup
		}
		// If container fails, DB tests will be skipped
	}

	code := m.Run()

	if sharedDBCleanup != nil {
		sharedDBCleanup()
	}

	os.Exit(code)
}

// ensureSharedDB returns the shared DB URL, skipping the test if unavailable.
func ensureSharedDB(t *testing.T) string {
	t.Helper()
	if sharedDBURL == "" {
		t.Skip("no database available (Docker not running?)")
	}
	return sharedDBURL
}

// ---------------------------------------------------------------------------
// setupResilienceServer — uses shared DB, resets between tests
// ---------------------------------------------------------------------------

func setupResilienceServer(t *testing.T, adminToken string) (*Server, *gin.Engine) {
	t.Helper()

	dbURL := ensureSharedDB(t)
	database, err := db.New(dbURL)
	require.NoError(t, err)
	require.NoError(t, database.Migrate(context.Background()))
	require.NoError(t, db.ResetTestDatabase(database))

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		AdminAPIToken: adminToken,
		NodeURL:       "http://localhost:8545",
		JWTSecret:     "test-secret",
		BaseURL:       "http://localhost:8080",
		Environment:   "development",
	}

	srv := &Server{
		db:             database,
		jwtService:     jwtService,
		rbacAccessCtrl: rbac.NewAccessController(database, 5*time.Minute),
		config:         cfg,
	}

	router := gin.New()

	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	srv.registerRBACRoutes(admin)
	srv.registerComplianceRoutes(admin)

	t.Cleanup(func() { srv.db.Close() })

	return srv, router
}

// ---------------------------------------------------------------------------
// setupAuthOnlyRouter — no DB, no container. For tests that only check
// middleware auth enforcement (middleware rejects before handler runs).
// ---------------------------------------------------------------------------

func setupAuthOnlyRouter(t *testing.T, adminToken string) *gin.Engine {
	t.Helper()

	jwtService, err := auth.NewJWTService(
		"test-secret",
		"test-refresh-secret",
		30*time.Minute,
		7*24*time.Hour,
	)
	require.NoError(t, err)

	cfg := &config.Config{
		AdminAPIToken: adminToken,
		NodeURL:       "http://localhost:8545",
		JWTSecret:     "test-secret",
		BaseURL:       "http://localhost:8080",
		Environment:   "development",
	}

	srv := &Server{
		jwtService: jwtService,
		config:     cfg,
	}

	router := gin.New()

	admin := router.Group("/api/v1/admin")
	admin.Use(srv.adminAuthMiddleware())
	srv.registerRBACRoutes(admin)
	srv.registerComplianceRoutes(admin)

	return router
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func createOrgForTest(t *testing.T, srv *Server) string {
	t.Helper()
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "resilience-org-" + uuid.New().String()[:8],
		Name: "Resilience Test Org",
	}
	require.NoError(t, srv.db.CreateOrganization(context.Background(), org))
	return org.ID
}

func assertNoInternalErrorLeakage(t *testing.T, body string) {
	t.Helper()
	lower := strings.ToLower(body)
	leakPatterns := []string{
		"sql:", "pq:", "pgx:", "connection refused", "dial tcp",
		"no rows", "sqlstate", "stack trace", "goroutine", "runtime error",
		"panic:", "open /", "/home/", "/usr/",
	}
	for _, pattern := range leakPatterns {
		if strings.Contains(lower, pattern) {
			t.Errorf("response body must not contain internal error detail %q, got: %s", pattern, body)
		}
	}
}
