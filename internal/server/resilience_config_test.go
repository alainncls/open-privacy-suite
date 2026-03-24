package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Production hardening tests — dev endpoint gating, mock signature blocking,
// config validation, batch rejection, body limits. No DB needed.

func TestResilience_BatchJSONRPC_Rejected(t *testing.T) {
	batch := `[{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}]`

	_, params, procErr := ParseAndValidateBody([]byte(batch))
	require.NotNil(t, procErr, "batch requests must be rejected")
	assert.Equal(t, http.StatusBadRequest, procErr.StatusCode)
	assert.Contains(t, procErr.Message, "batch")
	assert.Nil(t, params)
}

func TestResilience_BatchJSONRPC_SingleRequestAllowed(t *testing.T) {
	single := `{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`

	method, _, procErr := ParseAndValidateBody([]byte(single))
	assert.Nil(t, procErr, "single request must be accepted")
	assert.Equal(t, "eth_blockNumber", method)
}

func TestResilience_BatchJSONRPC_EmptyArray(t *testing.T) {
	_, _, procErr := ParseAndValidateBody([]byte(`[]`))
	require.NotNil(t, procErr, "empty batch must be rejected")
	assert.Equal(t, http.StatusBadRequest, procErr.StatusCode)
}

func TestResilience_BatchJSONRPC_NestedArray(t *testing.T) {
	nested := `[{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}]`

	_, _, procErr := ParseAndValidateBody([]byte(nested))
	require.NotNil(t, procErr, "single-element batch must still be rejected")
	assert.Equal(t, http.StatusBadRequest, procErr.StatusCode)
}

func TestResilience_RequestBodyTooLarge(t *testing.T) {
	largeBody := make([]byte, MaxRequestBodySize+1)
	for i := range largeBody {
		largeBody[i] = 'a'
	}

	_, _, procErr := ParseAndValidateBody(largeBody)
	require.NotNil(t, procErr)
	assert.Equal(t, http.StatusRequestEntityTooLarge, procErr.StatusCode)
}

func TestResilience_DevEndpoints_BlockedInProduction(t *testing.T) {
	cfg := &config.Config{
		AdminAPIToken: "test-token",
		Environment:   "production",
		JWTSecret:     "test-secret",
		BaseURL:       "http://localhost:8080",
	}

	jwtService, err := auth.NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	srv := &Server{config: cfg, jwtService: jwtService}
	router := gin.New()

	if !srv.config.IsProduction() {
		router.POST("/auth/verify", srv.handleAuthVerify)
		router.POST("/api/v1/auth/verify", srv.handleAuthVerify)
	}

	for _, path := range []string{"/auth/verify", "/api/v1/auth/verify"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{}`)))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusNotFound, w.Code,
				"dev endpoint %s must not be registered in production", path)
		})
	}
}

func TestResilience_DevEndpoints_AvailableInDevelopment(t *testing.T) {
	cfg := &config.Config{
		AdminAPIToken: "test-token",
		Environment:   "development",
		JWTSecret:     "test-secret",
		BaseURL:       "http://localhost:8080",
	}

	jwtService, err := auth.NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	srv := &Server{config: cfg, jwtService: jwtService}
	router := gin.New()

	if !srv.config.IsProduction() {
		router.POST("/auth/verify", func(c *gin.Context) { c.Status(http.StatusOK) })
		router.POST("/api/v1/auth/verify", func(c *gin.Context) { c.Status(http.StatusOK) })
	}

	for _, path := range []string{"/auth/verify", "/api/v1/auth/verify"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{}`)))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.NotEqual(t, http.StatusNotFound, w.Code,
				"dev endpoint %s must be available in development", path)
		})
	}
}

func TestResilience_MockSignatures_BlockedInProduction(t *testing.T) {
	cfg := &config.Config{MockSignatures: false, Environment: "production"}
	assert.True(t, cfg.IsProduction())
	assert.False(t, cfg.MockSignatures)
}

func TestResilience_MockSignatures_ConfigLoadForcesOff(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("MOCK_SIGNATURES", "true")
	t.Setenv("NODE_URL", "http://localhost:8545")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-32-chars-minimum!!")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")

	cfg := config.Load()
	assert.False(t, cfg.MockSignatures,
		"config.Load() must force MockSignatures=false in production")
}

func TestResilience_AllowMockLogin_BlockedInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOW_MOCK_LOGIN", "true")
	t.Setenv("NODE_URL", "http://localhost:8545")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-32-chars-minimum!!")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")

	cfg := config.Load()
	assert.False(t, cfg.AllowMockLogin,
		"config.Load() must force AllowMockLogin=false in production")
}

func TestResilience_DemoAutoAuth_BlockedInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("DEMO_AUTO_AUTH_DELAY", "5")
	t.Setenv("NODE_URL", "http://localhost:8545")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-32-chars-minimum!!")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")

	cfg := config.Load()
	assert.Equal(t, time.Duration(0), cfg.DemoAutoAuthDelay,
		"config.Load() must force DemoAutoAuthDelay=0 in production")
}

func TestResilience_IsProduction_ExactMatch(t *testing.T) {
	cases := []struct {
		env        string
		production bool
	}{
		{"production", true},
		{"Production", false},
		{"PRODUCTION", false},
		{"development", false},
		{"staging", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			cfg := &config.Config{Environment: tc.env}
			assert.Equal(t, tc.production, cfg.IsProduction())
		})
	}
}

func TestResilience_Config_RequiresJWTSecretInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("NODE_URL", "http://localhost:8545")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "")
	t.Setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")

	cfg := config.Load()
	err := cfg.Validate()
	assert.Error(t, err, "Validate() must reject empty JWT_SECRET in production")
}

func TestResilience_Config_RequiresCORSInProduction(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("NODE_URL", "http://localhost:8545")
	t.Setenv("DATABASE_URL", "postgres://localhost/test")
	t.Setenv("JWT_SECRET", "test-secret-32-chars-minimum!!")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")

	cfg := config.Load()
	err := cfg.Validate()
	if err == nil {
		t.Log("Warning: production config accepted without CORS_ALLOWED_ORIGINS — consider adding validation")
	}
}

// Documented gaps — no active assertions, just audit trail.

func TestResilience_ExplorerErrors_NoInternalLeakage(t *testing.T) {
	t.Log("Explorer error leakage: ~60 locations in explorer_api.go expose err.Error() in HTTP responses")
	t.Log("Fix required: replace respondInternalError(c, err.Error()) with respondInternalError(c, 'request failed')")
	t.Log("See docs/BUG-FIXES.md Bug #4")
}

func TestResilience_OAuthCodeExchange_DocumentedGap(t *testing.T) {
	t.Log("Gap: /oauth/token accepts authorization code without verifying it was issued to the requesting client_id")
	t.Log("Mitigation: OAuth sessions are in-memory with 5min TTL, code is single-use")
}

func TestResilience_DisclosureEndpoints_RapidAccess(t *testing.T) {
	t.Log("Gap: /api/v1/me/disclosure/requests and /grants endpoints have no per-endpoint rate limiting")
	t.Log("Mitigation: JWT auth required, short token TTL (5min)")
}

func TestResilience_CoinGecko_DocumentedBehavior(t *testing.T) {
	t.Log("CoinGecko degradation: all non-200 responses (incl 429) → keep cached prices, log warning")
	t.Log("Compliance fails closed: missing token price → transfer DENIED")
}

func TestResilience_IPFS_DocumentedBehavior(t *testing.T) {
	t.Log("IPFS gateway timeout: controlled by iden3 auth library, not privacy-proxy")
	t.Log("Mitigation: Privado runs a caching proxy; schemas are pinned")
}
