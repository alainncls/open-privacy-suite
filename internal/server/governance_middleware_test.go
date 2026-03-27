package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/governance"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestOrgWithGovernance sets up a test organization with governance enabled.
func createTestOrgWithGovernance(t *testing.T, database *db.DB, enabled bool, threshold int) *rbac.Organization {
	org := &rbac.Organization{
		ID:        uuid.New().String(),
		Slug:      "test-gov-mid-" + uuid.New().String()[:8],
		Name:      "Test Gov Middleware Org",
		Settings:  map[string]any{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		GovernanceEnabled: enabled,
	}
	org.ApprovalThreshold = threshold

	require.NoError(t, database.CreateOrganization(context.Background(), org))
	return org
}

func setupTestServerForMiddleware(t *testing.T, srv *testServerRBAC) {
	// Initialize the engine for testing
	srv.governanceEngine = governance.NewEngine(srv.db, srv.Server, nil) // No notifier needed for middleware test
	
	userID := uuid.New().String()
	user := &rbac.User{
		ID:         userID,
		ExternalID: "admin-middleware-did",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	require.NoError(t, srv.db.CreateUser(context.Background(), user))

	// Create a dummy endpoint that uses governance middleware
	srv.router.POST("/api/orgs/:org_id/dummy-resource",
		// Mock auth middleware that injects the user ID and active org
		func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Set("admin_user_id", userID)
			c.Set("active_org_id", c.Param("org_id"))
			c.Next()
		},
		srv.governanceMiddleware("createContractGrant"),
		func(c *gin.Context) {
			// Actual logic
			c.JSON(http.StatusCreated, gin.H{"status": "created"})
		},
	)
}

func TestMiddleware_GovernanceDisabled(t *testing.T) {
	srv := setupTestServerForRBAC(t) // reuse existing DB framework
	
	org := createTestOrgWithGovernance(t, srv.db, false, 1)
	setupTestServerForMiddleware(t, srv)

	body := map[string]any{"data": "test payload"}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+org.ID+"/dummy-resource", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	// Since governance is disabled, it should pass right through to the actual logic returning 201
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestMiddleware_GovernanceEnabled(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	
	org := createTestOrgWithGovernance(t, srv.db, true, 2)
	setupTestServerForMiddleware(t, srv)

	body := map[string]any{"data": "test secure payload"}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+org.ID+"/dummy-resource", bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.router.ServeHTTP(w, req)

	// Governance is enabled, it should be intercepted!
	assert.Equal(t, http.StatusAccepted, w.Code)

	var response map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "pending", response["status"])
	assert.NotEmpty(t, response["request_id"])

	// Check DB if it was really stored
	ctx := context.Background()
	dbReq, err := srv.db.GetApprovalRequest(ctx, response["request_id"].(string))
	require.NoError(t, err)
	assert.Equal(t, org.ID, dbReq.OrgID)
	assert.Equal(t, "createContractGrant", dbReq.ChangeType)
	assert.Equal(t, rbac.StatusPending, dbReq.Status)
	assert.Equal(t, 2, dbReq.ApprovalsNeeded)
}
