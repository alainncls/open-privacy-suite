package server

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"sync"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// TTL constants for Azure AD state tokens.
const (
	AzureStateTTL             = 10 * time.Minute
	AzureStateCleanupInterval = 1 * time.Minute
)

// azureStateEntry stores the nonce alongside a CSRF state token.
type azureStateEntry struct {
	nonce     string
	createdAt time.Time
}

// AzureStateStore is a thread-safe, TTL-expiring CSRF state store for Azure AD logins.
// Each state token is single-use: Consume removes it from the store.
type AzureStateStore struct {
	mu      sync.Mutex
	entries map[string]*azureStateEntry
	ttl     time.Duration
	stop    chan struct{}
}

// NewAzureStateStore creates a store with a background TTL cleanup goroutine.
func NewAzureStateStore(ttl, cleanupInterval time.Duration) *AzureStateStore {
	s := &AzureStateStore{
		entries: make(map[string]*azureStateEntry),
		ttl:     ttl,
		stop:    make(chan struct{}),
	}
	go s.cleanupLoop(cleanupInterval)
	return s
}

// Create generates a cryptographically random (state, nonce) pair and stores them.
func (s *AzureStateStore) Create() (state, nonce string) {
	state = randomToken(16)
	nonce = randomToken(16)
	s.mu.Lock()
	s.entries[state] = &azureStateEntry{nonce: nonce, createdAt: time.Now()}
	s.mu.Unlock()
	return state, nonce
}

// Consume validates a state token and returns its associated nonce.
// The entry is removed on success (single-use). Returns ok=false if missing or expired.
func (s *AzureStateStore) Consume(state string) (nonce string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, exists := s.entries[state]
	if !exists {
		return "", false
	}
	if time.Since(entry.createdAt) > s.ttl {
		delete(s.entries, state)
		return "", false
	}
	nonce = entry.nonce
	delete(s.entries, state)
	return nonce, true
}

// Stop terminates the background cleanup goroutine.
func (s *AzureStateStore) Stop() {
	close(s.stop)
}

func (s *AzureStateStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.cleanup()
		case <-s.stop:
			return
		}
	}
}

func (s *AzureStateStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for state, entry := range s.entries {
		if now.Sub(entry.createdAt) > s.ttl {
			delete(s.entries, state)
		}
	}
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// --- Handlers ---

// AzureURLResponse is the response from GET /api/v1/auth/azure/url.
type AzureURLResponse struct {
	URL   string `json:"url"`
	State string `json:"state"`
}

// AzureCallbackRequest is the body for POST /api/v1/auth/azure/callback.
type AzureCallbackRequest struct {
	Code        string `json:"code" binding:"required"`
	State       string `json:"state" binding:"required"`
	RedirectURI string `json:"redirect_uri" binding:"required"`
}

// ProvidersResponse is the response from GET /api/v1/auth/providers.
type ProvidersResponse struct {
	Providers []string `json:"providers"`
}

// handleAzureAuthURL handles GET /api/v1/auth/azure/url.
// Returns the Microsoft authorization URL and a CSRF state token.
func (s *Server) handleAzureAuthURL(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	redirectURI := c.Query("redirect_uri")
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri query parameter required"})
		return
	}

	if !s.isValidRedirectURI(redirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is not allowed"})
		return
	}

	state, nonce := s.azureStateStore.Create()
	url := s.azureAuthenticator.GetAuthorizationURL(redirectURI, state, nonce)
	c.JSON(http.StatusOK, AzureURLResponse{URL: url, State: state})
}

// handleAzureCallback handles POST /api/v1/auth/azure/callback.
// Validates CSRF state, exchanges the authorization code, and issues our JWT tokens.
func (s *Server) handleAzureCallback(c *gin.Context) {
	if s.azureAuthenticator == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Azure AD authentication not configured"})
		return
	}

	var req AzureCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
		return
	}

	// Validate redirect_uri against allowlist
	if !s.isValidRedirectURI(req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "redirect_uri is not allowed"})
		return
	}

	// Validate CSRF state — single-use, TTL-enforced
	nonce, ok := s.azureStateStore.Consume(req.State)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid or expired state token"})
		return
	}

	// Exchange authorization code for verified Azure identity
	identity, err := s.azureAuthenticator.ExchangeCode(c.Request.Context(), req.Code, req.RedirectURI, nonce)
	if err != nil {
		log.Printf("Azure AD code exchange failed: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Azure AD authentication failed"})
		return
	}

	// Validate tid is a valid UUID before using it for lookups
	if _, parseErr := uuid.Parse(identity.TenantID); parseErr != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid tenant ID in token"})
		return
	}

	// --- Tenant allowlist gate ---
	// Check if the user's Azure AD tenant is in the allowlist.
	tenantConfig, err := s.db.GetAllowedAzureTenantByTenantID(c.Request.Context(), identity.TenantID)
	if err != nil {
		log.Printf("Error checking Azure tenant allowlist for tid=%s: %v", identity.TenantID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check tenant authorization"})
		return
	}
	if tenantConfig == nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "your Azure AD tenant is not authorized"})
		return
	}

	subject := auth.AzureSubject(identity.OID)

	// Ensure user exists in RBAC system and retrieve their KYC status
	kyc := false
	if s.rbacAccessCtrl != nil {
		if !tenantConfig.AutoProvision {
			// Auto-provision disabled: only allow login if user already exists
			existing, getErr := s.db.GetUserByExternalID(c.Request.Context(), subject)
			if getErr != nil {
				log.Printf("Warning: failed to check user existence for %s: %v", subject, getErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check user status"})
				return
			}
			if existing == nil {
				c.JSON(http.StatusForbidden, gin.H{"error": "auto-provisioning is disabled for your tenant and no existing account was found"})
				return
			}
			if existing.Banned {
				c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
				return
			}
			kyc = existing.KYC
			// Pin auth_tenant_id if not yet set (immutable after first write).
			if existing.AuthTenantID == nil {
				if _, err := s.db.SetAuthTenantID(c.Request.Context(), existing.ID, identity.TenantID); err != nil {
					log.Printf("Warning: failed to set auth_tenant_id for user %s: %v", subject, err)
				}
				existing.AuthTenantID = &identity.TenantID
			} else if *existing.AuthTenantID != identity.TenantID {
				log.Printf("Warning: user %s has auth_tenant_id=%s but logged in from tenant %s", subject, *existing.AuthTenantID, identity.TenantID)
				c.JSON(http.StatusForbidden, gin.H{"error": "account is associated with a different Azure AD tenant"})
				return
			}
		} else {
			// Skip default group if tenant configures a specific group — user will be added there instead
			skipDefaultGroup := tenantConfig.DefaultOrgID != nil && tenantConfig.DefaultGroupID != nil
			user, ensureErr := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), subject, kyc, skipDefaultGroup)
			if ensureErr != nil {
				log.Printf("Error: failed to ensure RBAC user for %s: %v", subject, ensureErr)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to provision user account"})
				return
			}
			if user != nil {
				if user.Banned {
					c.JSON(http.StatusForbidden, gin.H{"error": "account is banned"})
					return
				}
				kyc = user.KYC

				// Pin auth_tenant_id if not yet set (immutable after first write).
				if user.AuthTenantID == nil {
					if _, err := s.db.SetAuthTenantID(c.Request.Context(), user.ID, identity.TenantID); err != nil {
						log.Printf("Warning: failed to set auth_tenant_id for user %s: %v", subject, err)
					}
					user.AuthTenantID = &identity.TenantID
				} else if *user.AuthTenantID != identity.TenantID {
					log.Printf("Warning: user %s has auth_tenant_id=%s but logged in from tenant %s", subject, *user.AuthTenantID, identity.TenantID)
					c.JSON(http.StatusForbidden, gin.H{"error": "account is associated with a different Azure AD tenant"})
					return
				}

				// Auto-add user to tenant's configured group (idempotent — safe against concurrent logins)
				if tenantConfig.DefaultOrgID != nil && tenantConfig.DefaultGroupID != nil {
					membership := &rbac.UserMembership{
						ID:      uuid.New().String(),
						UserID:  user.ID,
						GroupID: *tenantConfig.DefaultGroupID,
						Source:  "auto_provision",
					}
					created, createErr := s.db.CreateMembershipIfNotExists(c.Request.Context(), membership)
					if createErr != nil {
						// Tenant group assignment failed — fall back to default group so user isn't orphaned
						log.Printf("Warning: failed to auto-add user %s to tenant group %s, falling back to default group: %v", subject, *tenantConfig.DefaultGroupID, createErr)
						fallback := &rbac.UserMembership{
							ID:      uuid.New().String(),
							UserID:  user.ID,
							GroupID: rbac.DefaultGroupID,
							Source:  "auto_provision",
						}
						if _, fbErr := s.db.CreateMembershipIfNotExists(c.Request.Context(), fallback); fbErr != nil {
							log.Printf("Warning: fallback to default group also failed for user %s: %v", subject, fbErr)
						}
					} else if created {
						log.Printf("Auto-provisioned membership for user %s in group %s", subject, *tenantConfig.DefaultGroupID)
					}
				}
			}
		}
	}

	// Issue access token (short-lived)
	accessToken, err := s.jwtService.IssueAccessToken(subject, kyc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue access token: " + err.Error()})
		return
	}

	// Issue refresh token (long-lived)
	refreshToken, err := s.jwtService.IssueRefreshToken(subject)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue refresh token: " + err.Error()})
		return
	}

	// Persist refresh token
	tokenHash := auth.HashToken(refreshToken)
	expiresAt := time.Now().Add(RefreshTokenTTL)
	if err := s.db.SaveRefreshToken(c.Request.Context(), tokenHash, subject, expiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save refresh token: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(AccessTokenTTL.Seconds()),
	})
}

// handleAuthProviders handles GET /api/v1/auth/providers.
// Returns the list of configured authentication provider identifiers.
func (s *Server) handleAuthProviders(c *gin.Context) {
	providers := []string{"privado"}
	if s.azureAuthenticator != nil {
		providers = append(providers, "azuread")
	}
	c.JSON(http.StatusOK, ProvidersResponse{Providers: providers})
}
