package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/compliance"
)

type mockAPIKeyStore struct {
	key *compliance.APIKey
	err error
}

func (m *mockAPIKeyStore) GetAPIKeyByHash(_ context.Context, _ string) (*compliance.APIKey, error) {
	return m.key, m.err
}

func (m *mockAPIKeyStore) UpdateAPIKeyLastUsed(_ context.Context, _ string) error {
	return nil
}

func setupAPIKeyRouter(store APIKeyStore, permission string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.PUT("/test", apiKeyMiddleware(store, permission), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	rawKey := "ppk_testapikey1234567890abcdef12345678"
	store := &mockAPIKeyStore{
		key: &compliance.APIKey{
			ID:          "key-1",
			Name:        "Test Key",
			Permissions: []string{"rates:write"},
		},
	}

	r := setupAPIKeyRouter(store, "rates:write")
	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyMiddleware_MissingHeader(t *testing.T) {
	store := &mockAPIKeyStore{}
	r := setupAPIKeyRouter(store, "rates:write")

	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_InvalidKeyFormat(t *testing.T) {
	store := &mockAPIKeyStore{}
	r := setupAPIKeyRouter(store, "rates:write")

	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer notppk_key")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	store := &mockAPIKeyStore{key: nil} // key not found
	r := setupAPIKeyRouter(store, "rates:write")

	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer ppk_doesnotexist")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAPIKeyMiddleware_RevokedKey(t *testing.T) {
	revokedAt := time.Now().Add(-1 * time.Hour)
	store := &mockAPIKeyStore{
		key: &compliance.APIKey{
			ID:          "key-1",
			Name:        "Revoked Key",
			Permissions: []string{"rates:write"},
			RevokedAt:   &revokedAt,
		},
	}

	r := setupAPIKeyRouter(store, "rates:write")
	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer ppk_revokedkey123456")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyMiddleware_ExpiredKey(t *testing.T) {
	expiredAt := time.Now().Add(-1 * time.Hour)
	store := &mockAPIKeyStore{
		key: &compliance.APIKey{
			ID:          "key-1",
			Name:        "Expired Key",
			Permissions: []string{"rates:write"},
			ExpiresAt:   &expiredAt,
		},
	}

	r := setupAPIKeyRouter(store, "rates:write")
	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer ppk_expiredkey123456")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyMiddleware_WrongPermission(t *testing.T) {
	store := &mockAPIKeyStore{
		key: &compliance.APIKey{
			ID:          "key-1",
			Name:        "Wrong Permission",
			Permissions: []string{"other:read"},
		},
	}

	r := setupAPIKeyRouter(store, "rates:write")
	req := httptest.NewRequest(http.MethodPut, "/test", nil)
	req.Header.Set("Authorization", "Bearer ppk_wrongperm12345678")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
