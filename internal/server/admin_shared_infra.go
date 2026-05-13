package server

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
)

// shared_infrastructure admin API (KD-1, follow-up to M5 / RD-915).
//
// shared_infrastructure is a small whitelist of contracts the runtime
// trace validator skips when validating cross-org calls — Uniswap V3
// Router, Multicall3, ENS resolver, CREATE3 factory etc. The trust
// promise is "this address is public infrastructure callable by every
// org". M5 added the optional `codehash` column so the validator can
// reject the skip if the bytecode at the address drifts from what the
// operator attested.
//
// The table has no `org_id` column — entries are global. Mutating it
// changes policy for every tenant in the cluster. The admin surface
// is therefore **super-admin only** (X-Admin-Token); JWT org admins,
// even tier-2 with full admin rights in their org, cannot touch it.
// Same scoping rationale as Azure tenant CRUD (audit C4) and the
// base-currency switch (audit C5).
//
// Endpoints:
//
//   GET    /api/v1/admin/shared-infrastructure
//   POST   /api/v1/admin/shared-infrastructure
//   GET    /api/v1/admin/shared-infrastructure/:address
//   PUT    /api/v1/admin/shared-infrastructure/:address
//   DELETE /api/v1/admin/shared-infrastructure/:address
//   POST   /api/v1/admin/shared-infrastructure/:address/refresh-codehash
//
// Refresh-codehash is the operationally common case: a tracked
// upstream contract (e.g. Uniswap V3 Router) was upgraded, its
// bytecode rotated, the trace validator now denies every call to it.
// Operator hits refresh-codehash → handler fetches eth_getCode at
// "latest", computes keccak256, stores in the row's codehash column.
// Subsequent traces match and the skip resumes.
//
// Every mutation records an audit-log entry via
// recordAuditAction(ResourceTypeSharedInfra, ...) — operators can
// trace who added / rotated / removed which entry via the standard
// /admin/audit-logs endpoint.

// registerSharedInfraRoutes mounts the shared_infrastructure admin
// routes under the given admin router group. Called from
// registerRBACRoutes.
func (s *Server) registerSharedInfraRoutes(api *gin.RouterGroup) {
	api.GET("/shared-infrastructure", s.listSharedInfrastructure)
	api.POST("/shared-infrastructure", s.createSharedInfrastructure)
	api.GET("/shared-infrastructure/:address", s.getSharedInfrastructure)
	api.PUT("/shared-infrastructure/:address", s.updateSharedInfrastructure)
	api.DELETE("/shared-infrastructure/:address", s.deleteSharedInfrastructure)
	api.POST("/shared-infrastructure/:address/refresh-codehash", s.refreshSharedInfraCodehash)
}

// sharedInfraInput is the request body for create and update. Address
// on create comes from the body; on update it comes from the path and
// the body field is ignored.
type sharedInfraInput struct {
	Address     string  `json:"address"`
	Name        string  `json:"name" binding:"required"`
	Description string  `json:"description"`
	// Codehash is optional. Empty / omitted = no codehash pin
	// (legacy behaviour: trust by address alone). When supplied it
	// must be a 0x-prefixed lowercase 32-byte hex string. The
	// recommended workflow is to omit on create and use the
	// /refresh-codehash endpoint immediately after, which computes
	// it server-side from the current bytecode.
	Codehash    string  `json:"codehash"`
}

// validateSharedInfraInput checks the input shape before any DB
// write. Returns the normalized lowercase address + normalized
// codehash (or empty for no-pin) on success.
//
// Defense-in-depth: lowercase + format validation before write
// matches the read path's case-insensitive lookup; an operator
// passing a checksummed address gets the lowercase row.
func validateSharedInfraInput(addr, codehash string) (string, string, error) {
	addr = strings.TrimSpace(addr)
	if !auth.IsValidAddress(addr) {
		return "", "", errors.New("address must be a valid 0x-prefixed 20-byte hex address")
	}
	addr = strings.ToLower(addr)

	codehash = strings.TrimSpace(codehash)
	if codehash != "" {
		if !isValidHash32(codehash) {
			return "", "", errors.New("codehash must be a 0x-prefixed 32-byte hex string (or omitted)")
		}
		codehash = strings.ToLower(codehash)
	}
	return addr, codehash, nil
}

// isValidHash32 checks for a 0x-prefixed 32-byte (64 hex char) hash.
// Mirrors auth.IsValidAddress but at the keccak256 length. Used by
// the shared_infrastructure admin API for the codehash field.
func isValidHash32(h string) bool {
	if !strings.HasPrefix(h, "0x") && !strings.HasPrefix(h, "0X") {
		return false
	}
	hex := h[2:]
	if len(hex) != 64 {
		return false
	}
	for _, c := range hex {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func (s *Server) listSharedInfrastructure(c *gin.Context) {
	// Read is super-admin only too — the list itself reveals the
	// operator's trust topology (which DEXes, factories, etc. are
	// whitelisted), and JWT org admins have no legitimate need for
	// it. Same shape as listAzureTenants post-C4 fix.
	if !requireSuperAdmin(c) {
		return
	}
	rows, err := s.db.ListSharedInfrastructure(c.Request.Context())
	if err != nil {
		slog.Error("list shared_infrastructure: db read failed", "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list shared_infrastructure"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

func (s *Server) getSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}
	row, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("get shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read"})
		return
	}
	if row == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, row)
}

func (s *Server) createSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	var input sharedInfraInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	addr, codehash, vErr := validateSharedInfraInput(input.Address, input.Codehash)
	if vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": vErr.Error()})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	// Reject duplicate up front (the table has no unique constraint
	// on address today, but inserting two rows for the same address
	// is meaningless — they'd both be checked, and the first one
	// found wins — silently shadowing the second).
	existing, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("create shared_infrastructure: dedup read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create"})
		return
	}
	if existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "address already registered as shared_infrastructure; use PUT to update"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     addr,
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
	}
	if codehash != "" {
		ch := codehash
		row.Codehash = &ch
	}
	if err := s.db.CreateSharedInfrastructure(c.Request.Context(), row); err != nil {
		// Race window between the dedup-check above and this INSERT
		// is closed by the UNIQUE constraint on
		// shared_infrastructure.address (migration 054). Postgres
		// raises a unique-violation error here — translate to 409.
		// The plain-text marker is robust across pgx and lib/pq.
		if strings.Contains(strings.ToLower(err.Error()), "unique") ||
			strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			c.JSON(http.StatusConflict, gin.H{"error": "address already registered as shared_infrastructure; use PUT to update"})
			return
		}
		slog.Error("create shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create"})
		return
	}

	// Audit-log the mutation. ResourceID = address (canonical key for
	// this table); resource name = the human-readable Name field so
	// listAuditLogs renders something useful.
	s.recordAuditAction(c, rbac.AuditActionCreate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		nil,
		map[string]any{
			"address":     row.Address,
			"name":        row.Name,
			"description": row.Description,
			"codehash":    codehashForLog(row.Codehash),
		})

	c.JSON(http.StatusCreated, row)
}

func (s *Server) updateSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	var input sharedInfraInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	if strings.TrimSpace(input.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	// Codehash field, if present, must be a valid 32-byte hash.
	// Empty/omitted is allowed (clears the pin).
	_, codehash, vErr := validateSharedInfraInput(addr, input.Codehash)
	if vErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": vErr.Error()})
		return
	}

	// Load current state for the audit log before-image and to
	// confirm the row exists (404 if not).
	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("update shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     addr,
		Name:        strings.TrimSpace(input.Name),
		Description: strings.TrimSpace(input.Description),
	}
	if codehash != "" {
		ch := codehash
		row.Codehash = &ch
	}
	if err := s.db.UpdateSharedInfrastructure(c.Request.Context(), row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("update shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		map[string]any{
			"name":        before.Name,
			"description": before.Description,
			"codehash":    codehashForLog(before.Codehash),
		},
		map[string]any{
			"name":        row.Name,
			"description": row.Description,
			"codehash":    codehashForLog(row.Codehash),
		})

	c.JSON(http.StatusOK, row)
}

func (s *Server) deleteSharedInfrastructure(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("delete shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	if err := s.db.DeleteSharedInfrastructure(c.Request.Context(), addr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("delete shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionDelete, rbac.ResourceTypeSharedInfra, before.Address, before.Name,
		map[string]any{
			"name":        before.Name,
			"description": before.Description,
			"codehash":    codehashForLog(before.Codehash),
		},
		nil)

	c.JSON(http.StatusOK, gin.H{"message": "shared_infrastructure entry deleted"})
}

// refreshSharedInfraCodehash fetches eth_getCode at the address and
// writes its keccak256 into the row's codehash column. The common
// operational case: a tracked upstream contract was legitimately
// upgraded, its bytecode rotated, and the trace validator now denies
// every call to it. After the operator verifies (out of band) that
// the new bytecode is what they expect, this endpoint re-attests so
// the validator skip resumes.
//
// Race window: between the eth_getCode here and a subsequent trace
// validation read, a malicious actor could theoretically rotate the
// implementation slot back and forth. Mitigation: the operator's
// out-of-band verification + the fact that this is super-admin only.
// For high-assurance attestation flows the operator should compute
// the hash locally and PUT it explicitly rather than trust this
// endpoint.
func (s *Server) refreshSharedInfraCodehash(c *gin.Context) {
	if !requireSuperAdmin(c) {
		return
	}
	if s.runtimeTracer == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "runtime tracer not configured; refresh-codehash unavailable"})
		return
	}

	addr := strings.ToLower(strings.TrimSpace(c.Param("address")))
	if !auth.IsValidAddress(addr) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid address"})
		return
	}

	before, err := s.db.GetSharedInfrastructure(c.Request.Context(), addr)
	if err != nil {
		slog.Error("refresh shared_infrastructure: db read failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh"})
		return
	}
	if before == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}

	newHash, err := s.runtimeTracer.GetCodeHash(c.Request.Context(), addr)
	if err != nil {
		slog.Error("refresh shared_infrastructure: code-hash fetch failed", "addr", addr, "err", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "failed to fetch current bytecode hash from upstream node"})
		return
	}
	newHash = strings.ToLower(newHash)
	if !isValidHash32(newHash) {
		slog.Error("refresh shared_infrastructure: upstream returned invalid hash", "addr", addr, "hash", newHash)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream returned invalid bytecode hash"})
		return
	}

	row := &rbac.SharedInfrastructure{
		Address:     before.Address,
		Name:        before.Name,
		Description: before.Description,
		Codehash:    &newHash,
	}
	if err := s.db.UpdateSharedInfrastructure(c.Request.Context(), row); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		slog.Error("refresh shared_infrastructure: db write failed", "addr", addr, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh"})
		return
	}

	s.recordAuditAction(c, rbac.AuditActionUpdate, rbac.ResourceTypeSharedInfra, row.Address, row.Name,
		map[string]any{
			"codehash":     codehashForLog(before.Codehash),
			"refresh_kind": "refresh-codehash",
		},
		map[string]any{
			"codehash":     newHash,
			"refresh_kind": "refresh-codehash",
		})

	c.JSON(http.StatusOK, row)
}

// codehashForLog renders a *string codehash field for inclusion in
// the audit log payload. Empty pointer → empty string.
func codehashForLog(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
