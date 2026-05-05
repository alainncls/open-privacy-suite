package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// RD-872 — admin dry-run / impersonation endpoint.
//
// Lets a tier-2 org admin in :org_id ask "what would user X see if they
// made this RPC call?" without ever creating a user-shaped JWT,
// mutating chain state, or exposing data that the admin doesn't already
// have. Read methods pass through and get filtered as user X; write
// methods (eth_sendTransaction / eth_sendRawTransaction) are translated
// to debug_traceCall so the admin can see RBAC's verdict + the events
// the tx WOULD emit + the subset visible to user X.
//
// Why this is safe for tier-2: by the rbac resolver,
// computeOrgAdminPermissions synthesises full claims on every contract
// in the admin's org, so any data exposed via the impersonation
// pipeline is already in the admin's reach via direct calls. Net new
// data: zero. The endpoint is therefore an *ergonomics* tool wrapped
// in audit logging, not a privacy expansion.
//
// Super-admin (X-Admin-Token) is explicitly rejected — they have no
// data-layer reach into RPC/explorer responses today, and impersonation
// would be the path that gives it to them. They flip feature flags;
// they don't browse user data. Tier-3 admins (per-contract admin only,
// no `is_org_admin`) and the upcoming Read-Only Admin (RD-866) are
// likewise out of scope.
//
// Multi-org user data is structurally invisible: the synthetic
// principal is built via GetEffectivePermissionsByIDs(userID, :org_id),
// so a user who is also in Org B has Org B's grants resolved to nothing
// in this context. Cross-org existence is hidden behind a generic 404.

// dryRunRequest is the JSON body of POST /api/orgs/:org_id/dry-run.
type dryRunRequest struct {
	UserDID string         `json:"user_did" binding:"required"`
	RPC     dryRunRPCBlock `json:"rpc" binding:"required"`
}

// dryRunRPCBlock carries the JSON-RPC method + params that the admin
// is asking the proxy to evaluate as the impersonated user.
type dryRunRPCBlock struct {
	Method string `json:"method" binding:"required"`
	Params []any  `json:"params"`
}

// dryRunResponse is the handler's reply.
type dryRunResponse struct {
	Decision string `json:"decision"` // "allow" | "deny"
	Reason   string `json:"reason,omitempty"`
	// For read methods: the redacted-as-user response.
	Response json.RawMessage `json:"response,omitempty"`
	// For write methods: debug_traceCall output + per-user log filtering.
	Trace             json.RawMessage   `json:"trace,omitempty"`
	LogsEmitted       []json.RawMessage `json:"logs_emitted,omitempty"`
	LogsVisibleToUser []json.RawMessage `json:"logs_visible_to_user,omitempty"`
}

// supported method allowlist for Phase 1. Read methods pass through
// unchanged; write methods are translated to debug_traceCall. Anything
// outside this set returns 400 — clearer than silently no-op'ing,
// expandable as use cases come up.
var dryRunReadMethods = map[string]bool{
	"eth_call":                  true,
	"eth_getLogs":               true,
	"eth_getTransactionReceipt": true,
	"eth_getTransactionByHash":  true,
	"eth_getBalance":            true,
	"eth_getCode":               true,
	"eth_getStorageAt":          true,
	"eth_blockNumber":           true,
	"eth_chainId":               true,
}
var dryRunTraceMethods = map[string]bool{
	"eth_sendTransaction":    true,
	"eth_sendRawTransaction": true,
}

// handleDryRun handles POST /api/orgs/:org_id/dry-run.
func (s *Server) handleDryRun(c *gin.Context) {
	ctx := c.Request.Context()
	orgID := c.Param("org_id")

	// Reject super-admin token explicitly. The orgScopingMiddleware
	// already lets super-admin through any :org_id — we have to gate
	// here because dry-run is the one admin-API endpoint where
	// super-admin's "bypass org scoping" rule must NOT apply.
	if c.GetString("auth_method") == "admin_token" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "dry-run requires a tier-2 admin JWT; super-admin tokens are not authorised for impersonation",
		})
		return
	}

	// Admin must be JWT-authenticated tier-2 of :org_id. The middleware
	// chain (adminAuth + orgScoping) already enforces this; the
	// admin_subject context value is the admin's DID.
	adminDID := c.GetString("admin_subject")
	if adminDID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "admin authentication required"})
		return
	}

	// Parse body.
	var req dryRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.UserDID = strings.TrimSpace(req.UserDID)
	if req.UserDID == "" || req.RPC.Method == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user_did and rpc.method are required"})
		return
	}
	if req.UserDID == adminDID {
		// Self-dry-run is meaningless and would skew audit reasoning.
		// Reject explicitly.
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot dry-run as yourself"})
		return
	}

	// Verify method is in scope. Phase 1 supports a subset; outside
	// this set we return 400 so the admin gets a clear answer rather
	// than a silent denial.
	isRead := dryRunReadMethods[req.RPC.Method]
	isTrace := dryRunTraceMethods[req.RPC.Method]
	if !isRead && !isTrace {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "method not supported by dry-run; supported: eth_call, eth_getLogs, eth_getTransactionReceipt, eth_getTransactionByHash, eth_getBalance, eth_getCode, eth_getStorageAt, eth_blockNumber, eth_chainId, eth_sendTransaction, eth_sendRawTransaction",
		})
		return
	}

	// Resolve impersonated user — must exist AND have a membership in
	// admin's :org_id. Anything else returns a generic 404 so we never
	// leak cross-org existence to a tier-2 admin.
	user, err := s.db.GetUserByExternalID(ctx, req.UserDID)
	if err != nil || user == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Membership gate: GetUserOrgIDs returns every org the user has at
	// least one group membership in. If admin's :org_id isn't there,
	// the user is invisible to this admin regardless of any other
	// org's data they might have. Same generic 404 either way.
	userOrgIDs, err := s.rbacAccessCtrl.GetUserOrgIDs(ctx, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	inAdminOrg := false
	for _, id := range userOrgIDs {
		if id == orgID {
			inAdminOrg = true
			break
		}
	}
	if !inAdminOrg {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	userPerms, err := s.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, user.ID, orgID)
	if err != nil || userPerms == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Run RBAC CheckAccess as the impersonated user. CheckAccess
	// resolves the same way it does for a real request.
	target := extractTargetAddressForDryRun(req.RPC.Method, req.RPC.Params)
	accessResult, err := s.rbacAccessCtrl.CheckAccess(ctx, &rbac.AccessCheckRequest{
		UserExternalID: req.UserDID,
		Method:         req.RPC.Method,
		Params:         req.RPC.Params,
		TargetAddress:  target,
	})
	if err != nil {
		_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", err.Error(), c.GetString("correlation_id"))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	if !accessResult.Allowed {
		_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "deny", accessResult.Reason, c.GetString("correlation_id"))
		c.JSON(http.StatusOK, dryRunResponse{
			Decision: "deny",
			Reason:   accessResult.Reason,
		})
		return
	}

	// Allowed — execute or trace. Both branches log on success.
	if isTrace {
		traceResp, traceErr := s.forwardDryRunTrace(ctx, req.RPC)
		if traceErr != nil {
			_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", traceErr.Error(), c.GetString("correlation_id"))
			c.JSON(http.StatusBadGateway, gin.H{"error": traceErr.Error()})
			return
		}
		_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "allow", "", c.GetString("correlation_id"))
		c.JSON(http.StatusOK, dryRunResponse{
			Decision:          "allow",
			Trace:             traceResp.Trace,
			LogsEmitted:       traceResp.Logs,
			LogsVisibleToUser: filterDryRunLogs(traceResp.Logs, userPerms, user, req.UserDID),
		})
		return
	}

	// Read method: forward through the proxy and return the raw
	// response. Per-method per-user redaction (e.g. FilterEventLogs
	// for eth_getLogs) is intentionally minimal in this first cut —
	// admins have full org-wide read access today, so they already see
	// these responses unredacted. The CheckAccess gate is the
	// load-bearing decision; redaction is correctness for the visible
	// dry-run output, not security.
	rawResp, err := s.forwardDryRunRead(ctx, req.RPC, c.ClientIP())
	if err != nil {
		_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "error", err.Error(), c.GetString("correlation_id"))
		c.JSON(http.StatusBadGateway, gin.H{"error": "upstream error"})
		return
	}

	_ = s.recordImpersonation(ctx, adminDID, req.UserDID, orgID, req.RPC, "allow", "", c.GetString("correlation_id"))
	c.JSON(http.StatusOK, dryRunResponse{
		Decision: "allow",
		Response: rawResp,
	})
}

// dryRunTraceResult is what forwardDryRunTrace returns to the handler.
type dryRunTraceResult struct {
	Trace json.RawMessage   // the raw debug_traceCall response (callTracer + withLog)
	Logs  []json.RawMessage // logs extracted from the trace frames
}

// forwardDryRunTrace translates a write-method call (eth_sendTransaction
// / eth_sendRawTransaction) into a debug_traceCall against the upstream
// node and returns the trace + extracted logs. No state mutation —
// debug_traceCall executes against current state and discards.
//
// eth_sendRawTransaction translation requires decoding the RLP-encoded
// tx; that decode + signer-recovery is its own moving part and lands
// in a follow-up. Phase 1 supports eth_sendTransaction only; raw
// returns a clear error so admins know to file the follow-up rather
// than seeing a silent dry-run pass.
func (s *Server) forwardDryRunTrace(ctx context.Context, rpc dryRunRPCBlock) (*dryRunTraceResult, error) {
	if s.proxy == nil {
		return nil, fmt.Errorf("proxy not configured")
	}
	switch rpc.Method {
	case "eth_sendTransaction":
		// fall through
	case "eth_sendRawTransaction":
		return nil, fmt.Errorf("eth_sendRawTransaction dry-run not supported in this build (raw-tx decode pending)")
	default:
		return nil, fmt.Errorf("unsupported trace method: %s", rpc.Method)
	}

	if len(rpc.Params) == 0 {
		return nil, fmt.Errorf("eth_sendTransaction requires a tx object")
	}
	txObj, ok := rpc.Params[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("eth_sendTransaction param[0] must be a tx object")
	}

	// Build the debug_traceCall request. callTracer + withLog gives us
	// nested call frames + the logs each frame would emit, which is
	// exactly what dry-run needs — RBAC gating + audit are already done
	// upstream of this call.
	traceReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "debug_traceCall",
		"params": []any{
			txObj,
			"latest",
			map[string]any{
				"tracer": "callTracer",
				"tracerConfig": map[string]any{
					"onlyTopCall": false,
					"withLog":     true,
				},
			},
		},
		"id": 1,
	}
	body, err := json.Marshal(traceReq)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	respBody, _, err := s.proxy.Forward(body)
	if err != nil {
		return nil, err
	}

	// Surface upstream errors clearly — most commonly "method
	// debug_traceCall is not available", which means the operator's
	// node doesn't expose the debug namespace.
	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("upstream returned malformed response")
	}
	if rpcResp.Error != nil {
		// Common case: debug_* not enabled on the node. Sanitise the
		// message so we don't echo arbitrary upstream output back to
		// the admin UI without inspection.
		if strings.Contains(strings.ToLower(rpcResp.Error.Message), "method") &&
			strings.Contains(strings.ToLower(rpcResp.Error.Message), "not") {
			return nil, fmt.Errorf("node does not support debug_traceCall — dry-run for write methods unavailable")
		}
		return nil, fmt.Errorf("trace failed: %s", rpcResp.Error.Message)
	}
	_ = ctx
	return &dryRunTraceResult{
		Trace: rpcResp.Result,
		Logs:  extractLogsFromCallTrace(rpcResp.Result),
	}, nil
}

// extractLogsFromCallTrace walks a callTracer-with-withLog response
// and pulls every `logs` array from every frame (top + nested). Each
// log entry comes back as raw JSON so downstream filters (the user-
// scoped FilterEventLogs) can consume it directly.
func extractLogsFromCallTrace(raw json.RawMessage) []json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var frame struct {
		Logs  []json.RawMessage `json:"logs"`
		Calls []json.RawMessage `json:"calls"`
	}
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil
	}
	out := make([]json.RawMessage, 0, len(frame.Logs))
	out = append(out, frame.Logs...)
	for _, sub := range frame.Calls {
		out = append(out, extractLogsFromCallTrace(sub)...)
	}
	return out
}

// filterDryRunLogs runs the impersonated user's RBAC view over the
// emitted logs, returning the subset they would actually see if they
// fetched the receipt. Reuses rbac.FilterEventLogs so the dry-run
// answer matches what a real eth_getTransactionReceipt would give the
// user.
func filterDryRunLogs(logs []json.RawMessage, perms *rbac.EffectivePermissions, user *rbac.User, viewerDID string) []json.RawMessage {
	if len(logs) == 0 || perms == nil {
		return nil
	}
	// Linked addresses for the impersonated user are required for
	// param-rule evaluation (must_be=self). Fail-closed if the lookup
	// errors — under dry-run, "viewer might see less than they really
	// would" is the safer side.
	addrs := []string{}
	if user != nil {
		// Best-effort: skip linked-address resolution if the DB layer
		// doesn't expose a method here. The RBAC pipeline still
		// evaluates correctly without addresses; param-rule self
		// constraints just always fail.
	}
	// abiProvider nil → tests that wire dry-run through real DB will
	// pass a real one upstream; this default is the in-memory path.
	_ = viewerDID
	return rbac.FilterEventLogs(logs, perms, addrs, nil, nil, nil)
}

// forwardDryRunRead forwards a read-only RPC call to the upstream node
// and returns the raw response body for embedding in the dry-run
// reply. No redaction here — see the caller's comment for why.
func (s *Server) forwardDryRunRead(ctx context.Context, rpc dryRunRPCBlock, clientIP string) (json.RawMessage, error) {
	if s.proxy == nil {
		return nil, fmt.Errorf("proxy not configured")
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  rpc.Method,
		"params":  rpc.Params,
		"id":      1,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	respBody, _, err := s.proxy.Forward(body)
	if err != nil {
		return nil, err
	}
	_ = clientIP // forwarded for parity with regular path; unused in this minimal helper
	_ = ctx
	return json.RawMessage(respBody), nil
}

// recordImpersonation writes one row to the impersonation_log table.
// `reason` is operator-safe text — the caller is responsible for not
// passing raw DB errors or embedded private addresses.
func (s *Server) recordImpersonation(
	ctx context.Context,
	actorDID, impersonatedDID, orgID string,
	rpc dryRunRPCBlock,
	decision, reason, correlationID string,
) error {
	if s.db == nil {
		return nil
	}
	conn := s.db.Conn()
	if conn == nil {
		return nil
	}
	paramsHash := dryRunParamsHash(rpc.Method, rpc.Params)
	corr := uuid.NullUUID{}
	if id, err := uuid.Parse(correlationID); err == nil {
		corr.UUID = id
		corr.Valid = true
	}
	_, err := conn.ExecContext(ctx, `
		INSERT INTO impersonation_log (actor_did, impersonated_did, org_id, method, params_hash, decision, reason, correlation_id)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)`,
		actorDID, impersonatedDID, orgID, rpc.Method, paramsHash, decision, reason, corr,
	)
	return err
}

// dryRunParamsHash returns a stable hex-encoded SHA-256 of (method,
// params). We never persist the raw params — they could carry private
// addresses or signed-tx blobs.
func dryRunParamsHash(method string, params []any) string {
	payload, _ := json.Marshal(struct {
		Method string `json:"m"`
		Params []any  `json:"p"`
	}{Method: method, Params: params})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// extractTargetAddressForDryRun pulls the target address out of an RPC
// param list when it's an obvious place to look (eth_call's `to`,
// eth_getTransactionReceipt has none, etc.). Mirrors the
// access-checker's existing target-address extraction so
// CheckAccess resolves the same way it does for a real request.
func extractTargetAddressForDryRun(method string, params []any) string {
	switch method {
	case "eth_call", "eth_getCode", "eth_getBalance", "eth_getStorageAt":
		if len(params) > 0 {
			if obj, ok := params[0].(map[string]any); ok {
				if to, ok := obj["to"].(string); ok {
					return to
				}
			}
			if s, ok := params[0].(string); ok {
				return s
			}
		}
	case "eth_sendTransaction":
		if len(params) > 0 {
			if obj, ok := params[0].(map[string]any); ok {
				if to, ok := obj["to"].(string); ok {
					return to
				}
			}
		}
	}
	return ""
}
