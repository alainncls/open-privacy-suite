package server

import (
	"context"
	"log/slog"

	"privacy-proxy/internal/rbac"
)

// resolvePermsForFilter lazily resolves the user's effective permissions for
// response filtering. Returns nil if the user or org is unknown.
func (p *JSONRPCProcessor) resolvePermsForFilter(ctx context.Context, result *rbac.AccessCheckResult) *rbac.EffectivePermissions {
	if result == nil || result.UserID == "" || result.OrgID == "" {
		return nil
	}

	perms, err := p.rbacAccessCtrl.GetEffectivePermissionsByIDs(ctx, result.UserID, result.OrgID)
	if err != nil {
		slog.Warn("failed to resolve permissions for event rule filtering", "error", err, "user_id", result.UserID)
		return nil
	}
	return perms
}

// contractABIProvider returns an ABIProvider backed by the RBAC store.
func (p *JSONRPCProcessor) contractABIProvider(ctx context.Context) rbac.ABIProvider {
	return newStoreABIProvider(ctx, p.rbacAccessCtrl.Store())
}
