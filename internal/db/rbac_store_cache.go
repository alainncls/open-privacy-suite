package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Effective Permissions Cache operations

func (d *DB) GetCachedPermissions(ctx context.Context, userID, orgID string) (*rbac.EffectivePermissions, error) {
	query := `SELECT id, user_id, org_id, allowed_methods, contract_access, claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at
	          FROM effective_permissions_cache WHERE user_id = $1 AND org_id = $2 AND expires_at > $3`

	perms := &rbac.EffectivePermissions{}
	var allowedMethods, claimsArr pq.StringArray
	var contractAccess []byte
	var rateLimitRPS, rateLimitDaily sql.NullInt32

	err := d.conn.QueryRowContext(ctx, query, userID, orgID, time.Now()).Scan(
		&perms.ID, &perms.UserID, &perms.OrgID,
		&allowedMethods, &contractAccess, &claimsArr,
		&rateLimitRPS, &rateLimitDaily, &perms.ComputedAt, &perms.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cached permissions: %w", err)
	}

	perms.AllowedMethods = allowedMethods
	perms.Claims = make([]rbac.Claim, len(claimsArr))
	for i, c := range claimsArr {
		perms.Claims[i] = rbac.Claim(c)
	}

	if len(contractAccess) > 0 {
		if err := json.Unmarshal(contractAccess, &perms.ContractAccess); err != nil {
			return nil, fmt.Errorf("failed to unmarshal contract_access: %w", err)
		}
	} else {
		perms.ContractAccess = make(map[string]rbac.ContractAccess)
	}

	if rateLimitRPS.Valid {
		val := int(rateLimitRPS.Int32)
		perms.RateLimitRPS = &val
	}
	if rateLimitDaily.Valid {
		val := int(rateLimitDaily.Int32)
		perms.RateLimitDaily = &val
	}

	return perms, nil
}

func (d *DB) SetCachedPermissions(ctx context.Context, perms *rbac.EffectivePermissions) error {
	query := `INSERT INTO effective_permissions_cache (id, user_id, org_id, allowed_methods, contract_access, claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	          ON CONFLICT (user_id, org_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          contract_access = EXCLUDED.contract_access,
	          claims = EXCLUDED.claims,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          computed_at = EXCLUDED.computed_at,
	          expires_at = EXCLUDED.expires_at`

	claimsArr := make([]string, len(perms.Claims))
	for i, c := range perms.Claims {
		claimsArr[i] = string(c)
	}

	contractAccess, _ := json.Marshal(perms.ContractAccess)

	_, err := d.conn.ExecContext(ctx, query,
		perms.ID, perms.UserID, perms.OrgID,
		pq.Array(perms.AllowedMethods), contractAccess, pq.Array(claimsArr),
		perms.RateLimitRPS, perms.RateLimitDaily, perms.ComputedAt, perms.ExpiresAt,
	)
	return err
}

func (d *DB) InvalidateCacheForUser(ctx context.Context, userID string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM effective_permissions_cache WHERE user_id = $1`, userID)
	return err
}

func (d *DB) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM effective_permissions_cache WHERE org_id = $1`, orgID)
	return err
}

func (d *DB) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	// Invalidate cache for all users who are members of this group
	query := `DELETE FROM effective_permissions_cache
	          WHERE user_id IN (SELECT user_id FROM user_memberships WHERE group_id = $1)`
	_, err := d.conn.ExecContext(ctx, query, groupID)
	return err
}

func (d *DB) CleanupExpiredCache(ctx context.Context) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM effective_permissions_cache WHERE expires_at < $1`,
		time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
