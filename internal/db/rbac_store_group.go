package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Group operations

func (d *DB) CreateGroup(ctx context.Context, group *rbac.Group) error {
	query := `INSERT INTO groups (id, org_id, parent_id, slug, name, description, depth, path, is_org_admin)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		group.ID, group.OrgID, group.ParentID, group.Slug, group.Name,
		group.Description, group.Depth, group.Path, group.IsOrgAdmin,
	).Scan(&group.CreatedAt, &group.UpdatedAt)
}

func (d *DB) GetGroup(ctx context.Context, id string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE id = $1`

	group := &rbac.Group{}
	var parentID sql.NullString
	var description sql.NullString

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.CreatedAt, &group.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if parentID.Valid {
		group.ParentID = &parentID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) GetGroupBySlug(ctx context.Context, orgID, slug string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND slug = $2`

	group := &rbac.Group{}
	var parentID sql.NullString
	var description sql.NullString

	err := d.conn.QueryRowContext(ctx, query, orgID, slug).Scan(
		&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.CreatedAt, &group.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group: %w", err)
	}

	if parentID.Valid {
		group.ParentID = &parentID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) UpdateGroup(ctx context.Context, group *rbac.Group) error {
	query := `UPDATE groups SET slug = $2, name = $3, description = $4, is_org_admin = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query, group.ID, group.Slug, group.Name, group.Description, group.IsOrgAdmin)
	return err
}

func (d *DB) ListGroups(ctx context.Context, orgID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE org_id = $1 ORDER BY path`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) ListGroupsPaginated(ctx context.Context, orgID string, limit, offset int) ([]*rbac.Group, int, error) {
	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM groups WHERE org_id = $1`
	if err := d.conn.QueryRowContext(ctx, countQuery, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	// Get paginated results
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE org_id = $1 ORDER BY path LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	groups, err := scanGroups(rows)
	if err != nil {
		return nil, 0, err
	}

	return groups, total, nil
}

func (d *DB) ListGroupsWithAccessPaginated(ctx context.Context, orgID string, limit, offset int) ([]*rbac.GroupWithAccess, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE org_id = $1`, orgID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count groups: %w", err)
	}

	query := `SELECT g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.created_at, g.updated_at,
	                 ga.id, ga.allowed_methods, ga.claims, ga.rate_limit_rps, ga.rate_limit_daily, ga.created_at, ga.updated_at
	          FROM groups g
	          LEFT JOIN group_access ga ON g.id = ga.group_id
	          WHERE g.org_id = $1
	          ORDER BY g.path
	          LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, orgID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list groups with access: %w", err)
	}
	defer rows.Close()

	var results []*rbac.GroupWithAccess
	for rows.Next() {
		group := &rbac.Group{}
		var parentID, description sql.NullString

		// Access fields (nullable from LEFT JOIN)
		var accessID sql.NullString
		var allowedMethods, claimsStr pq.StringArray
		var rateLimitRPS, rateLimitDaily sql.NullInt32
		var accessCreatedAt, accessUpdatedAt sql.NullTime

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.CreatedAt, &group.UpdatedAt,
			&accessID, &allowedMethods, &claimsStr, &rateLimitRPS, &rateLimitDaily, &accessCreatedAt, &accessUpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan group with access: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		gwa := &rbac.GroupWithAccess{Group: group}

		if accessID.Valid {
			access := &rbac.GroupAccess{
				ID:             accessID.String,
				GroupID:        group.ID,
				AllowedMethods: []string(allowedMethods),
				CreatedAt:      accessCreatedAt.Time,
				UpdatedAt:      accessUpdatedAt.Time,
			}
			access.Claims = make([]rbac.Claim, len(claimsStr))
			for i, c := range claimsStr {
				access.Claims[i] = rbac.Claim(c)
			}
			if rateLimitRPS.Valid {
				val := int(rateLimitRPS.Int32)
				access.RateLimitRPS = &val
			}
			if rateLimitDaily.Valid {
				val := int(rateLimitDaily.Int32)
				access.RateLimitDaily = &val
			}
			gwa.Access = access
		}

		results = append(results, gwa)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating groups with access: %w", err)
	}

	return results, total, nil
}

func (d *DB) ListGroupsByParent(ctx context.Context, parentID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE parent_id = $1 ORDER BY name`

	rows, err := d.conn.QueryContext(ctx, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) GetGroupHierarchy(ctx context.Context, groupID string) ([]*rbac.Group, error) {
	// Get the group's path first
	group, err := d.GetGroup(ctx, groupID)
	if err != nil || group == nil {
		return nil, err
	}

	// If path is empty (groups created without a path), use slug as the path
	groupPath := group.Path
	if groupPath == "" {
		groupPath = group.Slug
	}

	// Parse the path and get all groups in the hierarchy
	pathParts := strings.Split(groupPath, ".")

	// Build query with parameter placeholders
	placeholders := make([]string, len(pathParts))
	args := make([]any, len(pathParts)+1)
	args[0] = group.OrgID
	for i, part := range pathParts {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = part
	}

	query := fmt.Sprintf(`SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND slug IN (%s) ORDER BY depth`, strings.Join(placeholders, ", "))

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get group hierarchy: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) DeleteGroup(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
	return err
}

func scanGroups(rows *sql.Rows) ([]*rbac.Group, error) {
	var groups []*rbac.Group
	for rows.Next() {
		group := &rbac.Group{}
		var parentID sql.NullString
		var description sql.NullString

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.IsOrgAdmin, &group.CreatedAt, &group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		groups = append(groups, group)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating groups: %w", err)
	}

	return groups, nil
}

// Group Access operations

func (d *DB) CreateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	query := `INSERT INTO group_access (id, group_id, allowed_methods, claims, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.Claims))
	for i, c := range access.Claims {
		claims[i] = string(c)
	}

	return d.conn.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RateLimitRPS, access.RateLimitDaily,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

func (d *DB) GetGroupAccess(ctx context.Context, groupID string) (*rbac.GroupAccess, error) {
	query := `SELECT id, group_id, allowed_methods, claims, rate_limit_rps, rate_limit_daily, created_at, updated_at
	          FROM group_access WHERE group_id = $1`

	access := &rbac.GroupAccess{}
	var allowedMethods, defaultClaims pq.StringArray
	var rateLimitRPS, rateLimitDaily sql.NullInt32

	err := d.conn.QueryRowContext(ctx, query, groupID).Scan(
		&access.ID, &access.GroupID,
		&allowedMethods, &defaultClaims,
		&rateLimitRPS, &rateLimitDaily,
		&access.CreatedAt, &access.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group access: %w", err)
	}

	access.AllowedMethods = allowedMethods
	access.Claims = make([]rbac.Claim, len(defaultClaims))
	for i, c := range defaultClaims {
		access.Claims[i] = rbac.Claim(c)
	}

	if rateLimitRPS.Valid {
		val := int(rateLimitRPS.Int32)
		access.RateLimitRPS = &val
	}
	if rateLimitDaily.Valid {
		val := int(rateLimitDaily.Int32)
		access.RateLimitDaily = &val
	}

	return access, nil
}

func (d *DB) UpdateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	query := `INSERT INTO group_access (id, group_id, allowed_methods, claims, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          ON CONFLICT (group_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          claims = EXCLUDED.claims,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.Claims))
	for i, c := range access.Claims {
		claims[i] = string(c)
	}

	return d.conn.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RateLimitRPS, access.RateLimitDaily,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

func (d *DB) DeleteGroupAccess(ctx context.Context, groupID string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM group_access WHERE group_id = $1`, groupID)
	return err
}

// SetGroupAccess creates or updates group access settings (alias for UpdateGroupAccess).
func (d *DB) SetGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	return d.UpdateGroupAccess(ctx, access)
}
