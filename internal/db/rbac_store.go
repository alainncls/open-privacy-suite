package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"privacy-proxy/internal/rbac"
)

// Ensure DB implements rbac.Store
var _ rbac.Store = (*DB)(nil)

// Organization operations

func (d *DB) CreateOrganization(ctx context.Context, org *rbac.Organization) error {
	query := `INSERT INTO organizations (id, slug, name, settings)
	          VALUES ($1, $2, $3, $4)
	          RETURNING created_at, updated_at`

	settings, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	return d.conn.QueryRowContext(ctx, query,
		org.ID, org.Slug, org.Name, settings,
	).Scan(&org.CreatedAt, &org.UpdatedAt)
}

func (d *DB) GetOrganization(ctx context.Context, id string) (*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, created_at, updated_at
	          FROM organizations WHERE id = $1`

	org := &rbac.Organization{}
	var settings []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&org.ID, &org.Slug, &org.Name, &settings, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if err := json.Unmarshal(settings, &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return org, nil
}

func (d *DB) GetOrganizationBySlug(ctx context.Context, slug string) (*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, created_at, updated_at
	          FROM organizations WHERE slug = $1`

	org := &rbac.Organization{}
	var settings []byte

	err := d.conn.QueryRowContext(ctx, query, slug).Scan(
		&org.ID, &org.Slug, &org.Name, &settings, &org.CreatedAt, &org.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	if err := json.Unmarshal(settings, &org.Settings); err != nil {
		return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
	}

	return org, nil
}

func (d *DB) UpdateOrganization(ctx context.Context, org *rbac.Organization) error {
	query := `UPDATE organizations SET slug = $2, name = $3, settings = $4, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	settings, err := json.Marshal(org.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query, org.ID, org.Slug, org.Name, settings)
	return err
}

func (d *DB) ListOrganizations(ctx context.Context) ([]*rbac.Organization, error) {
	query := `SELECT id, slug, name, settings, created_at, updated_at
	          FROM organizations ORDER BY name`

	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list organizations: %w", err)
	}
	defer rows.Close()

	var orgs []*rbac.Organization
	for rows.Next() {
		org := &rbac.Organization{}
		var settings []byte

		if err := rows.Scan(&org.ID, &org.Slug, &org.Name, &settings, &org.CreatedAt, &org.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan organization: %w", err)
		}

		if err := json.Unmarshal(settings, &org.Settings); err != nil {
			return nil, fmt.Errorf("failed to unmarshal settings: %w", err)
		}

		orgs = append(orgs, org)
	}

	return orgs, nil
}

func (d *DB) DeleteOrganization(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

// Group operations

func (d *DB) CreateGroup(ctx context.Context, group *rbac.Group) error {
	query := `INSERT INTO groups (id, org_id, parent_id, role_id, slug, name, description, depth, path)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		group.ID, group.OrgID, group.ParentID, group.RoleID, group.Slug, group.Name,
		group.Description, group.Depth, group.Path,
	).Scan(&group.CreatedAt, &group.UpdatedAt)
}

func (d *DB) GetGroup(ctx context.Context, id string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, role_id, slug, name, description, depth, path, created_at, updated_at
	          FROM groups WHERE id = $1`

	group := &rbac.Group{}
	var parentID sql.NullString
	var roleID sql.NullString
	var description sql.NullString

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&group.ID, &group.OrgID, &parentID, &roleID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.CreatedAt, &group.UpdatedAt,
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
	if roleID.Valid {
		group.RoleID = &roleID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) GetGroupBySlug(ctx context.Context, orgID, slug string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, role_id, slug, name, description, depth, path, created_at, updated_at
	          FROM groups WHERE org_id = $1 AND slug = $2`

	group := &rbac.Group{}
	var parentID sql.NullString
	var roleID sql.NullString
	var description sql.NullString

	err := d.conn.QueryRowContext(ctx, query, orgID, slug).Scan(
		&group.ID, &group.OrgID, &parentID, &roleID, &group.Slug, &group.Name,
		&description, &group.Depth, &group.Path, &group.CreatedAt, &group.UpdatedAt,
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
	if roleID.Valid {
		group.RoleID = &roleID.String
	}
	if description.Valid {
		group.Description = description.String
	}

	return group, nil
}

func (d *DB) UpdateGroup(ctx context.Context, group *rbac.Group) error {
	query := `UPDATE groups SET slug = $2, name = $3, description = $4, role_id = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query, group.ID, group.Slug, group.Name, group.Description, group.RoleID)
	return err
}

func (d *DB) ListGroups(ctx context.Context, orgID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, role_id, slug, name, description, depth, path, created_at, updated_at
	          FROM groups WHERE org_id = $1 ORDER BY path`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	return scanGroups(rows)
}

func (d *DB) ListGroupsByParent(ctx context.Context, parentID string) ([]*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, role_id, slug, name, description, depth, path, created_at, updated_at
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

	// Parse the path and get all groups in the hierarchy
	pathParts := strings.Split(group.Path, ".")

	// Build query with parameter placeholders
	placeholders := make([]string, len(pathParts))
	args := make([]any, len(pathParts)+1)
	args[0] = group.OrgID
	for i, part := range pathParts {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args[i+1] = part
	}

	query := fmt.Sprintf(`SELECT id, org_id, parent_id, role_id, slug, name, description, depth, path, created_at, updated_at
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
		var roleID sql.NullString
		var description sql.NullString

		if err := rows.Scan(
			&group.ID, &group.OrgID, &parentID, &roleID, &group.Slug, &group.Name,
			&description, &group.Depth, &group.Path, &group.CreatedAt, &group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan group: %w", err)
		}

		if parentID.Valid {
			group.ParentID = &parentID.String
		}
		if roleID.Valid {
			group.RoleID = &roleID.String
		}
		if description.Valid {
			group.Description = description.String
		}

		groups = append(groups, group)
	}
	return groups, nil
}

// Group Permissions operations

func (d *DB) SetGroupPermissions(ctx context.Context, perms *rbac.GroupPermissions) error {
	query := `INSERT INTO group_permissions (id, group_id, allow_methods, allow_addresses, owned_addresses, address_functions, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	          ON CONFLICT (group_id) DO UPDATE SET
	          allow_methods = EXCLUDED.allow_methods,
	          allow_addresses = EXCLUDED.allow_addresses,
	          owned_addresses = EXCLUDED.owned_addresses,
	          address_functions = EXCLUDED.address_functions,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	allowMethods, _ := json.Marshal(perms.AllowMethods)
	allowAddresses, _ := json.Marshal(perms.AllowAddresses)
	ownedAddresses, _ := json.Marshal(perms.OwnedAddresses)
	addressFunctions, _ := json.Marshal(perms.AddressFunctions)

	return d.conn.QueryRowContext(ctx, query,
		perms.ID, perms.GroupID,
		allowMethods, allowAddresses, ownedAddresses, addressFunctions,
		perms.RateLimitRPS, perms.RateLimitDaily,
	).Scan(&perms.CreatedAt, &perms.UpdatedAt)
}

func (d *DB) GetGroupPermissions(ctx context.Context, groupID string) (*rbac.GroupPermissions, error) {
	query := `SELECT id, group_id, allow_methods, allow_addresses, owned_addresses, address_functions, rate_limit_rps, rate_limit_daily, created_at, updated_at
	          FROM group_permissions WHERE group_id = $1`

	perms := &rbac.GroupPermissions{}
	var allowMethods, allowAddresses, ownedAddresses, addressFunctions []byte
	var rateLimitRPS, rateLimitDaily sql.NullInt32

	err := d.conn.QueryRowContext(ctx, query, groupID).Scan(
		&perms.ID, &perms.GroupID,
		&allowMethods, &allowAddresses, &ownedAddresses, &addressFunctions,
		&rateLimitRPS, &rateLimitDaily,
		&perms.CreatedAt, &perms.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get group permissions: %w", err)
	}

	if err := json.Unmarshal(allowMethods, &perms.AllowMethods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
	}
	if err := json.Unmarshal(allowAddresses, &perms.AllowAddresses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_addresses: %w", err)
	}
	if err := json.Unmarshal(ownedAddresses, &perms.OwnedAddresses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal owned_addresses: %w", err)
	}
	if len(addressFunctions) > 0 {
		if err := json.Unmarshal(addressFunctions, &perms.AddressFunctions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal address_functions: %w", err)
		}
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

func (d *DB) DeleteGroupPermissions(ctx context.Context, groupID string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM group_permissions WHERE group_id = $1`, groupID)
	return err
}

// Role operations

func (d *DB) CreateRole(ctx context.Context, role *rbac.Role) error {
	query := `INSERT INTO roles (id, org_id, name, description, claims, allow_methods)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	claims, _ := json.Marshal(role.Claims)
	allowMethods, _ := json.Marshal(role.AllowMethods)

	return d.conn.QueryRowContext(ctx, query,
		role.ID, role.OrgID, role.Name, role.Description, claims, allowMethods,
	).Scan(&role.CreatedAt, &role.UpdatedAt)
}

func (d *DB) GetRole(ctx context.Context, id string) (*rbac.Role, error) {
	query := `SELECT id, org_id, name, description, claims, allow_methods, created_at, updated_at
	          FROM roles WHERE id = $1`

	role := &rbac.Role{}
	var description sql.NullString
	var claims, allowMethods []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&role.ID, &role.OrgID, &role.Name, &description, &claims, &allowMethods,
		&role.CreatedAt, &role.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}

	if err := json.Unmarshal(claims, &role.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	if err := json.Unmarshal(allowMethods, &role.AllowMethods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
	}

	return role, nil
}

func (d *DB) GetRoleByName(ctx context.Context, orgID, name string) (*rbac.Role, error) {
	query := `SELECT id, org_id, name, description, claims, allow_methods, created_at, updated_at
	          FROM roles WHERE org_id = $1 AND name = $2`

	role := &rbac.Role{}
	var description sql.NullString
	var claims, allowMethods []byte

	err := d.conn.QueryRowContext(ctx, query, orgID, name).Scan(
		&role.ID, &role.OrgID, &role.Name, &description, &claims, &allowMethods,
		&role.CreatedAt, &role.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if description.Valid {
		role.Description = description.String
	}

	if err := json.Unmarshal(claims, &role.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	if err := json.Unmarshal(allowMethods, &role.AllowMethods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
	}

	return role, nil
}

func (d *DB) UpdateRole(ctx context.Context, role *rbac.Role) error {
	query := `UPDATE roles SET name = $2, description = $3, claims = $4, allow_methods = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	claims, _ := json.Marshal(role.Claims)
	allowMethods, _ := json.Marshal(role.AllowMethods)

	_, err := d.conn.ExecContext(ctx, query, role.ID, role.Name, role.Description, claims, allowMethods)
	return err
}

func (d *DB) ListRoles(ctx context.Context, orgID string) ([]*rbac.Role, error) {
	query := `SELECT id, org_id, name, description, claims, allow_methods, created_at, updated_at
	          FROM roles WHERE org_id = $1 ORDER BY name`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer rows.Close()

	var roles []*rbac.Role
	for rows.Next() {
		role := &rbac.Role{}
		var description sql.NullString
		var claims, allowMethods []byte

		if err := rows.Scan(
			&role.ID, &role.OrgID, &role.Name, &description, &claims, &allowMethods,
			&role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		if description.Valid {
			role.Description = description.String
		}

		if err := json.Unmarshal(claims, &role.Claims); err != nil {
			return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
		}
		if err := json.Unmarshal(allowMethods, &role.AllowMethods); err != nil {
			return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
		}

		roles = append(roles, role)
	}

	return roles, nil
}

func (d *DB) DeleteRole(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

// User operations

func (d *DB) CreateUser(ctx context.Context, user *rbac.User) error {
	query := `INSERT INTO users (id, external_id, kyc, banned, note, metadata)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return d.conn.QueryRowContext(ctx, query,
		user.ID, user.ExternalID, user.KYC, user.Banned, user.Note, metadata,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

func (d *DB) GetUser(ctx context.Context, id string) (*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, created_at, updated_at
	          FROM users WHERE id = $1`

	user := &rbac.User{}
	var note sql.NullString
	var metadata []byte

	err := d.conn.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.ExternalID, &user.KYC, &user.Banned, &note, &metadata,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if note.Valid {
		user.Note = note.String
	}

	if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return user, nil
}

func (d *DB) GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, created_at, updated_at
	          FROM users WHERE external_id = $1`

	user := &rbac.User{}
	var note sql.NullString
	var metadata []byte

	err := d.conn.QueryRowContext(ctx, query, externalID).Scan(
		&user.ID, &user.ExternalID, &user.KYC, &user.Banned, &note, &metadata,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if note.Valid {
		user.Note = note.String
	}

	if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return user, nil
}

func (d *DB) UpdateUser(ctx context.Context, user *rbac.User) error {
	query := `UPDATE users SET kyc = $2, banned = $3, note = $4, metadata = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = d.conn.ExecContext(ctx, query, user.ID, user.KYC, user.Banned, user.Note, metadata)
	return err
}

func (d *DB) ListUsers(ctx context.Context, limit, offset int) ([]*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, created_at, updated_at
	          FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := d.conn.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*rbac.User
	for rows.Next() {
		user := &rbac.User{}
		var note sql.NullString
		var metadata []byte

		if err := rows.Scan(
			&user.ID, &user.ExternalID, &user.KYC, &user.Banned, &note, &metadata,
			&user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		if note.Valid {
			user.Note = note.String
		}

		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		users = append(users, user)
	}

	return users, nil
}

func (d *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// Membership operations

func (d *DB) CreateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `INSERT INTO user_memberships (id, user_id, group_id, role_id, source, zk_credential_ref, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		membership.ID, membership.UserID, membership.GroupID, membership.RoleID,
		string(membership.Source), membership.ZKCredentialRef, membership.ExpiresAt,
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
}

func (d *DB) GetMembership(ctx context.Context, id string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, role_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE id = $1`

	return scanMembership(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, role_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1 AND group_id = $2`

	return scanMembership(d.conn.QueryRowContext(ctx, query, userID, groupID))
}

func (d *DB) UpdateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `UPDATE user_memberships SET role_id = $2, source = $3, zk_credential_ref = $4, expires_at = $5, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query,
		membership.ID, membership.RoleID, string(membership.Source),
		membership.ZKCredentialRef, membership.ExpiresAt,
	)
	return err
}

func (d *DB) ListUserMemberships(ctx context.Context, userID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, role_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	return scanMemberships(rows)
}

func (d *DB) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*rbac.MembershipWithDetails, error) {
	query := `SELECT m.id, m.user_id, m.group_id, m.role_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 g.id, g.org_id, g.parent_id, g.role_id, g.slug, g.name, g.description, g.depth, g.path, g.created_at, g.updated_at,
	                 r.id, r.org_id, r.name, r.description, r.claims, r.allow_methods, r.created_at, r.updated_at
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          LEFT JOIN roles r ON COALESCE(g.role_id, m.role_id) = r.id
	          WHERE m.user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships with details: %w", err)
	}
	defer rows.Close()

	var results []*rbac.MembershipWithDetails
	for rows.Next() {
		result := &rbac.MembershipWithDetails{
			Membership: &rbac.UserMembership{},
			Group:      &rbac.Group{},
		}

		var roleID, zkCredRef sql.NullString
		var expiresAt sql.NullTime
		var groupParentID, groupRoleID, groupDescription sql.NullString
		var rID, rOrgID, rName, rDescription sql.NullString
		var rClaims, rAllowMethods []byte
		var rCreatedAt, rUpdatedAt sql.NullTime

		if err := rows.Scan(
			&result.Membership.ID, &result.Membership.UserID, &result.Membership.GroupID,
			&roleID, &result.Membership.Source, &zkCredRef, &expiresAt,
			&result.Membership.CreatedAt, &result.Membership.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &groupParentID, &groupRoleID, &result.Group.Slug,
			&result.Group.Name, &groupDescription, &result.Group.Depth, &result.Group.Path,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
			&rID, &rOrgID, &rName, &rDescription, &rClaims, &rAllowMethods, &rCreatedAt, &rUpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if roleID.Valid {
			result.Membership.RoleID = &roleID.String
		}
		if zkCredRef.Valid {
			result.Membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			result.Membership.ExpiresAt = &expiresAt.Time
		}
		if groupParentID.Valid {
			result.Group.ParentID = &groupParentID.String
		}
		if groupRoleID.Valid {
			result.Group.RoleID = &groupRoleID.String
		}
		if groupDescription.Valid {
			result.Group.Description = groupDescription.String
		}

		if rID.Valid {
			result.Role = &rbac.Role{
				ID:          rID.String,
				OrgID:       rOrgID.String,
				Name:        rName.String,
				Description: rDescription.String,
				CreatedAt:   rCreatedAt.Time,
				UpdatedAt:   rUpdatedAt.Time,
			}
			if len(rClaims) > 0 {
				if err := json.Unmarshal(rClaims, &result.Role.Claims); err != nil {
					return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
				}
			}
			if len(rAllowMethods) > 0 {
				if err := json.Unmarshal(rAllowMethods, &result.Role.AllowMethods); err != nil {
					return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (d *DB) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*rbac.MembershipWithDetails, error) {
	query := `SELECT m.id, m.user_id, m.group_id, m.role_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 g.id, g.org_id, g.parent_id, g.role_id, g.slug, g.name, g.description, g.depth, g.path, g.created_at, g.updated_at,
	                 r.id, r.org_id, r.name, r.description, r.claims, r.allow_methods, r.created_at, r.updated_at
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          LEFT JOIN roles r ON COALESCE(g.role_id, m.role_id) = r.id
	          WHERE m.user_id = $1 AND g.org_id = $2`

	rows, err := d.conn.QueryContext(ctx, query, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	var results []*rbac.MembershipWithDetails
	for rows.Next() {
		result := &rbac.MembershipWithDetails{
			Membership: &rbac.UserMembership{},
			Group:      &rbac.Group{},
		}

		var roleID, zkCredRef sql.NullString
		var expiresAt sql.NullTime
		var groupParentID, groupRoleID, groupDescription sql.NullString
		var rID, rOrgID, rName, rDescription sql.NullString
		var rClaims, rAllowMethods []byte
		var rCreatedAt, rUpdatedAt sql.NullTime

		if err := rows.Scan(
			&result.Membership.ID, &result.Membership.UserID, &result.Membership.GroupID,
			&roleID, &result.Membership.Source, &zkCredRef, &expiresAt,
			&result.Membership.CreatedAt, &result.Membership.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &groupParentID, &groupRoleID, &result.Group.Slug,
			&result.Group.Name, &groupDescription, &result.Group.Depth, &result.Group.Path,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
			&rID, &rOrgID, &rName, &rDescription, &rClaims, &rAllowMethods, &rCreatedAt, &rUpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if roleID.Valid {
			result.Membership.RoleID = &roleID.String
		}
		if zkCredRef.Valid {
			result.Membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			result.Membership.ExpiresAt = &expiresAt.Time
		}
		if groupParentID.Valid {
			result.Group.ParentID = &groupParentID.String
		}
		if groupRoleID.Valid {
			result.Group.RoleID = &groupRoleID.String
		}
		if groupDescription.Valid {
			result.Group.Description = groupDescription.String
		}

		if rID.Valid {
			result.Role = &rbac.Role{
				ID:          rID.String,
				OrgID:       rOrgID.String,
				Name:        rName.String,
				Description: rDescription.String,
				CreatedAt:   rCreatedAt.Time,
				UpdatedAt:   rUpdatedAt.Time,
			}
			if len(rClaims) > 0 {
				if err := json.Unmarshal(rClaims, &result.Role.Claims); err != nil {
					return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
				}
			}
			if len(rAllowMethods) > 0 {
				if err := json.Unmarshal(rAllowMethods, &result.Role.AllowMethods); err != nil {
					return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
				}
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (d *DB) ListGroupMembers(ctx context.Context, groupID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, role_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE group_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list group members: %w", err)
	}
	defer rows.Close()

	return scanMemberships(rows)
}

func (d *DB) DeleteMembership(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM user_memberships WHERE id = $1`, id)
	return err
}

func (d *DB) DeleteExpiredMemberships(ctx context.Context) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM user_memberships WHERE expires_at IS NOT NULL AND expires_at < $1`,
		time.Now(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func scanMembership(row *sql.Row) (*rbac.UserMembership, error) {
	membership := &rbac.UserMembership{}
	var roleID, zkCredRef sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(
		&membership.ID, &membership.UserID, &membership.GroupID,
		&roleID, &membership.Source, &zkCredRef, &expiresAt,
		&membership.CreatedAt, &membership.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan membership: %w", err)
	}

	if roleID.Valid {
		membership.RoleID = &roleID.String
	}
	if zkCredRef.Valid {
		membership.ZKCredentialRef = zkCredRef.String
	}
	if expiresAt.Valid {
		membership.ExpiresAt = &expiresAt.Time
	}

	return membership, nil
}

func scanMemberships(rows *sql.Rows) ([]*rbac.UserMembership, error) {
	var memberships []*rbac.UserMembership
	for rows.Next() {
		membership := &rbac.UserMembership{}
		var roleID, zkCredRef sql.NullString
		var expiresAt sql.NullTime

		if err := rows.Scan(
			&membership.ID, &membership.UserID, &membership.GroupID,
			&roleID, &membership.Source, &zkCredRef, &expiresAt,
			&membership.CreatedAt, &membership.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if roleID.Valid {
			membership.RoleID = &roleID.String
		}
		if zkCredRef.Valid {
			membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			membership.ExpiresAt = &expiresAt.Time
		}

		memberships = append(memberships, membership)
	}
	return memberships, nil
}

// Contract Ownership operations

func (d *DB) CreateContractOwnership(ctx context.Context, ownership *rbac.ContractOwnership) error {
	query := `INSERT INTO contract_ownership (id, contract_address, org_id, owner_group_id, deployed_by_user_id, deployed_at, metadata)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	metadata, _ := json.Marshal(ownership.Metadata)

	return d.conn.QueryRowContext(ctx, query,
		ownership.ID, strings.ToLower(ownership.ContractAddress), ownership.OrgID,
		ownership.OwnerGroupID,
		ownership.DeployedByUserID, ownership.DeployedAt, metadata,
	).Scan(&ownership.CreatedAt, &ownership.UpdatedAt)
}

func (d *DB) GetContractOwnership(ctx context.Context, id string) (*rbac.ContractOwnership, error) {
	query := `SELECT id, contract_address, org_id, owner_group_id, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contract_ownership WHERE id = $1`

	return scanContractOwnership(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetContractOwnershipByAddress(ctx context.Context, orgID, address string) (*rbac.ContractOwnership, error) {
	query := `SELECT id, contract_address, org_id, owner_group_id, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contract_ownership WHERE org_id = $1 AND contract_address = $2`

	return scanContractOwnership(d.conn.QueryRowContext(ctx, query, orgID, strings.ToLower(address)))
}

func (d *DB) UpdateContractOwnership(ctx context.Context, ownership *rbac.ContractOwnership) error {
	query := `UPDATE contract_ownership SET owner_group_id = $2, metadata = $3, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	metadata, _ := json.Marshal(ownership.Metadata)

	_, err := d.conn.ExecContext(ctx, query,
		ownership.ID, ownership.OwnerGroupID, metadata,
	)
	return err
}

func (d *DB) ListContractOwnerships(ctx context.Context, orgID string) ([]*rbac.ContractOwnership, error) {
	query := `SELECT id, contract_address, org_id, owner_group_id, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contract_ownership WHERE org_id = $1 ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract ownerships: %w", err)
	}
	defer rows.Close()

	return scanContractOwnerships(rows)
}

func (d *DB) ListContractOwnershipsByGroup(ctx context.Context, groupID string) ([]*rbac.ContractOwnership, error) {
	query := `SELECT id, contract_address, org_id, owner_group_id, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contract_ownership WHERE owner_group_id = $1 ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract ownerships: %w", err)
	}
	defer rows.Close()

	return scanContractOwnerships(rows)
}

func (d *DB) DeleteContractOwnership(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM contract_ownership WHERE id = $1`, id)
	return err
}

func scanContractOwnership(row *sql.Row) (*rbac.ContractOwnership, error) {
	ownership := &rbac.ContractOwnership{}
	var deployedByUserID sql.NullString
	var deployedAt sql.NullTime
	var metadata []byte

	err := row.Scan(
		&ownership.ID, &ownership.ContractAddress, &ownership.OrgID, &ownership.OwnerGroupID,
		&deployedByUserID, &deployedAt, &metadata,
		&ownership.CreatedAt, &ownership.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract ownership: %w", err)
	}

	if deployedByUserID.Valid {
		ownership.DeployedByUserID = &deployedByUserID.String
	}
	if deployedAt.Valid {
		ownership.DeployedAt = &deployedAt.Time
	}

	if err := json.Unmarshal(metadata, &ownership.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return ownership, nil
}

func scanContractOwnerships(rows *sql.Rows) ([]*rbac.ContractOwnership, error) {
	var ownerships []*rbac.ContractOwnership
	for rows.Next() {
		ownership := &rbac.ContractOwnership{}
		var deployedByUserID sql.NullString
		var deployedAt sql.NullTime
		var metadata []byte

		if err := rows.Scan(
			&ownership.ID, &ownership.ContractAddress, &ownership.OrgID, &ownership.OwnerGroupID,
			&deployedByUserID, &deployedAt, &metadata,
			&ownership.CreatedAt, &ownership.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract ownership: %w", err)
		}

		if deployedByUserID.Valid {
			ownership.DeployedByUserID = &deployedByUserID.String
		}
		if deployedAt.Valid {
			ownership.DeployedAt = &deployedAt.Time
		}

		if err := json.Unmarshal(metadata, &ownership.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		ownerships = append(ownerships, ownership)
	}
	return ownerships, nil
}

// Effective Permissions Cache operations

func (d *DB) GetCachedPermissions(ctx context.Context, userID, orgID string) (*rbac.EffectivePermissions, error) {
	query := `SELECT id, user_id, org_id, allow_methods, allow_addresses, owned_addresses, address_functions, claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at
	          FROM effective_permissions_cache WHERE user_id = $1 AND org_id = $2 AND expires_at > $3`

	perms := &rbac.EffectivePermissions{}
	var allowMethods, allowAddresses, ownedAddresses, addressFunctions, claims []byte
	var rateLimitRPS, rateLimitDaily sql.NullInt32

	err := d.conn.QueryRowContext(ctx, query, userID, orgID, time.Now()).Scan(
		&perms.ID, &perms.UserID, &perms.OrgID,
		&allowMethods, &allowAddresses, &ownedAddresses, &addressFunctions, &claims,
		&rateLimitRPS, &rateLimitDaily, &perms.ComputedAt, &perms.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cached permissions: %w", err)
	}

	if err := json.Unmarshal(allowMethods, &perms.AllowMethods); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_methods: %w", err)
	}
	if err := json.Unmarshal(allowAddresses, &perms.AllowAddresses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allow_addresses: %w", err)
	}
	if err := json.Unmarshal(ownedAddresses, &perms.OwnedAddresses); err != nil {
		return nil, fmt.Errorf("failed to unmarshal owned_addresses: %w", err)
	}
	if len(addressFunctions) > 0 {
		if err := json.Unmarshal(addressFunctions, &perms.AddressFunctions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal address_functions: %w", err)
		}
	}
	if err := json.Unmarshal(claims, &perms.Claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
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
	query := `INSERT INTO effective_permissions_cache (id, user_id, org_id, allow_methods, allow_addresses, owned_addresses, address_functions, claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	          ON CONFLICT (user_id, org_id) DO UPDATE SET
	          allow_methods = EXCLUDED.allow_methods,
	          allow_addresses = EXCLUDED.allow_addresses,
	          owned_addresses = EXCLUDED.owned_addresses,
	          address_functions = EXCLUDED.address_functions,
	          claims = EXCLUDED.claims,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          computed_at = EXCLUDED.computed_at,
	          expires_at = EXCLUDED.expires_at`

	allowMethods, _ := json.Marshal(perms.AllowMethods)
	allowAddresses, _ := json.Marshal(perms.AllowAddresses)
	ownedAddresses, _ := json.Marshal(perms.OwnedAddresses)
	addressFunctions, _ := json.Marshal(perms.AddressFunctions)
	claims, _ := json.Marshal(perms.Claims)

	_, err := d.conn.ExecContext(ctx, query,
		perms.ID, perms.UserID, perms.OrgID,
		allowMethods, allowAddresses, ownedAddresses, addressFunctions, claims,
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

// Audit Log operations

func (d *DB) CreateAuditLog(ctx context.Context, entry *rbac.AuditLogEntry) error {
	query := `INSERT INTO rbac_audit_log (actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING id, created_at`

	var oldValue, newValue []byte
	var err error

	if entry.OldValue != nil {
		oldValue, err = json.Marshal(entry.OldValue)
		if err != nil {
			return fmt.Errorf("failed to marshal old value: %w", err)
		}
	}

	if entry.NewValue != nil {
		newValue, err = json.Marshal(entry.NewValue)
		if err != nil {
			return fmt.Errorf("failed to marshal new value: %w", err)
		}
	}

	return d.conn.QueryRowContext(ctx, query,
		entry.ActorID, entry.ActorExternalID, entry.Action, entry.ResourceType,
		entry.ResourceID, entry.ResourceName, oldValue, newValue, entry.IPAddress,
	).Scan(&entry.ID, &entry.CreatedAt)
}

func (d *DB) ListAuditLogs(ctx context.Context, resourceType string, resourceID *string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	var query string
	var args []any

	if resourceID != nil {
		query = `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
		         FROM rbac_audit_log WHERE resource_type = $1 AND resource_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		args = []any{resourceType, *resourceID, limit, offset}
	} else {
		query = `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
		         FROM rbac_audit_log WHERE resource_type = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{resourceType, limit, offset}
	}

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func (d *DB) ListAuditLogsByActor(ctx context.Context, actorID string, limit, offset int) ([]*rbac.AuditLogEntry, error) {
	query := `SELECT id, actor_id, actor_external_id, action, resource_type, resource_id, resource_name, old_value, new_value, ip_address, created_at
	          FROM rbac_audit_log WHERE actor_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`

	rows, err := d.conn.QueryContext(ctx, query, actorID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	defer rows.Close()

	return scanAuditLogs(rows)
}

func scanAuditLogs(rows *sql.Rows) ([]*rbac.AuditLogEntry, error) {
	var entries []*rbac.AuditLogEntry
	for rows.Next() {
		entry := &rbac.AuditLogEntry{}
		var actorID, resourceID sql.NullString
		var oldValue, newValue []byte

		if err := rows.Scan(
			&entry.ID, &actorID, &entry.ActorExternalID, &entry.Action, &entry.ResourceType,
			&resourceID, &entry.ResourceName, &oldValue, &newValue, &entry.IPAddress,
			&entry.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if actorID.Valid {
			entry.ActorID = &actorID.String
		}
		if resourceID.Valid {
			entry.ResourceID = &resourceID.String
		}

		if len(oldValue) > 0 {
			if err := json.Unmarshal(oldValue, &entry.OldValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal old value: %w", err)
			}
		}

		if len(newValue) > 0 {
			if err := json.Unmarshal(newValue, &entry.NewValue); err != nil {
				return nil, fmt.Errorf("failed to unmarshal new value: %w", err)
			}
		}

		entries = append(entries, entry)
	}
	return entries, nil
}
