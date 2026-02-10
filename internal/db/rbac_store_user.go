package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"privacy-proxy/internal/rbac"
)

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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// UserFilter contains filter options for listing users
type UserFilter struct {
	OrgID  string // Filter by organization (users with memberships in this org)
	Search string // Search by DID (external_id) or linked ETH address
}

// ListUsersFiltered returns users matching the given filters
func (d *DB) ListUsersFiltered(ctx context.Context, filter UserFilter, limit, offset int) ([]*rbac.User, error) {
	var args []any
	argNum := 1

	// Build the query dynamically based on filters
	query := `SELECT DISTINCT u.id, u.external_id, u.kyc, u.banned, u.note, u.metadata, u.created_at, u.updated_at
	          FROM users u`

	// Join with memberships/groups if filtering by org
	if filter.OrgID != "" {
		query += `
		    JOIN user_memberships m ON u.id = m.user_id
		    JOIN groups g ON m.group_id = g.id`
	}

	// Join with eth_address_links if searching (to search by linked address)
	if filter.Search != "" {
		query += `
		    LEFT JOIN eth_address_links e ON u.external_id = e.did`
	}

	// Build WHERE clause
	var conditions []string

	if filter.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("g.org_id = $%d", argNum))
		args = append(args, filter.OrgID)
		argNum++
	}

	if filter.Search != "" {
		// Search by external_id (DID) or linked ETH address using ILIKE for case-insensitive matching
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(u.external_id ILIKE $%d OR e.eth_address ILIKE $%d)", argNum, argNum+1))
		args = append(args, searchPattern, searchPattern)
		argNum += 2
	}

	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			query += " AND " + conditions[i]
		}
	}

	query += fmt.Sprintf(" ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d", argNum, argNum+1)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

func (d *DB) ListUsersPaginated(ctx context.Context, limit, offset int) ([]*rbac.User, int, error) {
	var total int
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	users, err := d.ListUsers(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (d *DB) ListUsersFilteredPaginated(ctx context.Context, filter UserFilter, limit, offset int) ([]*rbac.User, int, error) {
	var args []any
	argNum := 1

	// Build shared FROM/JOIN/WHERE clauses
	from := `FROM users u`
	var conditions []string

	if filter.OrgID != "" {
		from += `
		    JOIN user_memberships m ON u.id = m.user_id
		    JOIN groups g ON m.group_id = g.id`
		conditions = append(conditions, fmt.Sprintf("g.org_id = $%d", argNum))
		args = append(args, filter.OrgID)
		argNum++
	}

	if filter.Search != "" {
		from += `
		    LEFT JOIN eth_address_links e ON u.external_id = e.did`
		searchPattern := "%" + filter.Search + "%"
		conditions = append(conditions, fmt.Sprintf("(u.external_id ILIKE $%d OR e.eth_address ILIKE $%d)", argNum, argNum+1))
		args = append(args, searchPattern, searchPattern)
		argNum += 2
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + conditions[0]
		for i := 1; i < len(conditions); i++ {
			where += " AND " + conditions[i]
		}
	}

	// Count query
	countQuery := fmt.Sprintf("SELECT COUNT(DISTINCT u.id) %s%s", from, where)
	var total int
	if err := d.conn.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Data query
	dataQuery := fmt.Sprintf("SELECT DISTINCT u.id, u.external_id, u.kyc, u.banned, u.note, u.metadata, u.created_at, u.updated_at %s%s ORDER BY u.created_at DESC LIMIT $%d OFFSET $%d", from, where, argNum, argNum+1)
	dataArgs := append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
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
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}

		if note.Valid {
			user.Note = note.String
		}

		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating users: %w", err)
	}

	return users, total, nil
}

func (d *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// Membership operations

func (d *DB) CreateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `INSERT INTO user_memberships (id, user_id, group_id, source, zk_credential_ref, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	return d.conn.QueryRowContext(ctx, query,
		membership.ID, membership.UserID, membership.GroupID,
		string(membership.Source), membership.ZKCredentialRef, membership.ExpiresAt,
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
}

func (d *DB) GetMembership(ctx context.Context, id string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE id = $1`

	return scanMembership(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetMembershipByUserAndGroup(ctx context.Context, userID, groupID string) (*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1 AND group_id = $2`

	return scanMembership(d.conn.QueryRowContext(ctx, query, userID, groupID))
}

func (d *DB) UpdateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `UPDATE user_memberships SET source = $2, zk_credential_ref = $3, expires_at = $4, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	_, err := d.conn.ExecContext(ctx, query,
		membership.ID, string(membership.Source),
		membership.ZKCredentialRef, membership.ExpiresAt,
	)
	return err
}

func (d *DB) ListUserMemberships(ctx context.Context, userID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
	          FROM user_memberships WHERE user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	return scanMemberships(rows)
}

func (d *DB) ListUserMembershipsWithDetails(ctx context.Context, userID string) ([]*rbac.MembershipWithDetails, error) {
	query := `SELECT m.id, m.user_id, m.group_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.created_at, g.updated_at
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          WHERE m.user_id = $1`

	rows, err := d.conn.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships with details: %w", err)
	}
	defer rows.Close()

	return scanMembershipsWithDetails(rows)
}

func (d *DB) ListUserMembershipsInOrg(ctx context.Context, userID, orgID string) ([]*rbac.MembershipWithDetails, error) {
	query := `SELECT m.id, m.user_id, m.group_id, m.source, m.zk_credential_ref, m.expires_at, m.created_at, m.updated_at,
	                 g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.created_at, g.updated_at
	          FROM user_memberships m
	          JOIN groups g ON m.group_id = g.id
	          WHERE m.user_id = $1 AND g.org_id = $2`

	rows, err := d.conn.QueryContext(ctx, query, userID, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list memberships: %w", err)
	}
	defer rows.Close()

	return scanMembershipsWithDetails(rows)
}

func (d *DB) ListGroupMembers(ctx context.Context, groupID string) ([]*rbac.UserMembership, error) {
	query := `SELECT id, user_id, group_id, source, zk_credential_ref, expires_at, created_at, updated_at
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
	var zkCredRef sql.NullString
	var expiresAt sql.NullTime

	err := row.Scan(
		&membership.ID, &membership.UserID, &membership.GroupID,
		&membership.Source, &zkCredRef, &expiresAt,
		&membership.CreatedAt, &membership.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan membership: %w", err)
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
		var zkCredRef sql.NullString
		var expiresAt sql.NullTime

		if err := rows.Scan(
			&membership.ID, &membership.UserID, &membership.GroupID,
			&membership.Source, &zkCredRef, &expiresAt,
			&membership.CreatedAt, &membership.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}

		if zkCredRef.Valid {
			membership.ZKCredentialRef = zkCredRef.String
		}
		if expiresAt.Valid {
			membership.ExpiresAt = &expiresAt.Time
		}

		memberships = append(memberships, membership)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating memberships: %w", err)
	}

	return memberships, nil
}

func scanMembershipsWithDetails(rows *sql.Rows) ([]*rbac.MembershipWithDetails, error) {
	var results []*rbac.MembershipWithDetails
	for rows.Next() {
		result := &rbac.MembershipWithDetails{
			Membership: &rbac.UserMembership{},
			Group:      &rbac.Group{},
		}

		var zkCredRef sql.NullString
		var expiresAt sql.NullTime
		var groupParentID, groupDescription sql.NullString

		if err := rows.Scan(
			&result.Membership.ID, &result.Membership.UserID, &result.Membership.GroupID,
			&result.Membership.Source, &zkCredRef, &expiresAt,
			&result.Membership.CreatedAt, &result.Membership.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &groupParentID, &result.Group.Slug,
			&result.Group.Name, &groupDescription, &result.Group.Depth, &result.Group.Path, &result.Group.IsOrgAdmin,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
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
		if groupDescription.Valid {
			result.Group.Description = groupDescription.String
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating memberships: %w", err)
	}

	return results, nil
}
