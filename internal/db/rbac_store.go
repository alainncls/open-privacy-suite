package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Ensure DB implements rbac.Store
var _ rbac.Store = (*DB)(nil)

// nullStringPtr converts a sql.NullString to a pointer to string, or nil if null.
func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

// nullTimePtr converts a sql.NullTime to a pointer to time.Time, or nil if null.
func nullTimePtr(ns sql.NullTime) *time.Time {
	if ns.Valid {
		return &ns.Time
	}
	return nil
}

// nullIntPtr converts a sql.NullInt32 to a pointer to int, or nil if null.
func nullIntPtr(ns sql.NullInt32) *int {
	if ns.Valid {
		val := int(ns.Int32)
		return &val
	}
	return nil
}

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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating organizations: %w", err)
	}

	return orgs, nil
}

func (d *DB) DeleteOrganization(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

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
	query := `INSERT INTO group_access (id, group_id, allowed_methods, default_claims, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.DefaultClaims))
	for i, c := range access.DefaultClaims {
		claims[i] = string(c)
	}

	return d.conn.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RateLimitRPS, access.RateLimitDaily,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

func (d *DB) GetGroupAccess(ctx context.Context, groupID string) (*rbac.GroupAccess, error) {
	query := `SELECT id, group_id, allowed_methods, default_claims, rate_limit_rps, rate_limit_daily, created_at, updated_at
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
	access.DefaultClaims = make([]rbac.Claim, len(defaultClaims))
	for i, c := range defaultClaims {
		access.DefaultClaims[i] = rbac.Claim(c)
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
	query := `INSERT INTO group_access (id, group_id, allowed_methods, default_claims, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          ON CONFLICT (group_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          default_claims = EXCLUDED.default_claims,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          updated_at = CURRENT_TIMESTAMP
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.DefaultClaims))
	for i, c := range access.DefaultClaims {
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

// Contract operations

func (d *DB) CreateContract(ctx context.Context, contract *rbac.Contract) error {
	query := `INSERT INTO contracts (id, org_id, address, name, deployed_by_user_id, deployed_at, metadata)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	metadata, _ := json.Marshal(contract.Metadata)

	return d.conn.QueryRowContext(ctx, query,
		contract.ID, contract.OrgID, strings.ToLower(contract.Address), contract.Name,
		contract.DeployedByUserID, contract.DeployedAt, metadata,
	).Scan(&contract.CreatedAt, &contract.UpdatedAt)
}

func (d *DB) GetContract(ctx context.Context, id string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE id = $1`

	return scanContract(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetContractByAddress(ctx context.Context, orgID, address string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE org_id = $1 AND lower(address) = $2`

	return scanContract(d.conn.QueryRowContext(ctx, query, orgID, strings.ToLower(address)))
}

func (d *DB) UpdateContract(ctx context.Context, contract *rbac.Contract) error {
	query := `UPDATE contracts SET name = $2, metadata = $3, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	metadata, _ := json.Marshal(contract.Metadata)

	_, err := d.conn.ExecContext(ctx, query, contract.ID, contract.Name, metadata)
	return err
}

func (d *DB) ListContracts(ctx context.Context, orgID string) ([]*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE org_id = $1 ORDER BY created_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contracts: %w", err)
	}
	defer rows.Close()

	return scanContracts(rows)
}

func (d *DB) DeleteContract(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM contracts WHERE id = $1`, id)
	return err
}

func scanContract(row *sql.Row) (*rbac.Contract, error) {
	contract := &rbac.Contract{}
	var name sql.NullString
	var deployedByUserID sql.NullString
	var deployedAt sql.NullTime
	var metadata []byte

	err := row.Scan(
		&contract.ID, &contract.OrgID, &contract.Address, &name,
		&deployedByUserID, &deployedAt, &metadata,
		&contract.CreatedAt, &contract.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract: %w", err)
	}

	if name.Valid {
		contract.Name = name.String
	}
	if deployedByUserID.Valid {
		contract.DeployedByUserID = &deployedByUserID.String
	}
	if deployedAt.Valid {
		contract.DeployedAt = &deployedAt.Time
	}

	if err := json.Unmarshal(metadata, &contract.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return contract, nil
}

func scanContracts(rows *sql.Rows) ([]*rbac.Contract, error) {
	var contracts []*rbac.Contract
	for rows.Next() {
		contract := &rbac.Contract{}
		var name sql.NullString
		var deployedByUserID sql.NullString
		var deployedAt sql.NullTime
		var metadata []byte

		if err := rows.Scan(
			&contract.ID, &contract.OrgID, &contract.Address, &name,
			&deployedByUserID, &deployedAt, &metadata,
			&contract.CreatedAt, &contract.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract: %w", err)
		}

		if name.Valid {
			contract.Name = name.String
		}
		if deployedByUserID.Valid {
			contract.DeployedByUserID = &deployedByUserID.String
		}
		if deployedAt.Valid {
			contract.DeployedAt = &deployedAt.Time
		}

		if err := json.Unmarshal(metadata, &contract.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		contracts = append(contracts, contract)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contracts: %w", err)
	}

	return contracts, nil
}

// Contract Grant operations

func (d *DB) CreateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `INSERT INTO contract_grants (id, contract_id, group_id, claims, functions)
	          VALUES ($1, $2, $3, $4, $5)
	          RETURNING created_at, updated_at`

	claims := make([]string, len(grant.Claims))
	for i, c := range grant.Claims {
		claims[i] = string(c)
	}

	var functions interface{}
	if grant.Functions != nil {
		functions = pq.Array(grant.Functions)
	}

	return d.conn.QueryRowContext(ctx, query,
		grant.ID, grant.ContractID, grant.GroupID,
		pq.Array(claims), functions,
	).Scan(&grant.CreatedAt, &grant.UpdatedAt)
}

func (d *DB) GetContractGrant(ctx context.Context, id string) (*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, claims, functions, created_at, updated_at
	          FROM contract_grants WHERE id = $1`

	return scanContractGrant(d.conn.QueryRowContext(ctx, query, id))
}

func (d *DB) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, claims, functions, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 AND group_id = $2`

	return scanContractGrant(d.conn.QueryRowContext(ctx, query, contractID, groupID))
}

func (d *DB) UpdateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `UPDATE contract_grants SET claims = $2, functions = $3, updated_at = CURRENT_TIMESTAMP
	          WHERE id = $1`

	claims := make([]string, len(grant.Claims))
	for i, c := range grant.Claims {
		claims[i] = string(c)
	}

	var functions interface{}
	if grant.Functions != nil {
		functions = pq.Array(grant.Functions)
	}

	_, err := d.conn.ExecContext(ctx, query, grant.ID, pq.Array(claims), functions)
	return err
}

func (d *DB) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, claims, functions, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 ORDER BY created_at`

	rows, err := d.conn.QueryContext(ctx, query, contractID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants: %w", err)
	}
	defer rows.Close()

	return scanContractGrants(rows)
}

func (d *DB) ListContractGrantsByGroup(ctx context.Context, groupID string) ([]*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, claims, functions, created_at, updated_at
	          FROM contract_grants WHERE group_id = $1 ORDER BY created_at`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants: %w", err)
	}
	defer rows.Close()

	return scanContractGrants(rows)
}

func (d *DB) ListContractGrantsByGroupWithContract(ctx context.Context, groupID string) ([]*rbac.ContractGrantWithGroup, error) {
	query := `SELECT cg.id, cg.contract_id, cg.group_id, cg.claims, cg.functions, cg.created_at, cg.updated_at,
	                 g.id, g.org_id, g.parent_id, g.slug, g.name, g.description, g.depth, g.path, g.is_org_admin, g.created_at, g.updated_at
	          FROM contract_grants cg
	          JOIN groups g ON cg.group_id = g.id
	          WHERE cg.group_id = $1 ORDER BY cg.created_at`

	rows, err := d.conn.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants with group: %w", err)
	}
	defer rows.Close()

	var results []*rbac.ContractGrantWithGroup
	for rows.Next() {
		result := &rbac.ContractGrantWithGroup{
			Grant: &rbac.ContractGrant{},
			Group: &rbac.Group{},
		}

		var claims, functions pq.StringArray
		var parentID, description sql.NullString

		if err := rows.Scan(
			&result.Grant.ID, &result.Grant.ContractID, &result.Grant.GroupID,
			&claims, &functions, &result.Grant.CreatedAt, &result.Grant.UpdatedAt,
			&result.Group.ID, &result.Group.OrgID, &parentID, &result.Group.Slug,
			&result.Group.Name, &description, &result.Group.Depth, &result.Group.Path, &result.Group.IsOrgAdmin,
			&result.Group.CreatedAt, &result.Group.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract grant with group: %w", err)
		}

		result.Grant.Claims = make([]rbac.Claim, len(claims))
		for i, c := range claims {
			result.Grant.Claims[i] = rbac.Claim(c)
		}
		if len(functions) > 0 {
			result.Grant.Functions = functions
		}
		if parentID.Valid {
			result.Group.ParentID = &parentID.String
		}
		if description.Valid {
			result.Group.Description = description.String
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contract grants: %w", err)
	}

	return results, nil
}

func (d *DB) DeleteContractGrant(ctx context.Context, id string) error {
	_, err := d.conn.ExecContext(ctx, `DELETE FROM contract_grants WHERE id = $1`, id)
	return err
}

func scanContractGrant(row *sql.Row) (*rbac.ContractGrant, error) {
	grant := &rbac.ContractGrant{}
	var claims, functions pq.StringArray

	err := row.Scan(
		&grant.ID, &grant.ContractID, &grant.GroupID,
		&claims, &functions, &grant.CreatedAt, &grant.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract grant: %w", err)
	}

	grant.Claims = make([]rbac.Claim, len(claims))
	for i, c := range claims {
		grant.Claims[i] = rbac.Claim(c)
	}
	if len(functions) > 0 {
		grant.Functions = functions
	}

	return grant, nil
}

func scanContractGrants(rows *sql.Rows) ([]*rbac.ContractGrant, error) {
	var grants []*rbac.ContractGrant
	for rows.Next() {
		grant := &rbac.ContractGrant{}
		var claims, functions pq.StringArray

		if err := rows.Scan(
			&grant.ID, &grant.ContractID, &grant.GroupID,
			&claims, &functions, &grant.CreatedAt, &grant.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan contract grant: %w", err)
		}

		grant.Claims = make([]rbac.Claim, len(claims))
		for i, c := range claims {
			grant.Claims[i] = rbac.Claim(c)
		}
		if len(functions) > 0 {
			grant.Functions = functions
		}

		grants = append(grants, grant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contract grants: %w", err)
	}

	return grants, nil
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
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

// Effective Permissions Cache operations

func (d *DB) GetCachedPermissions(ctx context.Context, userID, orgID string) (*rbac.EffectivePermissions, error) {
	query := `SELECT id, user_id, org_id, allowed_methods, contract_access, default_claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at
	          FROM effective_permissions_cache WHERE user_id = $1 AND org_id = $2 AND expires_at > $3`

	perms := &rbac.EffectivePermissions{}
	var allowedMethods, defaultClaims pq.StringArray
	var contractAccess []byte
	var rateLimitRPS, rateLimitDaily sql.NullInt32

	err := d.conn.QueryRowContext(ctx, query, userID, orgID, time.Now()).Scan(
		&perms.ID, &perms.UserID, &perms.OrgID,
		&allowedMethods, &contractAccess, &defaultClaims,
		&rateLimitRPS, &rateLimitDaily, &perms.ComputedAt, &perms.ExpiresAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get cached permissions: %w", err)
	}

	perms.AllowedMethods = allowedMethods
	perms.DefaultClaims = make([]rbac.Claim, len(defaultClaims))
	for i, c := range defaultClaims {
		perms.DefaultClaims[i] = rbac.Claim(c)
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
	query := `INSERT INTO effective_permissions_cache (id, user_id, org_id, allowed_methods, contract_access, default_claims, rate_limit_rps, rate_limit_daily, computed_at, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	          ON CONFLICT (user_id, org_id) DO UPDATE SET
	          allowed_methods = EXCLUDED.allowed_methods,
	          contract_access = EXCLUDED.contract_access,
	          default_claims = EXCLUDED.default_claims,
	          rate_limit_rps = EXCLUDED.rate_limit_rps,
	          rate_limit_daily = EXCLUDED.rate_limit_daily,
	          computed_at = EXCLUDED.computed_at,
	          expires_at = EXCLUDED.expires_at`

	defaultClaims := make([]string, len(perms.DefaultClaims))
	for i, c := range perms.DefaultClaims {
		defaultClaims[i] = string(c)
	}

	contractAccess, _ := json.Marshal(perms.ContractAccess)

	_, err := d.conn.ExecContext(ctx, query,
		perms.ID, perms.UserID, perms.OrgID,
		pq.Array(perms.AllowedMethods), contractAccess, pq.Array(defaultClaims),
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

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return entries, nil
}

// Alias methods for convenience

// SetGroupAccess creates or updates group access settings (alias for UpdateGroupAccess).
func (d *DB) SetGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	return d.UpdateGroupAccess(ctx, access)
}

// ListContractGrants lists grants for a contract (alias for ListContractGrantsByContract).
func (d *DB) ListContractGrants(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByContract(ctx, contractID)
}

// ListContractGrantsForGroup lists grants for a group (alias for ListContractGrantsByGroup).
func (d *DB) ListContractGrantsForGroup(ctx context.Context, groupID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByGroup(ctx, groupID)
}
