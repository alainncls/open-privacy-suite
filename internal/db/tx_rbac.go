package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"privacy-proxy/internal/rbac"

	"github.com/lib/pq"
)

// Contract operations on transaction

func (t *Tx) CreateContract(ctx context.Context, contract *rbac.Contract) error {
	query := `INSERT INTO contracts (id, org_id, address, name, deployed_by_user_id, deployed_at, metadata)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	metadata, _ := json.Marshal(contract.Metadata)

	return t.tx.QueryRowContext(ctx, query,
		contract.ID, contract.OrgID, strings.ToLower(contract.Address), contract.Name,
		contract.DeployedByUserID, contract.DeployedAt, metadata,
	).Scan(&contract.CreatedAt, &contract.UpdatedAt)
}

func (t *Tx) GetContract(ctx context.Context, id string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE id = $1`

	return scanContractRow(t.tx.QueryRowContext(ctx, query, id))
}

func (t *Tx) GetContractByAddress(ctx context.Context, orgID, address string) (*rbac.Contract, error) {
	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE org_id = $1 AND lower(address) = $2`

	return scanContractRow(t.tx.QueryRowContext(ctx, query, orgID, strings.ToLower(address)))
}

func (t *Tx) DeleteContract(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM contracts WHERE id = $1`, id)
	return err
}

// GetContractDeployerByAddress returns the user ID that deployed a contract at the given address.
// Returns nil if the contract is not found or has no deployer recorded.
func (t *Tx) GetContractDeployerByAddress(ctx context.Context, address string) (*string, error) {
	query := `SELECT deployed_by_user_id FROM contracts WHERE LOWER(address) = LOWER($1)`
	var deployerID sql.NullString
	err := t.tx.QueryRowContext(ctx, query, address).Scan(&deployerID)
	if err == sql.ErrNoRows {
		return nil, nil // Contract not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get contract deployer: %w", err)
	}
	if !deployerID.Valid {
		return nil, nil // No deployer recorded
	}
	return &deployerID.String, nil
}

func (t *Tx) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*rbac.Contract, error) {
	if len(ids) == 0 {
		return make(map[string]*rbac.Contract), nil
	}

	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE id = ANY($1)`

	rows, err := t.tx.QueryContext(ctx, query, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to get contracts by IDs: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*rbac.Contract)
	for rows.Next() {
		contract := &rbac.Contract{}
		var name sql.NullString
		var deployedByUserID sql.NullString
		var deployedAt sql.NullTime
		var metadata []byte

		err := rows.Scan(
			&contract.ID, &contract.OrgID, &contract.Address, &name,
			&deployedByUserID, &deployedAt, &metadata,
			&contract.CreatedAt, &contract.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan contract: %w", err)
		}

		contract.Name = name.String
		if deployedByUserID.Valid {
			contract.DeployedByUserID = &deployedByUserID.String
		}
		if deployedAt.Valid {
			contract.DeployedAt = &deployedAt.Time
		}
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &contract.Metadata)
		}

		result[contract.ID] = contract
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating contracts: %w", err)
	}

	return result, nil
}

// Contract Grant operations on transaction

func (t *Tx) CreateContractGrant(ctx context.Context, grant *rbac.ContractGrant) error {
	query := `INSERT INTO contract_grants (id, contract_id, group_id, functions)
	          VALUES ($1, $2, $3, $4)
	          RETURNING created_at, updated_at`

	var functions any
	if grant.Functions != nil {
		b, err := json.Marshal(grant.Functions)
		if err != nil {
			return fmt.Errorf("failed to marshal functions: %w", err)
		}
		functions = b
	}

	return t.tx.QueryRowContext(ctx, query,
		grant.ID, grant.ContractID, grant.GroupID, functions,
	).Scan(&grant.CreatedAt, &grant.UpdatedAt)
}

func (t *Tx) GetContractGrantByContractAndGroup(ctx context.Context, contractID, groupID string) (*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 AND group_id = $2`

	return scanContractGrantRow(t.tx.QueryRowContext(ctx, query, contractID, groupID))
}

func (t *Tx) ListContractGrantsByContract(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	query := `SELECT id, contract_id, group_id, functions, created_at, updated_at
	          FROM contract_grants WHERE contract_id = $1 ORDER BY created_at`

	rows, err := t.tx.QueryContext(ctx, query, contractID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contract grants: %w", err)
	}
	defer rows.Close()

	return scanContractGrants(rows)
}

func (t *Tx) DeleteContractGrant(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM contract_grants WHERE id = $1`, id)
	return err
}

func (t *Tx) DeleteContractGrantsByContract(ctx context.Context, contractID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM contract_grants WHERE contract_id = $1`, contractID)
	return err
}

// Group operations on transaction

func (t *Tx) CreateGroup(ctx context.Context, group *rbac.Group) error {
	query := `INSERT INTO groups (id, org_id, parent_id, slug, name, description, depth, path, is_org_admin)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	          RETURNING created_at, updated_at`

	return t.tx.QueryRowContext(ctx, query,
		group.ID, group.OrgID, group.ParentID, group.Slug, group.Name,
		group.Description, group.Depth, group.Path, group.IsOrgAdmin,
	).Scan(&group.CreatedAt, &group.UpdatedAt)
}

func (t *Tx) GetGroup(ctx context.Context, id string) (*rbac.Group, error) {
	query := `SELECT id, org_id, parent_id, slug, name, description, depth, path, is_org_admin, created_at, updated_at
	          FROM groups WHERE id = $1`

	group := &rbac.Group{}
	var parentID sql.NullString
	var description sql.NullString

	err := t.tx.QueryRowContext(ctx, query, id).Scan(
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

func (t *Tx) DeleteGroup(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM groups WHERE id = $1`, id)
	return err
}

// Group Access operations on transaction

func (t *Tx) CreateGroupAccess(ctx context.Context, access *rbac.GroupAccess) error {
	query := `INSERT INTO group_access (id, group_id, allowed_methods, claims, rate_limit_rps, rate_limit_daily)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	claims := make([]string, len(access.Claims))
	for i, c := range access.Claims {
		claims[i] = string(c)
	}

	return t.tx.QueryRowContext(ctx, query,
		access.ID, access.GroupID,
		pq.Array(access.AllowedMethods), pq.Array(claims),
		access.RateLimitRPS, access.RateLimitDaily,
	).Scan(&access.CreatedAt, &access.UpdatedAt)
}

func (t *Tx) DeleteGroupAccess(ctx context.Context, groupID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM group_access WHERE group_id = $1`, groupID)
	return err
}

// Membership operations on transaction

func (t *Tx) CreateMembership(ctx context.Context, membership *rbac.UserMembership) error {
	query := `INSERT INTO user_memberships (id, user_id, group_id, source, zk_credential_ref, expires_at)
	          VALUES ($1, $2, $3, $4, $5, $6)
	          RETURNING created_at, updated_at`

	return t.tx.QueryRowContext(ctx, query,
		membership.ID, membership.UserID, membership.GroupID,
		string(membership.Source), membership.ZKCredentialRef, membership.ExpiresAt,
	).Scan(&membership.CreatedAt, &membership.UpdatedAt)
}

func (t *Tx) DeleteMembership(ctx context.Context, id string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM user_memberships WHERE id = $1`, id)
	return err
}

func (t *Tx) DeleteMembershipsByGroup(ctx context.Context, groupID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM user_memberships WHERE group_id = $1`, groupID)
	return err
}

// User operations on transaction

func (t *Tx) CreateUser(ctx context.Context, user *rbac.User) error {
	query := `INSERT INTO users (id, external_id, kyc, banned, note, metadata, auth_tenant_id)
	          VALUES ($1, $2, $3, $4, $5, $6, $7)
	          RETURNING created_at, updated_at`

	metadata, err := json.Marshal(user.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return t.tx.QueryRowContext(ctx, query,
		user.ID, user.ExternalID, user.KYC, user.Banned, user.Note, metadata, user.AuthTenantID,
	).Scan(&user.CreatedAt, &user.UpdatedAt)
}

func (t *Tx) GetUserByExternalID(ctx context.Context, externalID string) (*rbac.User, error) {
	query := `SELECT id, external_id, kyc, banned, note, metadata, auth_tenant_id, created_at, updated_at
	          FROM users WHERE external_id = $1`

	user := &rbac.User{}
	var note sql.NullString
	var metadata []byte

	err := t.tx.QueryRowContext(ctx, query, externalID).Scan(
		&user.ID, &user.ExternalID, &user.KYC, &user.Banned, &note, &metadata, &user.AuthTenantID,
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

// Cache invalidation on transaction

func (t *Tx) InvalidateCacheForGroup(ctx context.Context, groupID string) error {
	query := `DELETE FROM effective_permissions_cache
	          WHERE user_id IN (SELECT user_id FROM user_memberships WHERE group_id = $1)`
	_, err := t.tx.ExecContext(ctx, query, groupID)
	return err
}

func (t *Tx) InvalidateCacheForOrg(ctx context.Context, orgID string) error {
	_, err := t.tx.ExecContext(ctx, `DELETE FROM effective_permissions_cache WHERE org_id = $1`, orgID)
	return err
}

// Helper to scan a contract row (shared between DB and Tx)
func scanContractRow(row *sql.Row) (*rbac.Contract, error) {
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

// Helper to scan a contract grant row (shared between DB and Tx)
func scanContractGrantRow(row *sql.Row) (*rbac.ContractGrant, error) {
	grant := &rbac.ContractGrant{}
	var functionsJSON []byte

	err := row.Scan(
		&grant.ID, &grant.ContractID, &grant.GroupID,
		&functionsJSON, &grant.CreatedAt, &grant.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan contract grant: %w", err)
	}

	if len(functionsJSON) > 0 {
		if err := json.Unmarshal(functionsJSON, &grant.Functions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal functions: %w", err)
		}
	}

	return grant, nil
}
