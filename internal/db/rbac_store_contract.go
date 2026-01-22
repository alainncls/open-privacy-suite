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

func (d *DB) GetContractsByIDs(ctx context.Context, ids []string) (map[string]*rbac.Contract, error) {
	if len(ids) == 0 {
		return make(map[string]*rbac.Contract), nil
	}

	query := `SELECT id, org_id, address, name, deployed_by_user_id, deployed_at, metadata, created_at, updated_at
	          FROM contracts WHERE id = ANY($1)`

	rows, err := d.conn.QueryContext(ctx, query, pq.Array(ids))
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

	var functions any
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

	var functions any
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

// ListContractGrants lists grants for a contract (alias for ListContractGrantsByContract).
func (d *DB) ListContractGrants(ctx context.Context, contractID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByContract(ctx, contractID)
}

// ListContractGrantsForGroup lists grants for a group (alias for ListContractGrantsByGroup).
func (d *DB) ListContractGrantsForGroup(ctx context.Context, groupID string) ([]*rbac.ContractGrant, error) {
	return d.ListContractGrantsByGroup(ctx, groupID)
}
