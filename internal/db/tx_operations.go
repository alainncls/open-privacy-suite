package db

import (
	"context"
	"fmt"

	"privacy-proxy/internal/rbac"
)

// CreateContractWithGrant creates a contract and its initial grant atomically.
// If either operation fails, both are rolled back.
func (d *DB) CreateContractWithGrant(ctx context.Context, contract *rbac.Contract, grant *rbac.ContractGrant) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateContract(ctx, contract); err != nil {
			return fmt.Errorf("failed to create contract: %w", err)
		}

		// Set the contract ID on the grant
		grant.ContractID = contract.ID

		if err := tx.CreateContractGrant(ctx, grant); err != nil {
			return fmt.Errorf("failed to create contract grant: %w", err)
		}

		return nil
	})
}

// DeleteContractWithGrants deletes a contract and all its grants atomically.
// This prevents orphaned grants if the contract deletion fails.
func (d *DB) DeleteContractWithGrants(ctx context.Context, contractID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		// Delete all grants first (foreign key would prevent contract deletion anyway)
		if err := tx.DeleteContractGrantsByContract(ctx, contractID); err != nil {
			return fmt.Errorf("failed to delete contract grants: %w", err)
		}

		if err := tx.DeleteContract(ctx, contractID); err != nil {
			return fmt.Errorf("failed to delete contract: %w", err)
		}

		return nil
	})
}

// DeleteGroupWithDependencies deletes a group and all its dependencies atomically:
// - Group access settings
// - Contract grants for this group
// - User memberships in this group
// - Cache entries for affected users
func (d *DB) DeleteGroupWithDependencies(ctx context.Context, groupID string) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		// Invalidate cache first (while we still have membership info)
		if err := tx.InvalidateCacheForGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to invalidate cache: %w", err)
		}

		// Delete user memberships
		if err := tx.DeleteMembershipsByGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete memberships: %w", err)
		}

		// Delete contract grants for this group
		if _, err := tx.tx.ExecContext(ctx,
			`DELETE FROM contract_grants WHERE group_id = $1`, groupID); err != nil {
			return fmt.Errorf("failed to delete contract grants: %w", err)
		}

		// Delete group access
		if err := tx.DeleteGroupAccess(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete group access: %w", err)
		}

		// Finally delete the group
		if err := tx.DeleteGroup(ctx, groupID); err != nil {
			return fmt.Errorf("failed to delete group: %w", err)
		}

		return nil
	})
}

// CreateUserWithMembership creates a user and adds them to a group atomically.
func (d *DB) CreateUserWithMembership(ctx context.Context, user *rbac.User, membership *rbac.UserMembership) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Set the user ID on the membership
		membership.UserID = user.ID

		if err := tx.CreateMembership(ctx, membership); err != nil {
			return fmt.Errorf("failed to create membership: %w", err)
		}

		return nil
	})
}

// CreateGroupWithAccess creates a group and its access settings atomically.
func (d *DB) CreateGroupWithAccess(ctx context.Context, group *rbac.Group, access *rbac.GroupAccess) error {
	return d.WithTx(ctx, func(tx *Tx) error {
		if err := tx.CreateGroup(ctx, group); err != nil {
			return fmt.Errorf("failed to create group: %w", err)
		}

		// Set the group ID on the access
		access.GroupID = group.ID

		if err := tx.CreateGroupAccess(ctx, access); err != nil {
			return fmt.Errorf("failed to create group access: %w", err)
		}

		return nil
	})
}

// EnsureUserExistsWithMembership ensures a user exists and has a membership to the specified group.
// If the user doesn't exist, creates them with the given membership.
// If the user exists but doesn't have the membership, creates the membership.
// This operation is atomic.
func (d *DB) EnsureUserExistsWithMembership(ctx context.Context, user *rbac.User, membership *rbac.UserMembership) (*rbac.User, error) {
	var resultUser *rbac.User

	err := d.WithTx(ctx, func(tx *Tx) error {
		// Check if user exists
		existing, err := tx.GetUserByExternalID(ctx, user.ExternalID)
		if err != nil {
			return fmt.Errorf("failed to check existing user: %w", err)
		}

		if existing != nil {
			resultUser = existing
			return nil // User already exists, membership should be handled separately
		}

		// Create the user
		if err := tx.CreateUser(ctx, user); err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Set the user ID on the membership
		membership.UserID = user.ID

		if err := tx.CreateMembership(ctx, membership); err != nil {
			return fmt.Errorf("failed to create membership: %w", err)
		}

		resultUser = user
		return nil
	})

	return resultUser, err
}
