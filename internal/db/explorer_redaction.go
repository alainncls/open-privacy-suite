package db

import (
	"context"
	"strings"

	"privacy-proxy/internal/explorer"

	"github.com/lib/pq"
)

// GetBatchVisibility resolves visibility rules for a list of addresses efficiently.
// It replaces N+1 queries by looking up all address owners and their grants in bulk.
func (d *DB) GetBatchVisibility(ctx context.Context, viewerDID string, addresses []string) (explorer.VisibilityMap, error) {
	result := make(explorer.VisibilityMap)
	if len(addresses) == 0 {
		return result, nil
	}

	// 1. Deduplicate and normalize addresses
	addrSet := make(map[string]bool)
	for _, a := range addresses {
		addrSet[strings.ToLower(a)] = true
	}
	var uniqueAddrs []string
	for a := range addrSet {
		uniqueAddrs = append(uniqueAddrs, a)
		// Default to hidden
		result[a] = explorer.VisibilityHidden
	}

	// 2. Look up owners for all unique addresses
	queryOwners := `
		SELECT LOWER(eth_address), did
		FROM eth_address_links
		WHERE LOWER(eth_address) = ANY($1)
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, queryOwners, pq.Array(uniqueAddrs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	addressOwners := make(map[string]string)
	for rows.Next() {
		var addr, did string
		if err := rows.Scan(&addr, &did); err != nil {
			return nil, err
		}
		addressOwners[addr] = did
	}

	// 3. Process first pass: Public addresses and Own addresses
	var targetDIDs []string
	didToAddresses := make(map[string][]string)

	for _, addr := range uniqueAddrs {
		ownerDID, hasOwner := addressOwners[addr]

		if !hasOwner {
			// Public address (no owner)
			result[addr] = explorer.VisibilityFull
			continue
		}

		if ownerDID == viewerDID && viewerDID != "" {
			// Own address
			result[addr] = explorer.VisibilityFull
			continue
		}

		// Otherwise, it belongs to someone else. We need to check grants.
		targetDIDs = append(targetDIDs, ownerDID)
		didToAddresses[ownerDID] = append(didToAddresses[ownerDID], addr)
	}

	// 4. Org contract visibility check
	// Collect addresses that were marked VisibilityFull due to no eth_address_links owner.
	// These might be org-owned contracts, which should be hidden to non-members.
	var publicAddrs []string
	for _, addr := range uniqueAddrs {
		if _, hasOwner := addressOwners[addr]; !hasOwner {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) > 0 {
		// Step 1: Find ALL org-owned contracts and default them to VisibilityRedacted.
		// This is separate from admin group lookup — a contract is private regardless
		// of whether any admin groups exist.
		orgContractDetect := `
			SELECT LOWER(c.address) FROM contracts c
			WHERE LOWER(c.address) = ANY($1)`
		orgDetectRows, err := d.conn.QueryContext(ctx, orgContractDetect, pq.Array(publicAddrs))
		if err != nil {
			return nil, err
		}
		defer orgDetectRows.Close()

		var orgContractAddrs []string
		for orgDetectRows.Next() {
			var addr string
			if err := orgDetectRows.Scan(&addr); err != nil {
				return nil, err
			}
			result[addr] = explorer.VisibilityRedacted
			orgContractAddrs = append(orgContractAddrs, addr)
		}

		// Step 2: For authenticated viewers, check if they have admin-level access
		// to any of these contracts. Admin = is_org_admin group OR 'admin' claim in
		// contract_grants OR 'admin' claim in group_access (when group has a grant on
		// the contract). The group_access.claims check aligns explorer visibility with
		// the RPC layer, where admin claim is typically set via group_access (G11 fix).
		if viewerDID != "" && len(orgContractAddrs) > 0 {
			adminGroupQuery := `
				SELECT LOWER(c.address) AS addr, g.id AS group_id
				FROM contracts c
				JOIN groups g ON g.org_id = c.org_id
				LEFT JOIN contract_grants cg ON cg.contract_id = c.id AND cg.group_id = g.id
				LEFT JOIN group_access ga ON ga.group_id = g.id
				WHERE LOWER(c.address) = ANY($1)
				  AND (g.is_org_admin = true
				       OR 'admin' = ANY(cg.claims)
				       OR (cg.id IS NOT NULL AND 'admin' = ANY(ga.claims)))`

			orgRows, err := d.conn.QueryContext(ctx, adminGroupQuery, pq.Array(orgContractAddrs))
			if err != nil {
				return nil, err
			}
			defer orgRows.Close()

			// Map: address -> set of admin group_ids
			contractGroupIDs := make(map[string]map[string]bool)
			for orgRows.Next() {
				var addr, groupID string
				if err := orgRows.Scan(&addr, &groupID); err != nil {
					return nil, err
				}
				if contractGroupIDs[addr] == nil {
					contractGroupIDs[addr] = make(map[string]bool)
				}
				contractGroupIDs[addr][groupID] = true
			}

			if len(contractGroupIDs) > 0 {
				allGroupIDs := make(map[string]bool)
				for _, groups := range contractGroupIDs {
					for gid := range groups {
						allGroupIDs[gid] = true
					}
				}
				groupIDSlice := make([]string, 0, len(allGroupIDs))
				for gid := range allGroupIDs {
					groupIDSlice = append(groupIDSlice, gid)
				}

				memberQuery := `
					SELECT DISTINCT m.group_id
					FROM user_memberships m
					JOIN users u ON u.id = m.user_id
					WHERE u.external_id = $1
					  AND m.group_id = ANY($2)
					  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

				memberRows, err := d.conn.QueryContext(ctx, memberQuery, viewerDID, pq.Array(groupIDSlice))
				if err != nil {
					return nil, err
				}
				defer memberRows.Close()

				viewerGroups := make(map[string]bool)
				for memberRows.Next() {
					var gid string
					if err := memberRows.Scan(&gid); err != nil {
						return nil, err
					}
					viewerGroups[gid] = true
				}

				// Upgrade to VisibilityFull only for contracts where viewer is in an admin group
				for addr, groups := range contractGroupIDs {
					for gid := range groups {
						if viewerGroups[gid] {
							result[addr] = explorer.VisibilityFull
							break
						}
					}
				}
			}
		}
	}

	// NOTE: Disclosure grants are intentionally NOT checked here.
	// Grants only affect the dedicated grant endpoint (/grant/{id}/{addr_id}/transactions),
	// not the general explorer views. This prevents grants from leaking disclosed address
	// visibility into block pages, tx lists, and other explorer views.
	// See GetBatchVisibilityDetailed for the grant-aware version (used by privacy dashboard).

	return result, nil
}

// GetBatchVisibilityDetailed resolves visibility for a list of addresses, returning
// full AddressVisibility results including reason, pseudonym, and grant metadata.
// This uses the same logic as GetBatchVisibility (which the redactor depends on)
// but captures extra information needed by the API layer.
func (d *DB) GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]explorer.AddressVisibility, error) {
	result := make(map[string]explorer.AddressVisibility)
	if len(addresses) == 0 {
		return result, nil
	}

	// 1. Deduplicate and normalize addresses
	addrSet := make(map[string]bool)
	for _, a := range addresses {
		addrSet[strings.ToLower(a)] = true
	}
	var uniqueAddrs []string
	for a := range addrSet {
		uniqueAddrs = append(uniqueAddrs, a)
		// Default to hidden
		result[a] = explorer.AddressVisibility{
			Address: a,
			Visible: false,
			Level:   explorer.VisibilityHidden,
			Reason:  explorer.ReasonNoAccess,
		}
	}

	// 2. Look up owners for all unique addresses
	queryOwners := `
		SELECT LOWER(eth_address), did
		FROM eth_address_links
		WHERE LOWER(eth_address) = ANY($1)
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, queryOwners, pq.Array(uniqueAddrs))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	addressOwners := make(map[string]string)
	for rows.Next() {
		var addr, did string
		if err := rows.Scan(&addr, &did); err != nil {
			return nil, err
		}
		addressOwners[addr] = did
	}

	// 3. Process first pass: Public addresses and Own addresses
	var targetDIDs []string
	didToAddresses := make(map[string][]string)

	for _, addr := range uniqueAddrs {
		ownerDID, hasOwner := addressOwners[addr]

		if !hasOwner {
			// Public address (no owner) — may be overridden by org contract check below
			result[addr] = explorer.AddressVisibility{
				Address: addr,
				Visible: true,
				Level:   explorer.VisibilityFull,
				Reason:  explorer.ReasonPublicAddress,
			}
			continue
		}

		if ownerDID == viewerDID && viewerDID != "" {
			// Own address
			result[addr] = explorer.AddressVisibility{
				Address: addr,
				Visible: true,
				Level:   explorer.VisibilityFull,
				Reason:  explorer.ReasonOwnAddress,
			}
			continue
		}

		// Otherwise, it belongs to someone else. We need to check grants.
		targetDIDs = append(targetDIDs, ownerDID)
		didToAddresses[ownerDID] = append(didToAddresses[ownerDID], addr)
	}

	// 4. Org contract visibility check
	var publicAddrs []string
	for _, addr := range uniqueAddrs {
		if _, hasOwner := addressOwners[addr]; !hasOwner {
			publicAddrs = append(publicAddrs, addr)
		}
	}

	if len(publicAddrs) > 0 {
		orgContractQuery := `
			SELECT LOWER(c.address) AS addr, cg.group_id
			FROM contracts c
			JOIN contract_grants cg ON cg.contract_id = c.id
			WHERE LOWER(c.address) = ANY($1)`

		orgRows, err := d.conn.QueryContext(ctx, orgContractQuery, pq.Array(publicAddrs))
		if err != nil {
			return nil, err
		}
		defer orgRows.Close()

		contractGroupIDs := make(map[string]map[string]bool)
		for orgRows.Next() {
			var addr, groupID string
			if err := orgRows.Scan(&addr, &groupID); err != nil {
				return nil, err
			}
			if contractGroupIDs[addr] == nil {
				contractGroupIDs[addr] = make(map[string]bool)
			}
			contractGroupIDs[addr][groupID] = true
		}

		if len(contractGroupIDs) > 0 {
			// Default org-owned contracts to VisibilityRedacted, matching GetBatchVisibility behavior.
			for addr := range contractGroupIDs {
				result[addr] = explorer.AddressVisibility{
					Address: addr,
					Visible: false,
					Level:   explorer.VisibilityRedacted,
					Reason:  explorer.ReasonNoAccess,
				}
			}

			if viewerDID != "" {
				allGroupIDs := make(map[string]bool)
				for _, groups := range contractGroupIDs {
					for gid := range groups {
						allGroupIDs[gid] = true
					}
				}
				groupIDSlice := make([]string, 0, len(allGroupIDs))
				for gid := range allGroupIDs {
					groupIDSlice = append(groupIDSlice, gid)
				}

				memberQuery := `
					SELECT DISTINCT m.group_id
					FROM user_memberships m
					JOIN users u ON u.id = m.user_id
					WHERE u.external_id = $1
					  AND m.group_id = ANY($2)
					  AND (m.expires_at IS NULL OR m.expires_at > NOW())`

				memberRows, err := d.conn.QueryContext(ctx, memberQuery, viewerDID, pq.Array(groupIDSlice))
				if err != nil {
					return nil, err
				}
				defer memberRows.Close()

				viewerGroups := make(map[string]bool)
				for memberRows.Next() {
					var gid string
					if err := memberRows.Scan(&gid); err != nil {
						return nil, err
					}
					viewerGroups[gid] = true
				}

				for addr, groups := range contractGroupIDs {
					for gid := range groups {
						if viewerGroups[gid] {
							result[addr] = explorer.AddressVisibility{
								Address: addr,
								Visible: true,
								Level:   explorer.VisibilityFull,
								Reason:  explorer.ReasonRBACGroupMember,
							}
							break
						}
					}
				}
			}
		}
	}

	// NOTE: Disclosure grants are intentionally NOT checked here (G17).
	// Per REDACTION_SPEC.md: "GetBatchVisibilityDetailed retains grant metadata
	// but no longer upgrades visibility level." The check-address endpoint must not
	// reveal grant existence — that would create a new oracle (attacker learns which
	// addresses have grants). The privacy dashboard discovers grants via the
	// viewable-addresses endpoint, not check-address.

	return result, nil
}

// GetLinkedAddresses returns the lowercase ETH addresses linked to a DID.
func (d *DB) GetLinkedAddresses(ctx context.Context, did string) ([]string, error) {
	if did == "" {
		return nil, nil
	}

	query := `
		SELECT LOWER(eth_address)
		FROM eth_address_links
		WHERE did = $1
		  AND revoked = false`

	rows, err := d.conn.QueryContext(ctx, query, did)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, rows.Err()
}
