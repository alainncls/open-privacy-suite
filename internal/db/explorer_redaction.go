package db

import (
	"context"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/disclosure"
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
		FROM address_links 
		WHERE LOWER(eth_address) = ANY($1) 
		  AND deleted_at IS NULL`

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

	if len(targetDIDs) == 0 || viewerDID == "" {
		// Nothing more to check (or viewer is anonymous and can only see public addresses)
		return result, nil
	}

	// 4. Check active grants in bulk
	queryGrants := `
		SELECT u.external_id, g.scope
		FROM disclosure_grants g
		JOIN disclosure_requests r ON g.request_id = r.id
		JOIN users u ON r.target_user_id = u.id
		WHERE r.requester_did = $1
		  AND u.external_id = ANY($2)
		  AND g.revoked_at IS NULL 
		  AND g.expires_at > NOW()`

	grantRows, err := d.conn.QueryContext(ctx, queryGrants, viewerDID, pq.Array(targetDIDs))
	if err != nil {
		return nil, err
	}
	defer grantRows.Close()

	for grantRows.Next() {
		var targetDID string
		var scopeBytes []byte
		if err := grantRows.Scan(&targetDID, &scopeBytes); err != nil {
			return nil, err
		}

		// Use the greatest disclosure level if there are multiple grants (though query shouldn't usually yield dupes with same target)
		var scope disclosure.Scope
		if err := json.Unmarshal(scopeBytes, &scope); err != nil {
			continue // skip invalid scope
		}

		level := explorer.VisibilityFull
		switch scope.DisclosureLevel {
		case disclosure.DisclosurePseudonymous:
			level = explorer.VisibilityPseudonymous
		case disclosure.DisclosureRedacted:
			level = explorer.VisibilityRedacted
		case disclosure.DisclosureFull, "":
			level = explorer.VisibilityFull
		default:
			level = explorer.VisibilityRedacted // Fail-safe
		}

		// Apply the resolved level to all addresses owned by this DID
		for _, addr := range didToAddresses[targetDID] {
			// Only update if it's better than currently hiding it (which is the default)
			// (Or more precisely, just blindly set it since we know it was hidden before this block)
			result[addr] = level
		}
	}

	return result, nil
}
