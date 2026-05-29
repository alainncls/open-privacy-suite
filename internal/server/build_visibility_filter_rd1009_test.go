package server

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// extendedExplorerSchema extends the basic explorerSchema (defined in
// explorer_api_test.go) with the token_transfers table the RD-1009 test needs.
// Kept as a separate string rather than mutating explorerSchema so the existing
// test fleet's truncate semantics stay simple.
const extendedExplorerSchemaRD1009 = `
CREATE TABLE IF NOT EXISTS token_transfers (
    id SERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL REFERENCES transactions(hash) ON DELETE CASCADE,
    log_index INT NOT NULL,
    token_address TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    value NUMERIC(78, 0) NOT NULL,
    block_number BIGINT NOT NULL,
    timestamp BIGINT,
    transfer_type TEXT DEFAULT 'transfer',
    token_type TEXT DEFAULT 'ERC20',
    token_id NUMERIC(78, 0),
    is_internal BOOLEAN DEFAULT false,
    UNIQUE(tx_hash, log_index)
);
`

// TestBuildVisibilityFilter_UnionsTransferParticipantTxHashes_RD1009 is the
// server-level proof that `buildVisibilityFilter` now unions in tx hashes
// whose token-transfer participants are admin-visible. Pre-fix the filter
// only contained the viewer's Full-visibility addresses + the `tx_visible_to`
// shares from explicit disclosure grants, leaving the cross-redactor row
// asymmetry open. Post-fix the union closes it at the SQL allowlist filter
// before the redactor ever runs — and as a side benefit guarantees the
// downstream RedactOpts.VisibleTxHashes (built via redactOptsFromFilter)
// covers the same set, so the redactor's bothHidden branch is also bypassed.
func TestBuildVisibilityFilter_UnionsTransferParticipantTxHashes_RD1009(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)

	// Add token_transfers to the schema (the base explorerSchema doesn't
	// include it; RD-1009 needs it to drive the new query).
	_, err := conn.ExecContext(context.Background(), extendedExplorerSchemaRD1009)
	require.NoError(t, err, "create token_transfers table")
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), "DROP TABLE IF EXISTS token_transfers")
	})

	ctx := context.Background()

	// ---- Set up the visibility world.
	// One admin org with a token contract; one admin-visible org-mate EOA; one
	// private wallet EOA that calls the token contract to send tokens to the
	// org-mate. The admin viewer is org-admin of the contract's owning org;
	// the org-mate's EOA is linked to a user in the same org.
	orgID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "rd1009-org", "RD-1009 Test Org")
	require.NoError(t, err)

	// Admin user + group with is_org_admin → has Full visibility on the contract.
	adminUserID := uuid.New().String()
	const adminDID = "did:privado:rd1009_admin"
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		adminUserID, adminDID)
	require.NoError(t, err)

	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
		adminGroupID, orgID)
	require.NoError(t, err)

	_, err = conn.ExecContext(ctx,
		"INSERT INTO user_memberships (id, user_id, group_id, source) VALUES ($1, $2, $3, 'admin')",
		uuid.New().String(), adminUserID, adminGroupID)
	require.NoError(t, err)

	// Org-mate user with a linked EOA. The admin should NOT have Full visibility
	// on the org-mate's EOA (user EOAs are Hidden to everyone except the owner,
	// per the spec §2.1 matrix). This is intentional — the RD-1009 scenario is
	// "admin sees the transfer because the recipient is admin-visible to them"
	// for the *contract owner* admin viewer specifically. To make this test
	// shape work with the current visibility model we need the org-mate's
	// address to come back as Full. The cleanest route is to use a registered
	// contract address as the "org-mate" (org contracts ARE admin-visible).
	// That mirrors the real bug scenario: many flows have the org-mate side as
	// a contract (e.g. a settlement vault), not a raw EOA.
	const orgMateContract = "0xcccccccccccccccccccccccccccccccccccccccc"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		contractID, orgID, orgMateContract, "OrgMate Vault")
	require.NoError(t, err)

	// The private token contract that the wallet calls. NOT registered in the
	// admin's org — Hidden to them.
	const privateTokenContract = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherOrgID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		otherOrgID, "rd1009-other-org", "Other Org")
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
		uuid.New().String(), otherOrgID, privateTokenContract, "Private Token")
	require.NoError(t, err)

	// Wallet EOA — linked to a user in the OTHER org so it's Hidden to our admin.
	const privateWalletEOA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherUserID := uuid.New().String()
	const otherDID = "did:privado:rd1009_other"
	_, err = conn.ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		otherUserID, otherDID)
	require.NoError(t, err)
	// eth_address_links keys on the DID (see migration 001) — a synthetic
	// signature/message_hash satisfies NOT NULL and is irrelevant to the
	// visibility resolution.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO eth_address_links (did, eth_address, link_type) VALUES ($1, $2, 'user')`,
		otherDID, privateWalletEOA)
	require.NoError(t, err)

	// ---- Seed the explorer chain data.
	blockNum := seedExplorerBlock(t, conn)

	// The RD-1009 reproducer tx: wallet calls private token → admin-visible
	// org-mate. Tx.from and tx.to are both Hidden to the admin; transfer.to
	// is the admin-visible orgmate contract.
	const reproducerTxHash = "0xrd1009_reproducer"
	seedExplorerTransaction(t, conn, blockNum, reproducerTxHash, privateWalletEOA, privateTokenContract)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, $4, 1000, $5)`,
		reproducerTxHash, privateTokenContract, privateWalletEOA, orgMateContract, blockNum)
	require.NoError(t, err)

	// Control: a wholly-hidden tx with no admin-visible transfer participant.
	// MUST NOT appear in the filter's VisibleTxHashes union.
	const controlTxHash = "0xrd1009_control"
	seedExplorerTransaction(t, conn, blockNum, controlTxHash, privateWalletEOA, privateTokenContract)
	_, err = conn.ExecContext(ctx, `
		INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		VALUES ($1, 0, $2, $3, '0xdeadbeef00000000000000000000000000000000', 1000, $4)`,
		controlTxHash, privateTokenContract, privateWalletEOA, blockNum)
	require.NoError(t, err)

	// ---- Run the visibility filter as the admin viewer.
	filter := srv.buildVisibilityFilter(ctx, adminDID)
	require.NotNil(t, filter, "filter should never be nil")
	require.True(t, filter.AllPrivate, "filter must be in allowlist mode")

	// The org-mate contract should be in VisibleAddresses (admin's own org).
	require.Contains(t, filter.VisibleAddresses, orgMateContract,
		"admin should have Full visibility on their org's contract")

	// THE RD-1009 INVARIANT: the reproducer tx hash MUST appear in
	// VisibleTxHashes because its transfer touches the admin-visible
	// orgMateContract. Pre-fix the union was missing and this assertion fails.
	require.Contains(t, filter.VisibleTxHashes, reproducerTxHash,
		"RD-1009 regression: buildVisibilityFilter should union in tx hashes whose token-transfer participants are admin-visible")

	// The control tx (no visible-side transfer participant) MUST NOT be in
	// the union — that would be over-revealing.
	require.NotContains(t, filter.VisibleTxHashes, controlTxHash,
		"buildVisibilityFilter must not include txs whose transfers have no visible participant")

	_ = database // returned by helper; not asserted on here but kept in scope for future expansion (e.g. driving the full redactor path).
}
