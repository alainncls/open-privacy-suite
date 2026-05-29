package explorer

import (
	"context"
	"testing"
)

// TestRedactInternalTransactions_VisibleTxHashesOverride_RD1009 pins the
// follow-up to RD-1009: RedactInternalTransactions must honour
// RedactOpts.VisibleTxHashes the same way RedactTransactions does. Pre-fix
// the function ignored the field entirely — even though buildRedactOptsForViewer
// (post-PR-#285) populates it via the transfer-participant union — so an
// internal tx whose own from/to are both hidden would drop under the
// bothHidden predicate while:
//
//   - /transactions list keeps the parent tx row (VisibleTxHashes flows
//     through buildVisibilityFilter and into RedactTransactions),
//   - /transactions/:hash by-hash dereference keeps it (RedactTransactions
//     via buildRedactOptsForViewer inherits the same union — RD-1009 commit 2),
//   - /transfers list keeps the derived ERC-20 row (admin-visible recipient),
//
// but /transactions/:hash/internal would be empty. The internal-txs tab
// would contradict the surrounding rows for the very same parent tx hash
// the other surfaces just rendered.
//
// Same bug class as RD-1009: cross-surface row-survival decisions disagree
// for one logical event (the parent tx + its derived rows). Fix shape is
// the same: union the parent-tx allowlist into the drop predicate.
//
// MUTATION CHECK: remove the VisibleTxHashes lookup added to the drop
// predicate in RedactInternalTransactions → this test fails with
// "RD-1009 internal-tx regression: ...". Restore → passes.
func TestRedactInternalTransactions_VisibleTxHashesOverride_RD1009(t *testing.T) {
	const sharedTxHash = "0xdeadbeefcafebabe"

	// Internal-tx with both sides hidden to the admin viewer — the parent tx
	// is in VisibleTxHashes via the transfer-participant union (because one
	// of the parent's derived token-transfer participants is admin-visible).
	privFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	privTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngine(VisibilityMap{
		privFrom: VisibilityHidden,
		privTo:   VisibilityHidden,
	})

	itxs := []InternalTransaction{{
		ID:     1,
		TxHash: sharedTxHash,
		From:   privFrom,
		To:     strPtr(privTo),
		Value:  "500",
	}}

	ctx := context.Background()

	// Without the fix: even with VisibleTxHashes populated for the parent tx,
	// RedactInternalTransactions drops the row.
	opts := RedactOpts{
		// Non-admin viewer to isolate the visibleTo path from the admin-audit
		// path — we want to prove VisibleTxHashes alone keeps the row, not
		// the OrgAdminViewUserTxs flag.
		VisibleTxHashes: map[string]bool{sharedTxHash: true},
	}
	result, err := engine.RedactInternalTransactions(ctx, itxs, "did:viewer", opts)
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("RD-1009 internal-tx regression: expected 1 surviving internal tx "+
			"(parent in VisibleTxHashes), got %d. RedactInternalTransactions must "+
			"honour RedactOpts.VisibleTxHashes the same way RedactTransactions does.",
			len(result))
	}
	// Addresses should be revealed (visibleTo override mirrors RedactTransactions
	// — when the parent tx is shared with the viewer, counterparty addresses
	// on the internal tx are exposed too; this is privacy-equivalent because
	// the surviving parent tx row already exposes them).
	if result[0].From != privFrom {
		t.Errorf("expected From=privFrom under visibleTo override, got %q", result[0].From)
	}
	if result[0].To == nil || *result[0].To != privTo {
		t.Errorf("expected To=privTo under visibleTo override, got %v", result[0].To)
	}
}

// TestRedactInternalTransactions_NoVisibleTxHashes_StillDrops is the
// negative half: without the parent tx in VisibleTxHashes, the existing
// bothHidden drop continues to fire. Pinning the negative case so a
// future refactor doesn't unconditionally surface all internal txs.
func TestRedactInternalTransactions_NoVisibleTxHashes_StillDrops(t *testing.T) {
	privFrom := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	privTo := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngine(VisibilityMap{
		privFrom: VisibilityHidden,
		privTo:   VisibilityHidden,
	})

	itxs := []InternalTransaction{{
		ID:     1,
		TxHash: "0xunrelated",
		From:   privFrom,
		To:     strPtr(privTo),
		Value:  "500",
	}}

	// Empty VisibleTxHashes — strict-privacy drop should still fire.
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:viewer",
		RedactOpts{})
	if err != nil {
		t.Fatalf("RedactInternalTransactions: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected both-hidden internal tx dropped with no VisibleTxHashes, got %d", len(result))
	}
}
