package explorer

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// RD-1149 regression guards for the SQL store: walking the by-address feeds
// on the returned opaque cursor must visit every row exactly once, even when
// a page boundary falls inside a block (the old bare `block_number < $before`
// bound dropped the boundary block's remaining rows). Also pins the legacy
// ?before= mapping and the fail-closed malformed-cursor error.
func TestStoreGetTransactionsByAddress_CursorWalk(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	setupExplorerSchema(t, sqlDB)

	const addr = "0xaaaa0000000000000000000000000000000000aa"
	ctx := context.Background()

	seedBlock := func(n uint64) {
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
			VALUES ($1, $2, $3, $4, 21000, 30000000, 1)`,
			n, fmt.Sprintf("0xkb%x", n), fmt.Sprintf("0xkb%x", n-1), 1000+n); err != nil {
			t.Fatalf("insert block: %v", err)
		}
	}
	seedTx := func(block uint64, txIndex int) string {
		hash := fmt.Sprintf("0xktx%d_%d", block, txIndex)
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
			VALUES ($1, $2, $3, $4, '0xbbbb0000000000000000000000000000000000bb', 0, 21000, 1, '0x', 1)`,
			hash, block, txIndex, addr); err != nil {
			t.Fatalf("insert tx: %v", err)
		}
		return hash
	}

	// Feed order (block DESC, tx_index DESC): block 101 holds 4 txs — limit 2
	// puts two page boundaries inside it.
	seedBlock(100)
	seedBlock(101)
	seedBlock(102)
	var want []string
	want = append(want, seedTx(102, 0))
	for i := 3; i >= 0; i-- {
		want = append(want, seedTx(101, i))
	}
	want = append(want, seedTx(100, 1), seedTx(100, 0))

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	t.Run("cursor walk visits every row exactly once", func(t *testing.T) {
		const limit = 2
		var got []string
		page := AddressPage{}
		for range [10]int{} {
			txs, next, err := store.GetTransactionsByAddress(ctx, addr, limit, page)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, tx := range txs {
				got = append(got, tx.Hash)
			}
			if next == "" {
				break
			}
			page = AddressPage{Cursor: next}
		}
		if len(got) != len(want) {
			t.Fatalf("walked %d txs, want %d (mid-block page boundary must not drop rows): %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("row %d = %s, want %s (feed order)", i, got[i], want[i])
			}
		}
	})

	t.Run("legacy before is block-exclusive", func(t *testing.T) {
		before := uint64(101)
		txs, _, err := store.GetTransactionsByAddress(ctx, addr, 10, AddressPage{BeforeBlock: &before})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(txs) != 2 {
			t.Fatalf("before=101 returned %d txs, want 2 (only block 100)", len(txs))
		}
		for _, tx := range txs {
			if tx.BlockNumber >= before {
				t.Errorf("before=%d returned tx in block %d", before, tx.BlockNumber)
			}
		}
	})

	t.Run("malformed cursor fails closed", func(t *testing.T) {
		_, _, err := store.GetTransactionsByAddress(ctx, addr, 10, AddressPage{Cursor: "!!not-base64!!"})
		if err == nil {
			t.Fatal("malformed cursor must error, not restart the feed")
		}
		if !isBadCursor(err) {
			t.Fatalf("error = %v, want ErrBadCursor", err)
		}
	})

	t.Run("cursor absent on the final page", func(t *testing.T) {
		txs, next, err := store.GetTransactionsByAddress(ctx, addr, len(want), AddressPage{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(txs) != len(want) {
			t.Fatalf("got %d txs, want %d", len(txs), len(want))
		}
		if next != "" {
			t.Errorf("exact-fit page must not return a cursor, got %q", next)
		}
	})
}

func isBadCursor(err error) bool {
	for e := err; e != nil; {
		if e == ErrBadCursor {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
