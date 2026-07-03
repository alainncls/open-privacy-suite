package server

import "testing"

// TestCountAcrossPages verifies the paged counter sums survivors across ALL
// pages — not just the first — which is the core of the address-stats fix:
// privacy/gRPC mode clamps each fetch to ~100 rows, so a single fetch capped the
// count at 100. It also pins the maxScan bound and termination.
func TestCountAcrossPages(t *testing.T) {
	type item struct {
		block uint64
		vis   bool
	}
	const total = 250
	// Newest-first feed across blocks total..1, one tx per block; every 3rd is
	// not visible (would be dropped by redaction).
	feed := make([]item, 0, total)
	for b := uint64(total); b >= 1; b-- {
		feed = append(feed, item{block: b, vis: b%3 != 0})
	}
	wantVisible := 0
	for _, it := range feed {
		if it.vis {
			wantVisible++
		}
	}

	const perPage = 100 // simulate the privacy/gRPC indexer page clamp
	// fetch returns up to perPage items strictly older than `before` (nil=newest),
	// mirroring GetTransactionsByAddress(... block_number < before ...).
	fetch := func(before *uint64) ([]item, error) {
		out := make([]item, 0, perPage)
		for _, it := range feed {
			if before != nil && it.block >= *before {
				continue
			}
			out = append(out, it)
			if len(out) == perPage {
				break
			}
		}
		return out, nil
	}
	cursorOf := func(it item) uint64 { return it.block }
	survivors := func(page []item) (int, error) {
		n := 0
		for _, it := range page {
			if it.vis {
				n++
			}
		}
		return n, nil
	}

	t.Run("counts across all pages (not capped at one page)", func(t *testing.T) {
		got, err := countAcrossPages(fetch, cursorOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantVisible {
			t.Errorf("count = %d, want %d (must scan all %d items, not just the first %d)",
				got, wantVisible, total, perPage)
		}
		if wantVisible <= perPage {
			t.Fatalf("test setup: wantVisible (%d) must exceed perPage (%d) to prove uncapped", wantVisible, perPage)
		}
	})

	t.Run("respects maxScan bound (rounds up to a page)", func(t *testing.T) {
		// maxScan=150 with perPage=100 -> scans 2 pages (200 items) then stops.
		got, err := countAcrossPages(fetch, cursorOf, survivors, 150)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		want := 0
		for _, it := range feed[:200] {
			if it.vis {
				want++
			}
		}
		if got != want {
			t.Errorf("bounded count = %d, want %d (first 2 pages)", got, want)
		}
		if got >= wantVisible {
			t.Errorf("bounded count = %d should be < full %d (maxScan must engage)", got, wantVisible)
		}
	})

	t.Run("single block larger than a page terminates (remainder omitted)", func(t *testing.T) {
		// All items in the same block (block 7). After the first page the cursor
		// advances to 7; the next fetch (block < 7) is empty, so the loop
		// terminates. The same-block remainder beyond one page is omitted, but
		// the loop is always bounded — never infinite.
		same := make([]item, 500)
		for i := range same {
			same[i] = item{block: 7, vis: true}
		}
		fetchSame := func(before *uint64) ([]item, error) {
			if before != nil && *before <= 7 {
				return nil, nil
			}
			return same[:perPage], nil
		}
		got, err := countAcrossPages(fetchSame, cursorOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != perPage {
			t.Errorf("count = %d, want %d (one page counted, then bounded break)", got, perPage)
		}
	})

	t.Run("backend that ignores the before cursor is not double-counted", func(t *testing.T) {
		// Regression guard for the gRPC chain-indexer backend, which ignores
		// `before` and re-serves the first page on every call. The page[0]
		// guard must break BEFORE counting the re-served page, so the first
		// page is counted exactly once (the bug counted it on every fetch).
		wantFirstPage := 0
		for _, it := range feed[:perPage] {
			if it.vis {
				wantFirstPage++
			}
		}
		calls := 0
		fetchIgnoresBefore := func(_ *uint64) ([]item, error) {
			calls++
			// Always return the newest page, regardless of `before`.
			return feed[:perPage], nil
		}
		got, err := countAcrossPages(fetchIgnoresBefore, cursorOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantFirstPage {
			t.Errorf("count = %d, want %d (re-served first page must be counted once, not doubled)", got, wantFirstPage)
		}
		// Two fetches expected: the first counts, the second trips the guard
		// and breaks. Without the guard the loop would scan to maxScan.
		if calls != 2 {
			t.Errorf("fetch calls = %d, want 2 (count first page, then guard breaks on re-serve)", calls)
		}
	})
}
