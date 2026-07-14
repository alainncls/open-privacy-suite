package explorer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ErrBadCursor marks a malformed AddressPage.Cursor. Handlers map it to a
// 400 — a bad cursor must fail the request (fail-closed), never silently
// restart the feed from the top (which would re-serve and double-count).
var ErrBadCursor = errors.New("malformed pagination cursor")

// feedCursor is the SQL store's continuation position for the by-address
// feeds (RD-1149): the (block, idx) of the last returned row, idx being
// tx_index for the tx feed and log_index for the transfer feed. Encoded
// base64url(JSON) — opaque to callers; the gRPC backend uses the indexer's
// own encoding instead, so cursors are only valid against the backend that
// issued them.
type feedCursor struct {
	Block uint64 `json:"b"`
	Index uint32 `json:"i"`
}

func encodeFeedCursor(c feedCursor) string {
	raw, _ := json.Marshal(c) // struct of two ints cannot fail to marshal
	return base64.RawURLEncoding.EncodeToString(raw)
}

func decodeFeedCursor(s string) (feedCursor, error) {
	var c feedCursor
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, ErrBadCursor
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, ErrBadCursor
	}
	return c, nil
}

// sqlFeedBound normalizes an AddressPage to the exclusive row-value bound
// (block, idx) used by the store's keyset queries: cursor → its position;
// legacy BeforeBlock=N → (N, 0) (≡ block_number < N); no position → nil.
func sqlFeedBound(page AddressPage) (*feedCursor, error) {
	if page.Cursor != "" {
		c, err := decodeFeedCursor(page.Cursor)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
	if page.BeforeBlock != nil {
		return &feedCursor{Block: *page.BeforeBlock, Index: 0}, nil
	}
	return nil, nil
}
