package db

import (
	"context"
	"strings"
)

// GetLinkedEthAddresses returns the lowercase ETH addresses linked to a DID.
// This wraps GetEthAddressesByDID, extracting just the address strings.
func (d *DB) GetLinkedEthAddresses(ctx context.Context, did string) ([]string, error) {
	links, err := d.GetEthAddressesByDID(ctx, did)
	if err != nil {
		return nil, err
	}
	addrs := make([]string, len(links))
	for i, l := range links {
		addrs[i] = strings.ToLower(l.EthAddress)
	}
	return addrs, nil
}
