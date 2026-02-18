package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	coingeckoBaseURL = "https://api.coingecko.com/api/v3/simple/price"
	fetchTimeout     = 10 * time.Second
)

// Fetcher retrieves token prices from the CoinGecko API.
type Fetcher struct {
	client *http.Client
}

// NewFetcher creates a new CoinGecko price fetcher.
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: fetchTimeout,
		},
	}
}

// Fetch retrieves USD prices for the given CoinGecko IDs.
// Returns a map of coingecko_id -> price_usd.
func (f *Fetcher) Fetch(ctx context.Context, ids []string) (map[string]float64, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	params := url.Values{}
	params.Set("ids", strings.Join(ids, ","))
	params.Set("vs_currencies", "usd")
	fetchURL := coingeckoBaseURL + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("CoinGecko request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("CoinGecko returned status %d: %s", resp.StatusCode, string(body))
	}

	// Response format: {"ethereum":{"usd":2500.42},"tether":{"usd":1.0}}
	var result map[string]map[string]float64
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode CoinGecko response: %w", err)
	}

	prices := make(map[string]float64, len(result))
	for id, currencies := range result {
		if usd, ok := currencies["usd"]; ok {
			prices[id] = usd
		}
	}

	return prices, nil
}
