package pricing

import (
	"context"
	"log"
	"time"

	"privacy-proxy/internal/compliance"
)

// SystemPriceStore defines the database operations needed by the pricing service.
type SystemPriceStore interface {
	ListSystemTokenPrices(ctx context.Context) ([]*compliance.SystemTokenPrice, error)
	UpsertSystemTokenPrice(ctx context.Context, price *compliance.SystemTokenPrice) error
}

// SettingsStore defines the database operations for system settings.
type SettingsStore interface {
	GetSystemSetting(ctx context.Context, key string) (string, error)
}

// Service fetches token prices from CoinGecko on a schedule and updates the system_token_prices table.
type Service struct {
	store               SystemPriceStore
	settingsStore       SettingsStore
	fetcher             *Fetcher
	interval            time.Duration
	cancel              context.CancelFunc
	done                chan struct{}
	consecutiveFailures int
}

// NewService creates a new pricing service.
func NewService(store SystemPriceStore, settingsStore SettingsStore, interval time.Duration) *Service {
	return &Service{
		store:         store,
		settingsStore: settingsStore,
		fetcher:       NewFetcher(),
		interval:      interval,
		done:          make(chan struct{}),
	}
}

// Start begins the background price fetching loop.
func (s *Service) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	go func() {
		defer close(s.done)

		// Fetch immediately on start
		s.fetchAndUpdate(ctx)

		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.fetchAndUpdate(ctx)
			}
		}
	}()

	log.Printf("Pricing service started (interval: %s)", s.interval)
}

// Stop gracefully stops the background fetching.
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
	log.Printf("Pricing service stopped")
}

func (s *Service) fetchAndUpdate(ctx context.Context) {
	// Read current system token IDs from DB
	systemPrices, err := s.store.ListSystemTokenPrices(ctx)
	if err != nil {
		log.Printf("WARNING: pricing service failed to list system token prices: %v", err)
		return
	}

	if len(systemPrices) == 0 {
		return
	}

	// Collect IDs to fetch — only CoinGecko-sourced tokens
	var ids []string
	priceMap := make(map[string]*compliance.SystemTokenPrice, len(systemPrices))
	for _, sp := range systemPrices {
		if sp.Source != "coingecko" || sp.CoingeckoID == nil {
			continue
		}
		ids = append(ids, *sp.CoingeckoID)
		priceMap[*sp.CoingeckoID] = sp
	}

	if len(ids) == 0 {
		return
	}

	// Read base currency from settings
	currency := "usd"
	if s.settingsStore != nil {
		if c, err := s.settingsStore.GetSystemSetting(ctx, "base_currency"); err == nil && c != "" {
			currency = c
		}
	}

	// Fetch from CoinGecko
	prices, err := s.fetcher.Fetch(ctx, ids, currency)
	if err != nil {
		s.consecutiveFailures++
		if s.consecutiveFailures >= 3 {
			log.Printf("ERROR: CoinGecko fetch failed %d consecutive times, prices may be stale: %v", s.consecutiveFailures, err)
		} else {
			log.Printf("WARNING: CoinGecko fetch failed, keeping existing prices: %v", err)
		}
		return
	}
	s.consecutiveFailures = 0

	// Upsert each result
	updated := 0
	for id, price := range prices {
		sp, ok := priceMap[id]
		if !ok {
			continue
		}
		sp.PriceFiat = price
		sp.UpdatedAt = time.Now()
		if err := s.store.UpsertSystemTokenPrice(ctx, sp); err != nil {
			log.Printf("WARNING: failed to update system price for %s: %v", id, err)
			continue
		}
		updated++
	}

	log.Printf("Pricing service: updated %d/%d token prices from CoinGecko", updated, len(ids))
}
