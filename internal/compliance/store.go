package compliance

import "context"

// Store defines database operations for travel rule compliance.
type Store interface {
	// Compliance config
	GetComplianceConfig(ctx context.Context, orgID string) (*ComplianceConfig, error)
	UpsertComplianceConfig(ctx context.Context, config *ComplianceConfig) error

	// Token pricing
	GetTokenPrice(ctx context.Context, orgID, tokenAddress string) (*TokenPrice, error)
	UpsertTokenPrice(ctx context.Context, price *TokenPrice) error
	DeleteTokenPrice(ctx context.Context, orgID, tokenAddress string) error
	ListTokenPrices(ctx context.Context, orgID string) ([]*TokenPrice, error)

	// Travel rule records
	CreateTravelRuleRecord(ctx context.Context, record *TravelRuleRecord) error
	GetTravelRuleRecord(ctx context.Context, id string) (*TravelRuleRecord, error)
	FindUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string) (*TravelRuleRecord, error)
	// ClaimUnusedTravelRuleRecord atomically finds an unused record and marks it as used.
	// This prevents TOCTOU race conditions where two concurrent requests could claim the same record.
	ClaimUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string) (*TravelRuleRecord, error)
	MarkTravelRuleRecordUsed(ctx context.Context, id string, txHash *string) error
	ListTravelRuleRecords(ctx context.Context, orgID string, limit, offset int) ([]*TravelRuleRecord, int, error)
	CleanupExpiredRecords(ctx context.Context) (int64, error)

	// Sanctioned addresses
	IsAddressSanctioned(ctx context.Context, orgID, address string) (bool, error)
	AddSanctionedAddress(ctx context.Context, sanction *SanctionedAddress) error
	RemoveSanctionedAddress(ctx context.Context, id string) error
	GetSanctionedAddress(ctx context.Context, id string) (*SanctionedAddress, error)
	ListSanctionedAddresses(ctx context.Context, orgID *string, limit, offset int) ([]*SanctionedAddress, int, error)

	// Compliance logs
	CreateComplianceLog(ctx context.Context, log *ComplianceLog) (int64, error)
	GetComplianceLog(ctx context.Context, id int64) (*ComplianceLog, error)
	ListComplianceLogs(ctx context.Context, orgID string, filters *ComplianceLogFilters) ([]*ComplianceLog, int, error)
}
