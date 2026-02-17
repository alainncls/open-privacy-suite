package compliance

import "time"

// TransferType indicates the type of value transfer.
type TransferType string

const (
	TransferTypeETH   TransferType = "eth"
	TransferTypeERC20 TransferType = "erc20"
)

// ComplianceConfig stores per-org compliance settings.
type ComplianceConfig struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Enabled      bool      `json:"enabled"`
	ThresholdUSD float64   `json:"threshold_usd"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TokenPrice stores admin-configured fiat valuation for a token.
type TokenPrice struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	TokenAddress    string    `json:"token_address"` // "native" for ETH, or lowercase 0x-prefixed contract address
	Symbol          string    `json:"symbol"`
	Decimals        int       `json:"decimals"`
	PriceUSD        float64   `json:"price_usd"`
	UpdatedByUserID *string   `json:"updated_by_user_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// TravelRuleRecord stores IVMS101 compliance data submitted before a transfer.
type TravelRuleRecord struct {
	ID                 string                 `json:"id"`
	OrgID              string                 `json:"org_id"`
	OriginatorUserID   string                 `json:"originator_user_id"`
	OriginatorData     map[string]any `json:"originator_data"`
	BeneficiaryData    map[string]any `json:"beneficiary_data"`
	TransferType       TransferType           `json:"transfer_type"`
	TokenAddress       *string                `json:"token_address,omitempty"`
	BeneficiaryAddress string                 `json:"beneficiary_address"`
	AmountWei          string                 `json:"amount_wei"`
	AmountUSD          float64                `json:"amount_usd"`
	ExpiresAt          time.Time              `json:"expires_at"`
	UsedAt             *time.Time             `json:"used_at,omitempty"`
	UsedTxHash         *string                `json:"used_tx_hash,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
}

// SanctionedAddress is a blocklisted address (global or per-org).
type SanctionedAddress struct {
	ID            string    `json:"id"`
	OrgID         *string   `json:"org_id,omitempty"` // nil = global
	Address       string    `json:"address"`
	Reason        string    `json:"reason"`
	Source        string    `json:"source,omitempty"`
	AddedByUserID *string   `json:"added_by_user_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ComplianceLog is an immutable record of a compliance decision.
type ComplianceLog struct {
	ID                 int64        `json:"id"`
	OrgID              string       `json:"org_id"`
	UserID             string       `json:"user_id"`
	TransferType       TransferType `json:"transfer_type"`
	TokenAddress       *string      `json:"token_address,omitempty"`
	FromAddress        string       `json:"from_address"`
	ToAddress          string       `json:"to_address"`
	AmountWei          string       `json:"amount_wei"`
	AmountUSD          *float64     `json:"amount_usd,omitempty"`
	ThresholdUSD       *float64     `json:"threshold_usd,omitempty"`
	Decision           string       `json:"decision"` // "allowed" or "denied"
	DenialReason       *string      `json:"denial_reason,omitempty"`
	TravelRuleRecordID *string      `json:"travel_rule_record_id,omitempty"`
	CreatedAt          time.Time    `json:"created_at"`
}

// AddressThresholdOverride stores per-address threshold overrides for risk-based compliance.
// When set, the address-specific threshold takes precedence over the org-level threshold.
type AddressThresholdOverride struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Address      string    `json:"address"` // lowercased 0x-prefixed
	ThresholdUSD float64   `json:"threshold_usd"`
	Note         string    `json:"note,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ComplianceLogFilters for querying compliance logs.
type ComplianceLogFilters struct {
	UserID       *string
	Decision     *string
	TransferType *TransferType
	Limit        int
	Offset       int
}
