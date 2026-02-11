package compliance

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"
	"time"
)

// Checker performs compliance checks on value transfers.
type Checker struct {
	store            Store
	defaultThreshold float64       // fallback threshold if org has no config
	recordExpiry     time.Duration // how long travel rule records stay valid
}

// NewChecker creates a new compliance checker.
func NewChecker(store Store, defaultThreshold float64, recordExpiry time.Duration) *Checker {
	return &Checker{
		store:            store,
		defaultThreshold: defaultThreshold,
		recordExpiry:     recordExpiry,
	}
}

// CheckRequest contains the parameters for a compliance check.
type CheckRequest struct {
	OrgID  string
	UserID string // internal user UUID
	From   string // sender address (hex)
	To     string // recipient address (hex)
	Data   string // calldata (hex)
	Value  string // transfer value (hex)
}

// CheckResult is the outcome of a compliance check.
type CheckResult struct {
	Allowed      bool
	Reason       string
	TransferInfo *TransferInfo
}

// Check performs a compliance check on the given transaction.
func (c *Checker) Check(ctx context.Context, req *CheckRequest) (*CheckResult, error) {
	// Step 1: Detect if this is a value transfer
	info := DetectTransfer(req.From, req.To, req.Data, req.Value)
	if info == nil {
		return &CheckResult{
			Allowed: true,
			Reason:  "not a value transfer",
		}, nil
	}

	// Step 2: Check if compliance is enabled for this org
	config, err := c.store.GetComplianceConfig(ctx, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance config: %w", err)
	}
	if config == nil || !config.Enabled {
		return &CheckResult{
			Allowed:      true,
			Reason:       "compliance not enabled for org",
			TransferInfo: info,
		}, nil
	}

	// Step 3: Sanctions check
	sanctionedTo, err := c.store.IsAddressSanctioned(ctx, req.OrgID, info.ToAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check sanctions for to address: %w", err)
	}
	if sanctionedTo {
		reason := fmt.Sprintf("recipient address %s is sanctioned", info.ToAddress)
		log.Printf("Compliance denied: org=%s user=%s %s", req.OrgID, req.UserID, reason)
		_ = c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil)
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	sanctionedFrom, err := c.store.IsAddressSanctioned(ctx, req.OrgID, info.FromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check sanctions for from address: %w", err)
	}
	if sanctionedFrom {
		reason := fmt.Sprintf("sender address %s is sanctioned", info.FromAddress)
		log.Printf("Compliance denied: org=%s user=%s %s", req.OrgID, req.UserID, reason)
		_ = c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil)
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Step 4: Calculate fiat value
	tokenAddr := "native"
	if info.TokenAddress != nil {
		tokenAddr = strings.ToLower(*info.TokenAddress)
	}

	tokenPrice, err := c.store.GetTokenPrice(ctx, req.OrgID, tokenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get token price: %w", err)
	}
	if tokenPrice == nil {
		// Fail closed: no price configured means we cannot evaluate
		reason := fmt.Sprintf("no price configured for token %s", tokenAddr)
		log.Printf("Compliance denied (fail closed): org=%s user=%s %s", req.OrgID, req.UserID, reason)
		_ = c.logDecision(ctx, req, info, nil, nil, "denied", reason, nil)
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Convert amountWei to USD: amountWei / 10^decimals * priceUSD
	amountUSD := weiToUSD(info.AmountWei, tokenPrice.Decimals, tokenPrice.PriceUSD)

	// Determine threshold
	threshold := config.ThresholdUSD
	if threshold == 0 {
		threshold = c.defaultThreshold
	}

	// Step 5: Below threshold -> allow
	if amountUSD < threshold {
		reason := fmt.Sprintf("transfer value $%.2f below threshold $%.2f", amountUSD, threshold)
		log.Printf("Compliance allowed: org=%s user=%s %s", req.OrgID, req.UserID, reason)
		_ = c.logDecision(ctx, req, info, &amountUSD, &threshold, "allowed", "", nil)
		return &CheckResult{
			Allowed:      true,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Step 6: Above threshold -> look for travel rule record
	record, err := c.store.FindUnusedTravelRuleRecord(ctx, req.OrgID, req.UserID, info.ToAddress, tokenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to find travel rule record: %w", err)
	}
	if record == nil {
		reason := fmt.Sprintf("transfer value $%.2f exceeds threshold $%.2f and no travel rule record found", amountUSD, threshold)
		log.Printf("Compliance denied: org=%s user=%s %s", req.OrgID, req.UserID, reason)
		_ = c.logDecision(ctx, req, info, &amountUSD, &threshold, "denied", reason, nil)
		return &CheckResult{
			Allowed:      false,
			Reason:       reason,
			TransferInfo: info,
		}, nil
	}

	// Step 7: Mark record as used and allow
	if err := c.store.MarkTravelRuleRecordUsed(ctx, record.ID, nil); err != nil {
		return nil, fmt.Errorf("failed to mark travel rule record as used: %w", err)
	}

	reason := fmt.Sprintf("transfer value $%.2f exceeds threshold $%.2f, travel rule record %s applied", amountUSD, threshold, record.ID)
	log.Printf("Compliance allowed: org=%s user=%s %s", req.OrgID, req.UserID, reason)
	_ = c.logDecision(ctx, req, info, &amountUSD, &threshold, "allowed", "", &record.ID)
	return &CheckResult{
		Allowed:      true,
		Reason:       reason,
		TransferInfo: info,
	}, nil
}

// logDecision creates a compliance log entry for an allow or deny decision.
func (c *Checker) logDecision(ctx context.Context, req *CheckRequest, info *TransferInfo,
	amountUSD *float64, thresholdUSD *float64, decision, denialReason string, recordID *string) error {

	var denialReasonPtr *string
	if denialReason != "" {
		denialReasonPtr = &denialReason
	}

	entry := &ComplianceLog{
		OrgID:              req.OrgID,
		UserID:             req.UserID,
		TransferType:       info.Type,
		TokenAddress:       info.TokenAddress,
		FromAddress:        info.FromAddress,
		ToAddress:          info.ToAddress,
		AmountWei:          info.AmountWei.String(),
		AmountUSD:          amountUSD,
		ThresholdUSD:       thresholdUSD,
		Decision:           decision,
		DenialReason:       denialReasonPtr,
		TravelRuleRecordID: recordID,
	}

	_, err := c.store.CreateComplianceLog(ctx, entry)
	if err != nil {
		log.Printf("Warning: failed to create compliance log: %v", err)
	}
	return err
}

// weiToUSD converts a wei amount to USD given the token decimals and price.
func weiToUSD(amountWei *big.Int, decimals int, priceUSD float64) float64 {
	if amountWei == nil || amountWei.Sign() == 0 {
		return 0
	}

	// Use big.Float for precision during the division
	amountFloat := new(big.Float).SetInt(amountWei)
	divisor := new(big.Float).SetFloat64(math.Pow10(decimals))
	tokenAmount := new(big.Float).Quo(amountFloat, divisor)

	// Multiply by price
	price := new(big.Float).SetFloat64(priceUSD)
	usdValue := new(big.Float).Mul(tokenAmount, price)

	result, _ := usdValue.Float64()
	return result
}
