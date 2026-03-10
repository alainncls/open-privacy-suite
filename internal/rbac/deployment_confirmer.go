package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// EthClient interface for getting transaction receipts.
// This is implemented by the RPC client layer.
type EthClient interface {
	GetTransactionReceipt(ctx context.Context, txHash string) (*TransactionReceipt, error)
}

// TransactionReceipt contains the result of a mined transaction.
type TransactionReceipt struct {
	Status          uint64 // 1 = success, 0 = failure
	ContractAddress string // Address of created contract (if deployment)
}

// DeploymentConfirmer confirms deployments and registers proxies.
// It can operate in two modes:
// 1. Direct notification (via ConfirmDeployment) when the RPC layer knows the result
// 2. Background polling (via Start) to check pending deployments
type DeploymentConfirmer struct {
	tracker      *PendingDeploymentTracker
	validator    *DeploymentValidator
	ethClient    EthClient
	pollInterval time.Duration
}

// NewDeploymentConfirmer creates a new deployment confirmer.
// The ethClient can be nil if only using direct notification mode.
func NewDeploymentConfirmer(
	tracker *PendingDeploymentTracker,
	validator *DeploymentValidator,
	ethClient EthClient,
) *DeploymentConfirmer {
	return &DeploymentConfirmer{
		tracker:      tracker,
		validator:    validator,
		ethClient:    ethClient,
		pollInterval: 15 * time.Second, // Default poll interval
	}
}

// SetPollInterval configures the polling interval for background confirmation.
func (c *DeploymentConfirmer) SetPollInterval(interval time.Duration) {
	c.pollInterval = interval
}

// ConfirmDeployment checks if a deployment tx is mined and registers the proxy if applicable.
// This method is typically called after receiving the transaction receipt from the RPC response.
// It removes the pending deployment from the tracker regardless of success/failure.
//
// Parameters:
//   - txHash: The transaction hash of the deployment
//
// Returns an error if:
//   - The deployment is not found in the tracker (already processed or unknown)
//   - The transaction failed (status = 0)
//   - The receipt is missing contract address
//   - Proxy registration fails
func (c *DeploymentConfirmer) ConfirmDeployment(ctx context.Context, txHash string) error {
	if c.ethClient == nil {
		return fmt.Errorf("eth client not configured for deployment confirmation")
	}

	// Get the pending deployment (removes it from tracker)
	deployment := c.tracker.Get(txHash)
	if deployment == nil {
		return fmt.Errorf("no pending deployment found for tx %s", txHash)
	}

	// Get the transaction receipt
	receipt, err := c.ethClient.GetTransactionReceipt(ctx, txHash)
	if err != nil {
		// Put it back for retry if we couldn't get the receipt
		c.tracker.Track(txHash, deployment)
		return fmt.Errorf("failed to get receipt for tx %s: %w", txHash, err)
	}

	// Handle the result
	return c.handleReceipt(ctx, deployment, receipt)
}

// ConfirmDeploymentWithReceipt processes a deployment confirmation using a provided receipt.
// This is useful when the caller already has the receipt (e.g., from the RPC response).
func (c *DeploymentConfirmer) ConfirmDeploymentWithReceipt(
	ctx context.Context,
	txHash string,
	receipt *TransactionReceipt,
) error {
	// Get the pending deployment (removes it from tracker)
	deployment := c.tracker.Get(txHash)
	if deployment == nil {
		// Not a tracked deployment - this is fine, just means it wasn't a proxy
		return nil
	}

	return c.handleReceipt(ctx, deployment, receipt)
}

// handleReceipt processes the receipt and registers the proxy if needed.
func (c *DeploymentConfirmer) handleReceipt(
	ctx context.Context,
	deployment *PendingDeployment,
	receipt *TransactionReceipt,
) error {
	if receipt == nil {
		return fmt.Errorf("receipt is nil")
	}

	// Check if transaction succeeded
	if receipt.Status == 0 {
		// Transaction failed, nothing to register
		return fmt.Errorf("deployment transaction failed")
	}

	// For contract deployments, we need the contract address
	if receipt.ContractAddress == "" {
		// This might be a non-deployment transaction that was tracked incorrectly
		return fmt.Errorf("receipt missing contract address")
	}

	// Only register if it's a proxy
	if !deployment.IsProxy || deployment.ProxyInfo == nil {
		// Not a proxy, nothing to register
		return nil
	}

	// Register the proxy
	err := c.validator.RegisterDeployedProxy(
		ctx,
		deployment.OrgID,
		receipt.ContractAddress,
		deployment.ProxyInfo,
		"", // Initial implementation is not known from deployment bytecode
	)
	if err != nil {
		return fmt.Errorf("failed to register proxy %s: %w", receipt.ContractAddress, err)
	}

	return nil
}

// Start begins background polling for pending deployments.
// This method blocks and should be run in a goroutine.
// It will continue until the context is cancelled.
func (c *DeploymentConfirmer) Start(ctx context.Context) {
	if c.ethClient == nil {
		slog.Warn("DeploymentConfirmer started without ethClient, background polling disabled")
		return
	}

	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	// Also run cleanup periodically (every 10 poll intervals)
	cleanupCounter := 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollPendingDeployments(ctx)

			cleanupCounter++
			if cleanupCounter >= 10 {
				removed := c.tracker.Cleanup()
				if removed > 0 {
					slog.Info("cleaned up expired pending deployments", "count", removed)
				}
				cleanupCounter = 0
			}
		}
	}
}

// pollPendingDeployments checks all pending deployments for confirmation.
func (c *DeploymentConfirmer) pollPendingDeployments(ctx context.Context) {
	// Get a snapshot of pending transaction hashes
	txHashes := c.getPendingTxHashes()

	for _, txHash := range txHashes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Try to confirm each deployment
		err := c.ConfirmDeployment(ctx, txHash)
		if err != nil {
			// Log but continue with other deployments
			// Note: ConfirmDeployment puts the deployment back if receipt fetch fails
			if !strings.Contains(err.Error(), "no pending deployment") {
				slog.Error("error confirming deployment", "tx_hash", txHash, "error", err)
			}
		}
	}
}

// getPendingTxHashes returns a copy of all pending transaction hashes.
func (c *DeploymentConfirmer) getPendingTxHashes() []string {
	c.tracker.mu.RLock()
	defer c.tracker.mu.RUnlock()

	hashes := make([]string, 0, len(c.tracker.pending))
	for txHash := range c.tracker.pending {
		hashes = append(hashes, txHash)
	}
	return hashes
}
