package access

import (
	"fmt"
	"privacy-proxy/internal/db"
)

type Controller struct {
	policyStore db.PolicyStore
}

// NewController creates a new access controller with a policy store
// Accepts PolicyStore interface to allow mocking in tests
func NewController(policyStore db.PolicyStore) *Controller {
	return &Controller{policyStore: policyStore}
}

// CheckAccess validates if a request should be allowed
// Returns error if access should be denied
func (c *Controller) CheckAccess(externalID, method string) error {
	policy, err := c.policyStore.GetPolicy(externalID)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	
	// If no policy exists, deny access
	if policy == nil {
		return fmt.Errorf("no policy found for %s", externalID)
	}
	
	// Check if banned
	if policy.Banned {
		return fmt.Errorf("user %s is banned", externalID)
	}
	
	// Check KYC - required for all users
	if !policy.KYC {
		return fmt.Errorf("KYC required for %s", externalID)
	}
	
	// Check method whitelist
	if !contains(policy.AllowMethods, method) {
		return fmt.Errorf("method %s not allowed for %s", method, externalID)
	}
	
	return nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
