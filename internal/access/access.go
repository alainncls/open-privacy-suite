package access

import (
	"fmt"
	"privacy-proxy/internal/db"
	"strings"
)

// Multicall3Address is the standard address for the Multicall3 contract
// deployed at the same address on all EVM chains
const Multicall3Address = "0xcA11bde05977b3631167028862bE2a173976CA11"

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
	return c.CheckAccessWithParams(externalID, method, nil)
}

// CheckAccessWithParams validates if a request should be allowed, including param-based checks
// Returns error if access should be denied
func (c *Controller) CheckAccessWithParams(externalID, method string, params []interface{}) error {
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

	// Check for Multicall3 if method is eth_call
	if method == "eth_call" && len(params) > 0 {
		if err := checkMulticall(params); err != nil {
			return err
		}
	}

	return nil
}

// checkMulticall validates that eth_call is not targeting Multicall3 contract
func checkMulticall(params []interface{}) error {
	if len(params) == 0 {
		return nil
	}

	callObj, ok := params[0].(map[string]interface{})
	if !ok {
		return nil
	}

	to, ok := callObj["to"].(string)
	if !ok {
		return nil
	}

	if strings.EqualFold(to, Multicall3Address) {
		return fmt.Errorf("multicall not allowed")
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
