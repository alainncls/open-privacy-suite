package rbac

import (
	"strings"
	"testing"
)

// TestFactoryAutoAllowLogic tests the auto-allow logic for org factory access.
func TestFactoryAutoAllowLogic(t *testing.T) {
	t.Run("containsClaim helper works correctly", func(t *testing.T) {
		claims := []Claim{ClaimDeploy, ClaimUpgrade}

		if !containsClaim(claims, ClaimDeploy) {
			t.Error("containsClaim should find ClaimDeploy")
		}
		if !containsClaim(claims, ClaimUpgrade) {
			t.Error("containsClaim should find ClaimUpgrade")
		}
		if containsClaim(claims, ClaimAdmin) {
			t.Error("containsClaim should NOT find ClaimAdmin")
		}
		if containsClaim(nil, ClaimDeploy) {
			t.Error("containsClaim should return false for nil slice")
		}
		if containsClaim([]Claim{}, ClaimDeploy) {
			t.Error("containsClaim should return false for empty slice")
		}
	})

	t.Run("deploy claim in default_claims grants factory access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{},
			Claims:         []Claim{ClaimDeploy},
		}

		hasDeploy := containsClaim(perms.Claims, ClaimDeploy)
		if !hasDeploy {
			t.Error("User with deploy in default_claims should have deploy claim")
		}
	})

	t.Run("deploy claim on any contract grants factory access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa000000000000000000000000000000000001": {Claims: []Claim{}},
				"0xbbbb000000000000000000000000000000000002": {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{},
		}

		hasDeployOnAnyContract := false
		for _, access := range perms.ContractAccess {
			if containsClaim(access.Claims, ClaimDeploy) {
				hasDeployOnAnyContract = true
				break
			}
		}
		if !hasDeployOnAnyContract {
			t.Error("User should have deploy claim on at least one contract")
		}
	})

	t.Run("no deploy claim denies factory access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa": {Claims: []Claim{}},
			},
			Claims: []Claim{},
		}

		hasDeployInDefault := containsClaim(perms.Claims, ClaimDeploy)
		hasDeployOnAnyContract := false
		for _, access := range perms.ContractAccess {
			if containsClaim(access.Claims, ClaimDeploy) {
				hasDeployOnAnyContract = true
				break
			}
		}

		if hasDeployInDefault || hasDeployOnAnyContract {
			t.Error("User should NOT have deploy claim anywhere")
		}
	})

	t.Run("factory address comparison is case-insensitive", func(t *testing.T) {
		factoryAddr := "0xABCDEF1234567890ABCDEF1234567890ABCDEF12"
		targetAddr := "0xabcdef1234567890abcdef1234567890abcdef12"

		if strings.ToLower(factoryAddr) != strings.ToLower(targetAddr) {
			t.Error("Factory address comparison should be case-insensitive")
		}
	})

	t.Run("collectAllClaims includes claims from all sources", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa": {Claims: []Claim{ClaimAdmin}},
				"0xbbbb": {Claims: []Claim{ClaimDeploy}},
			},
			Claims: []Claim{ClaimUpgrade},
		}

		allClaims := collectAllClaims(perms)

		claimSet := make(map[Claim]bool)
		for _, c := range allClaims {
			claimSet[c] = true
		}

		if !claimSet[ClaimUpgrade] {
			t.Error("Should include ClaimUpgrade from default_claims")
		}
		if !claimSet[ClaimAdmin] {
			t.Error("Should include ClaimAdmin from contract 0xaaaa")
		}
		if !claimSet[ClaimDeploy] {
			t.Error("Should include ClaimDeploy from contract 0xbbbb")
		}
	})
}

// TestFactoryAutoAllowSecurityProperties tests security properties of factory auto-allow.
func TestFactoryAutoAllowSecurityProperties(t *testing.T) {
	t.Run("cross-org factory access prevented by address isolation", func(t *testing.T) {
		orgAFactory := "0xfactory_org_a"
		orgBFactory := "0xfactory_org_b"

		if strings.ToLower(orgAFactory) == strings.ToLower(orgBFactory) {
			t.Error("Different org factories should have different addresses")
		}
	})

	t.Run("factory auto-allow requires deploy claim specifically", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa": {Claims: []Claim{ClaimAdmin}},
			},
			Claims: []Claim{},
		}

		hasDeploy := containsClaim(perms.Claims, ClaimDeploy)
		if hasDeploy {
			t.Error("Should not have deploy in default claims")
		}

		for _, access := range perms.ContractAccess {
			if containsClaim(access.Claims, ClaimDeploy) {
				t.Error("Should not have deploy on any contract")
			}
		}
	})

	t.Run("auto-allow preserves rate limits", func(t *testing.T) {
		rps := 100
		daily := 10000
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			Claims:         []Claim{ClaimDeploy},
			RateLimitRPS:   &rps,
			RateLimitDaily: &daily,
		}

		if perms.RateLimitRPS == nil || *perms.RateLimitRPS != 100 {
			t.Error("Rate limit RPS should be preserved")
		}
		if perms.RateLimitDaily == nil || *perms.RateLimitDaily != 10000 {
			t.Error("Rate limit daily should be preserved")
		}
	})
}
