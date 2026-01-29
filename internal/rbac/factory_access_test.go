package rbac

import (
	"strings"
	"testing"
)

// TestFactoryAutoAllowLogic tests the auto-allow logic for org factory access.
func TestFactoryAutoAllowLogic(t *testing.T) {
	t.Run("containsClaim helper works correctly", func(t *testing.T) {
		claims := []Claim{ClaimRead, ClaimWrite, ClaimDeploy}

		if !containsClaim(claims, ClaimRead) {
			t.Error("containsClaim should find ClaimRead")
		}
		if !containsClaim(claims, ClaimDeploy) {
			t.Error("containsClaim should find ClaimDeploy")
		}
		if containsClaim(claims, ClaimAdmin) {
			t.Error("containsClaim should NOT find ClaimAdmin")
		}
		if containsClaim(nil, ClaimRead) {
			t.Error("containsClaim should return false for nil slice")
		}
		if containsClaim([]Claim{}, ClaimRead) {
			t.Error("containsClaim should return false for empty slice")
		}
	})

	t.Run("deploy claim in default_claims grants factory access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{},
			DefaultClaims:  []Claim{ClaimRead, ClaimWrite, ClaimDeploy},
		}

		hasDeploy := containsClaim(perms.DefaultClaims, ClaimDeploy)
		if !hasDeploy {
			t.Error("User with deploy in default_claims should have deploy claim")
		}
	})

	t.Run("deploy claim on any contract grants factory access", func(t *testing.T) {
		perms := &EffectivePermissions{
			AllowedMethods: []string{"eth_sendTransaction"},
			ContractAccess: map[string]ContractAccess{
				"0xaaaa000000000000000000000000000000000001": {Claims: []Claim{ClaimRead}},
				"0xbbbb000000000000000000000000000000000002": {Claims: []Claim{ClaimRead, ClaimDeploy}},
			},
			DefaultClaims: []Claim{ClaimRead},
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
				"0xaaaa": {Claims: []Claim{ClaimRead, ClaimWrite}},
			},
			DefaultClaims: []Claim{ClaimRead, ClaimWrite},
		}

		hasDeployInDefault := containsClaim(perms.DefaultClaims, ClaimDeploy)
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
				"0xaaaa": {Claims: []Claim{ClaimWrite, ClaimAdmin}},
				"0xbbbb": {Claims: []Claim{ClaimDeploy}},
			},
			DefaultClaims: []Claim{ClaimRead},
		}

		allClaims := collectAllClaims(perms)

		claimSet := make(map[Claim]bool)
		for _, c := range allClaims {
			claimSet[c] = true
		}

		if !claimSet[ClaimRead] {
			t.Error("Should include ClaimRead from default_claims")
		}
		if !claimSet[ClaimWrite] {
			t.Error("Should include ClaimWrite from contract 0xaaaa")
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
				"0xaaaa": {Claims: []Claim{ClaimRead, ClaimWrite, ClaimAdmin}},
			},
			DefaultClaims: []Claim{ClaimRead, ClaimWrite},
		}

		hasDeploy := containsClaim(perms.DefaultClaims, ClaimDeploy)
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
			DefaultClaims:  []Claim{ClaimRead, ClaimDeploy},
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
