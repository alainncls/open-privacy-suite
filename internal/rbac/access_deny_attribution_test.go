package rbac

import (
	"context"
	"testing"
	"time"
)

// TestDenyResultsCarryResolvedOrg is the RD-1199 regression guard: once
// CheckAccess has resolved the caller's org, every deny from the later phases
// (method allowlist, eth_getLogs address validation, contract access) must
// carry OrgID/UserID. Denies used to return without them, so access_logs rows
// were written with a NULL org_id and an org's own RBAC denials never showed
// up in the tier-2 per-org audit view — only the fleet-wide super-admin scope
// matched NULL.
func TestDenyResultsCarryResolvedOrg(t *testing.T) {
	ctx := context.Background()
	store := NewMockCrossOrgStore()
	setupCrossOrgTestScenario(store)
	controller := NewAccessController(store, 5*time.Minute)

	contractA := "0xaaaa000000000000000000000000000000000001"
	contractB := "0xbbbb000000000000000000000000000000000002"

	attributed := []struct {
		name string
		req  *AccessCheckRequest
	}{
		{
			// checkMethodAllowed: not in group-a's allowed_methods.
			"method_not_allowed deny",
			&AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         "eth_getTransactionReceipt",
				Params:         []any{"0xabc"},
			},
		},
		{
			// validateContractAccess: contractB belongs to org-b.
			"cross-org contract deny",
			&AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         "eth_call",
				Params:         []any{map[string]any{"to": contractB, "data": "0x"}, "latest"},
				TargetAddress:  contractB,
			},
		},
		{
			// checkEthGetLogsAccess: filter contains another org's address.
			"eth_getLogs address deny",
			&AccessCheckRequest{
				UserExternalID: "did:test:user-a",
				Method:         "eth_getLogs",
				Params:         []any{map[string]any{"address": contractB, "fromBlock": "0x0", "toBlock": "latest"}},
				TargetAddress:  contractB,
			},
		},
	}

	for _, tt := range attributed {
		t.Run(tt.name, func(t *testing.T) {
			result, err := controller.CheckAccess(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed {
				t.Fatalf("expected deny, got allow")
			}
			if result.OrgID != "org-a" {
				t.Errorf("deny OrgID = %q, want %q — unattributed denials are invisible in the per-org audit view", result.OrgID, "org-a")
			}
			if result.UserID != "user-a" {
				t.Errorf("deny UserID = %q, want %q", result.UserID, "user-a")
			}
		})
	}

	// Control: the allow path keeps its attribution (pre-RD-1199 behavior).
	t.Run("allow still attributed", func(t *testing.T) {
		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Fatalf("expected allow, got deny: %s", result.Reason)
		}
		if result.OrgID != "org-a" || result.UserID != "user-a" {
			t.Errorf("allow attribution regressed: OrgID=%q UserID=%q", result.OrgID, result.UserID)
		}
	})

	// Controls: pre-org denials legitimately stay unattributed (NULL org_id,
	// super-admin-only rows).
	store.users["did:test:banned-x"] = &User{ID: "user-banned-x", ExternalID: "did:test:banned-x", KYC: true, Banned: true}
	preOrg := []struct {
		name string
		req  *AccessCheckRequest
	}{
		{"anonymous deny", &AccessCheckRequest{UserExternalID: "", Method: "eth_call"}},
		{"unknown user deny", &AccessCheckRequest{UserExternalID: "did:test:ghost", Method: "eth_call"}},
		{"banned user deny", &AccessCheckRequest{UserExternalID: "did:test:banned-x", Method: "eth_call"}},
		{"globally blocked method deny", &AccessCheckRequest{UserExternalID: "did:test:user-a", Method: "personal_unlockAccount"}},
	}
	for _, tt := range preOrg {
		t.Run(tt.name, func(t *testing.T) {
			result, err := controller.CheckAccess(ctx, tt.req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed {
				t.Fatalf("expected deny, got allow")
			}
			if result.OrgID != "" {
				t.Errorf("pre-org deny must stay unattributed, got OrgID=%q", result.OrgID)
			}
		})
	}
}
