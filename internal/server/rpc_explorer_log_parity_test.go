package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestRPCExplorerLogParity_RD1214 is the cross-layer matrix parity test that
// RD-887 scoped (Stage 5) but never shipped. For ONE DB fixture it drives BOTH
// log paths and asserts they reach identical results:
//
//   - explorer: RedactionEngine.RedactLogs
//   - RPC:      rbac.FilterEventLogs (entry) + JSONRPCProcessor.redactEmbeddedLogAddresses (fields)
//
// Both resolve embedded-address visibility through the SAME db.GetBatchVisibilityDetailed
// and zero via the SAME explorer.RedactLogAddressFields, so parity is a property
// of the shared code, not a convention. The test would fail the moment either
// layer diverged on an entry verdict OR a per-address verdict — the blind spot
// that let the RPC over-share and the explorer over-mask go unnoticed.
func TestRPCExplorerLogParity_RD1214(t *testing.T) {
	ctx := context.Background()
	dbURL := sharedTestDBURL(t)
	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "parity-org", Name: "Parity", Settings: map[string]any{},
	}))
	grantedGID := wiringCreateGroup(t, database, orgID, "parity-granted", nil, false)

	emitter := "0x1111111111111111111111111111111111111111"
	emitterCID := wiringCreateContractWithABI(t, database, orgID, emitter, "Emitter", erc20ABI)
	// Wildcard event_rules so the entry decision turns purely on the grant +
	// ABI gates — the field redaction is what we are comparing.
	wiringCreateGrant(t, database, emitterCID, grantedGID, &rbac.EventRulesField{Wildcard: true})

	viewerOwn := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	thirdParty := "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
	const viewerDID = "did:viewer:parity"
	wiringCreateUserInGroup(t, database, viewerDID, grantedGID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, viewerDID, viewerOwn))

	accessCtrl := rbac.NewAccessController(database, time.Minute)
	t.Cleanup(accessCtrl.Stop)
	engine := explorer.NewRedactionEngine(noopContractStore{}, database)
	wireExplorerRedactor(engine, database, accessCtrl, noopLogParticipantStore{}, nil)

	transfer := "0x" + topicHex("Transfer(address,address,uint256)")
	ownTopic := zeroPadAddrToTopic(viewerOwn)
	thirdTopic := zeroPadAddrToTopic(thirdParty)

	// The RPC uses p.addrVisResolver (the same *db.DB) for the field step; a
	// real ABI keeps the deny-when-no-ABI gate out of the way so the entry
	// verdict turns on the grant, matching the explorer's ABI resolver.
	p := &JSONRPCProcessor{addrVisResolver: database}
	abiProv := mapABIProvider{
		strings.ToLower(emitter): erc20ABI,
	}

	t.Run("admitted log: own kept, third-party zeroed, layers identical", func(t *testing.T) {
		// Explorer.
		exLogs := []explorer.Log{{
			ID: 1, Address: emitter, TxHash: "0xtx",
			Topic0: &transfer, Topic1: &ownTopic, Topic2: &thirdTopic, Data: "0x",
		}}
		exOut, err := engine.RedactLogs(ctx, exLogs, viewerDID)
		require.NoError(t, err)
		require.Len(t, exOut, 1, "explorer must admit the granted log")

		// RPC: entry (grant admits) then field-redaction via the shared path.
		perms := &rbac.EffectivePermissions{ContractAccess: map[string]rbac.ContractAccess{
			emitter: {Claims: []rbac.Claim{}, EventRules: &rbac.EventRulesField{Wildcard: true}},
		}}
		raw := []json.RawMessage{rawLogJSON(t, emitter, []string{transfer, ownTopic, thirdTopic}, "0x")}
		admitted := rbac.FilterEventLogs(raw, perms, []string{viewerOwn}, abiProv, nil, nil)
		require.Len(t, admitted, 1, "RPC must admit the granted log (parity of the entry decision)")
		rpcOut := p.redactEmbeddedLogAddresses(ctx, viewerDID, admitted, abiProv)

		exTopic1, exTopic2 := *exOut[0].Topic1, *exOut[0].Topic2
		rpcTopics := topicsOf(t, rpcOut[0])
		rpcTopic1, rpcTopic2 := rpcTopics[1], rpcTopics[2]

		// Own address kept on both.
		require.Truef(t, strings.EqualFold(exTopic1, ownTopic), "explorer must keep own address, got %s", exTopic1)
		require.Truef(t, strings.EqualFold(rpcTopic1, ownTopic), "RPC must keep own address, got %s", rpcTopic1)
		// Third-party zeroed on both.
		require.Equal(t, zeroTopic, exTopic2, "explorer must zero third-party")
		require.Equal(t, zeroTopic, rpcTopic2, "RPC must zero third-party")
		// Strict per-address parity: identical rendered topics.
		require.Truef(t, strings.EqualFold(exTopic1, rpcTopic1) && strings.EqualFold(exTopic2, rpcTopic2),
			"PARITY VIOLATION: explorer=[%s,%s] rpc=[%s,%s]", exTopic1, exTopic2, rpcTopic1, rpcTopic2)
	})

	t.Run("foreign-org emitter dropped on BOTH layers (RD-1009 symmetry)", func(t *testing.T) {
		foreignOrg := uuid.New().String()
		require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
			ID: foreignOrg, Slug: "foreign-org", Name: "Foreign", Settings: map[string]any{},
		}))
		foreign := "0x2222222222222222222222222222222222222222"
		// Registered WITH an ABI in the foreign org, so the drop is attributable
		// to the missing grant (RD-1208), not the no-ABI gate.
		wiringCreateContractWithABI(t, database, foreignOrg, foreign, "Foreign", erc20ABI)

		ftr := transfer
		exLogs := []explorer.Log{{ID: 9, Address: foreign, TxHash: "0xtxf", Topic0: &ftr, Topic1: &thirdTopic, Data: "0x"}}
		exOut, err := engine.RedactLogs(ctx, exLogs, viewerDID)
		require.NoError(t, err)
		require.Empty(t, exOut, "explorer must DROP a foreign-org emitter's log (viewer has no grant)")

		// RPC: no ContractAccess entry for the foreign emitter → no grant → drop.
		perms := &rbac.EffectivePermissions{ContractAccess: map[string]rbac.ContractAccess{}}
		raw := []json.RawMessage{rawLogJSON(t, foreign, []string{transfer, thirdTopic}, "0x")}
		abiProvForeign := mapABIProvider{strings.ToLower(foreign): erc20ABI}
		admitted := rbac.FilterEventLogs(raw, perms, []string{viewerOwn}, abiProvForeign, nil, nil)
		require.Empty(t, admitted, "RPC must DROP a foreign-org emitter's log — symmetric with the explorer (RD-1009/RD-1208)")
	})
}
