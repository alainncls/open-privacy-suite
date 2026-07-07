package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/explorer"

	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
)

// --- test doubles -----------------------------------------------------------

type mockABIProvider struct{ abis map[string]string }

func (m *mockABIProvider) GetContractABI(address string) string {
	return m.abis[strings.ToLower(address)]
}

type mockVisResolver struct {
	levels map[string]explorer.VisibilityLevel
	err    error
}

func (m *mockVisResolver) GetBatchVisibilityDetailed(_ context.Context, _ string, addrs []string) (map[string]explorer.AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	res := make(map[string]explorer.AddressVisibility)
	for _, a := range addrs {
		lvl, ok := m.levels[strings.ToLower(a)]
		if !ok {
			lvl = explorer.VisibilityHidden
		}
		res[strings.ToLower(a)] = explorer.AddressVisibility{Level: lvl}
	}
	return res, nil
}

// --- helpers ----------------------------------------------------------------

func selectorFor(t *testing.T, abiJSON, method string) string {
	t.Helper()
	parsed, err := gethabi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Fatalf("parse abi: %v", err)
	}
	m, ok := parsed.Methods[method]
	if !ok {
		t.Fatalf("method %q not in abi", method)
	}
	return "0x" + hex.EncodeToString(m.ID)
}

func addrWord(addr string) string {
	a := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return strings.Repeat("0", 64-len(a)) + a
}

func uintWord(v uint64) string {
	h := hex.EncodeToString([]byte{
		byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32),
		byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v),
	})
	return strings.Repeat("0", 64-len(h)) + h
}

func rpcResult(resultHex string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"result":"` + resultHex + `"}`)
}

func resultOf(t *testing.T, body []byte) string {
	t.Helper()
	var r struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("bad body %q: %v", body, err)
	}
	return r.Result
}

const (
	ownerABI    = `[{"type":"function","name":"owner","inputs":[],"outputs":[{"type":"address"}]}]`
	balanceABI  = `[{"type":"function","name":"balanceOf","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]}]`
	ownersABI   = `[{"type":"function","name":"getOwners","inputs":[],"outputs":[{"type":"address[]"}]}]`
	getCfgABI   = `[{"type":"function","name":"getConfig","inputs":[],"outputs":[{"type":"address"},{"type":"uint256"}]}]`
	toContract  = "0xcccccccccccccccccccccccccccccccccccccccc"
	privAddress = "0x1111111111111111111111111111111111111111"
)

// --- tests ------------------------------------------------------------------

func TestRedactEthCall_AddressOutput_RedactedForUnauthorized(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{toContract: ownerABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{privAddress: explorer.VisibilityRedacted}}
	body := rpcResult("0x" + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, ownerABI, "owner"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+addrWord("0x0000000000000000000000000000000000000000") {
		t.Errorf("address word should be zeroed for unauthorized viewer, got %s", got)
	}
}

func TestRedactEthCall_AddressOutput_RealForAuthorized(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{toContract: ownerABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{privAddress: explorer.VisibilityFull}}
	body := rpcResult("0x" + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, ownerABI, "owner"), "did:owner", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+addrWord(privAddress) {
		t.Errorf("authorized viewer should see the real address, got %s", got)
	}
}

func TestRedactEthCall_NoAddressOutput_PassesThrough(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{toContract: balanceABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	body := rpcResult("0x" + uintWord(12345))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, balanceABI, "balanceOf"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+uintWord(12345) {
		t.Errorf("uint256 return (no address) must pass through, got %s", got)
	}
}

func TestRedactEthCall_DynamicAddressOutput_FailsClosed(t *testing.T) {
	// address[] — the address lives in the dynamic tail; the static-slot scan
	// can't handle it, so the whole return must be blanked.
	abis := &mockABIProvider{abis: map[string]string{toContract: ownersABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	// offset(0x20) + len(1) + one address word — realistic abi encoding.
	body := rpcResult("0x" + uintWord(32) + uintWord(1) + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, ownersABI, "getOwners"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x" {
		t.Errorf("address[] return must be blanked (fail-closed), got %s", got)
	}
}

func TestRedactEthCall_DecodeError_FailsClosed(t *testing.T) {
	// Truncated return for an address method -> layout mismatch -> blank, never
	// pass the raw bytes through.
	abis := &mockABIProvider{abis: map[string]string{toContract: ownerABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	body := rpcResult("0x1234") // far too short for a 32-byte address word
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, ownerABI, "owner"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x" {
		t.Errorf("truncated address return must be blanked, got %s", got)
	}
}

func TestRedactEthCall_NilResolver_FailsClosed(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{toContract: ownerABI}}
	body := rpcResult("0x" + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, ownerABI, "owner"), "did:eve", abis, nil, false)
	if got := resultOf(t, out); got != "0x" {
		t.Errorf("nil resolver must blank an address-bearing return, got %s", got)
	}
}

func TestRedactEthCall_NoABI_PosturePassthroughVsDeny(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{}} // no ABI for toContract
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	body := rpcResult("0x" + addrWord(privAddress))

	// Default (deny=false): passthrough — current behaviour, documented residual.
	out := redactEthCallResult(context.Background(), body, toContract, "0xdeadbeef", "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+addrWord(privAddress) {
		t.Errorf("no-ABI + deny=false should pass through, got %s", got)
	}
	// Strict (deny=true): fail closed.
	out = redactEthCallResult(context.Background(), body, toContract, "0xdeadbeef", "did:eve", abis, vis, true)
	if got := resultOf(t, out); got != "0x" {
		t.Errorf("no-ABI + deny=true should blank, got %s", got)
	}
}

func TestRedactEthCall_MultiReturn_ZeroesOnlyAddressWord(t *testing.T) {
	// getConfig() returns (address token, uint256 fee). Redact the address word,
	// preserve the fee word.
	abis := &mockABIProvider{abis: map[string]string{toContract: getCfgABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{privAddress: explorer.VisibilityRedacted}}
	body := rpcResult("0x" + addrWord(privAddress) + uintWord(42))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, getCfgABI, "getConfig"), "did:eve", abis, vis, false)
	want := "0x" + addrWord("0x0000000000000000000000000000000000000000") + uintWord(42)
	if got := resultOf(t, out); got != want {
		t.Errorf("address word zeroed + fee preserved expected\n want %s\n got  %s", want, got)
	}
}

// A registered contract called with a selector absent from its ABI (proxy /
// fallback / unlisted function the caller is authorized to invoke) cannot be
// decoded -> must blank, NOT pass raw bytes through, even with deny=false.
// Guards the audit-found selector-miss leak.
func TestRedactEthCall_RegisteredContract_UnknownSelector_FailsClosed(t *testing.T) {
	abis := &mockABIProvider{abis: map[string]string{toContract: ownerABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{privAddress: explorer.VisibilityRedacted}}
	body := rpcResult("0x" + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, "0xdeadbeef", "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x" {
		t.Errorf("unknown selector on a registered contract must blank (fail-closed), got %s", got)
	}
}

// A bytes32 output holding a left-packed private address is redacted, mirroring
// the log redactor's bytes32 handling (CLAUDE.md access/visibility symmetry).
func TestRedactEthCall_Bytes32PackedAddress_Redacted(t *testing.T) {
	const bytes32ABI = `[{"type":"function","name":"slot","inputs":[],"outputs":[{"type":"bytes32"}]}]`
	abis := &mockABIProvider{abis: map[string]string{toContract: bytes32ABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{privAddress: explorer.VisibilityRedacted}}
	body := rpcResult("0x" + addrWord(privAddress)) // address left-packed into a bytes32 slot
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, bytes32ABI, "slot"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+addrWord("0x0000000000000000000000000000000000000000") {
		t.Errorf("bytes32-packed private address should be zeroed, got %s", got)
	}
}

// A bytes32 output holding a real hash (not address-shaped) is left untouched —
// the left-padding heuristic prevents over-redacting hashes.
func TestRedactEthCall_Bytes32Hash_PassesThrough(t *testing.T) {
	const bytes32ABI = `[{"type":"function","name":"slot","inputs":[],"outputs":[{"type":"bytes32"}]}]`
	abis := &mockABIProvider{abis: map[string]string{toContract: bytes32ABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	hash := "ff" + strings.Repeat("ab", 31) // 32 bytes, high byte non-zero
	body := rpcResult("0x" + hash)
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, bytes32ABI, "slot"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got != "0x"+hash {
		t.Errorf("non-address-like bytes32 hash must pass through, got %s", got)
	}
}

// A dynamic bytes32[] is deliberately NOT over-blanked (top-level SliceTy, no
// AddressTy) — it passes through rather than corrupting legitimate hash arrays.
func TestRedactEthCall_DynamicBytes32_PassesThrough(t *testing.T) {
	const bytes32ArrABI = `[{"type":"function","name":"slots","inputs":[],"outputs":[{"type":"bytes32[]"}]}]`
	abis := &mockABIProvider{abis: map[string]string{toContract: bytes32ArrABI}}
	vis := &mockVisResolver{levels: map[string]explorer.VisibilityLevel{}}
	body := rpcResult("0x" + uintWord(32) + uintWord(1) + addrWord(privAddress))
	out := redactEthCallResult(context.Background(), body, toContract, selectorFor(t, bytes32ArrABI, "slots"), "did:eve", abis, vis, false)
	if got := resultOf(t, out); got == "0x" {
		t.Error("bytes32[] should pass through (not over-blanked)")
	}
}
