package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	gethabi "github.com/ethereum/go-ethereum/accounts/abi"
	gethcommon "github.com/ethereum/go-ethereum/common"
)

// ExplorerVisibilityResolver resolves per-address visibility for a viewer DID.
// It is the SAME resolver the explorer redaction engine uses (db.DB.
// GetBatchVisibilityDetailed), reused on the RPC eth_call path so the two layers
// agree for any (viewer, address) pair — the CLAUDE.md access/visibility
// symmetry invariant. db.DB satisfies it; it is wired via
// JSONRPCProcessor.SetExplorerVisibilityResolver. When nil (unwired), the
// eth_call redactor fails closed for address-bearing returns.
type ExplorerVisibilityResolver interface {
	GetBatchVisibilityDetailed(ctx context.Context, viewerDID string, addresses []string) (map[string]explorer.AddressVisibility, error)
}

// redactEthCallResult applies field-level redaction to an eth_call response
// (RD-1144). eth_call return bytes are raw ABI-encoded values, so an
// address-typed return value can leak a private address the caller cannot
// otherwise see. Access to CALL the contract is already gated (RD-915 cross-org
// trace, RD-1053 intra-org grant scoping), but a RETURNED address is not
// "called", so tracing never sees it — this closes that field-level gap.
//
// Posture (mirrors the RD-875 deny-without-ABI model for logs, adapted to the
// fact that eth_call is the authorised read primitive of the network):
//
//   - ABI + method resolve, NO address anywhere in the outputs -> passthrough
//     (nothing to leak).
//   - ABI + method resolve, outputs are a flat sequence of single-word static
//     types including >= 1 address (or a bytes32 holding a left-packed address)
//     -> zero each such word whose address is not VisibilityFull to the viewer.
//   - ABI + method resolve, an address is reachable only through a dynamic /
//     array / tuple output -> FAIL CLOSED (blank): the static-slot scan cannot
//     prove the dynamic tail is address-free.
//   - ABI present but the method/selector cannot be resolved (unparseable ABI,
//     no selector, or a selector absent from the registered ABI — proxy /
//     fallback / unlisted function) -> FAIL CLOSED (blank). The contract is
//     registered, so we cannot pass an undecodable return through raw.
//   - any decode / visibility / resolver failure on an address-bearing method
//     -> FAIL CLOSED (blank). Unlike redactLogData (which returns the original
//     bytes on a decode error — safe there because logs pass an upstream no-ABI
//     deny gate), eth_call has no upstream gate, so the original bytes must
//     never be returned once we suspect an embedded private address.
//   - genuinely no resolvable ABI (unregistered contract) -> governed by
//     denyWithoutABI: false (default) = passthrough (documented residual,
//     closeable by registering the ABI); true = FAIL CLOSED (blank). A
//     privacy-vs-usability choice surfaced for operator/Legal sign-off.
//
// "Blank" replaces the result with "0x" (empty return data).
func redactEthCallResult(
	ctx context.Context,
	respBody []byte,
	to string,
	callData string,
	viewerDID string,
	abiProvider rbac.ABIProvider,
	vis ExplorerVisibilityResolver,
	denyWithoutABI bool,
) []byte {
	var resp struct {
		Result *string          `json:"result"`
		Error  *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return respBody // not a shape we recognise — leave untouched
	}
	if resp.Error != nil || resp.Result == nil {
		return respBody
	}
	resultHex := *resp.Result
	if resultHex == "" || resultHex == "0x" {
		return respBody // no return data — nothing to redact
	}

	blank := func() []byte {
		return []byte(`{"jsonrpc":"2.0","id":` + rpcResponseID(respBody) + `,"result":"0x"}`)
	}

	// Genuine no-ABI case: no target, or the contract has no registered ABI.
	// This is the ONLY place denyWithoutABI applies — the operator's
	// privacy-vs-usability choice for contracts they haven't registered.
	if to == "" || abiProvider == nil {
		if denyWithoutABI {
			return blank()
		}
		return respBody
	}
	abiJSON := abiProvider.GetContractABI(strings.ToLower(to))
	if abiJSON == "" {
		if denyWithoutABI {
			return blank()
		}
		return respBody
	}

	// ABI present -> the contract IS registered. From here on, a return we
	// cannot decode must be blanked, NEVER passed through raw, even when
	// denyWithoutABI is false: an unparseable ABI, an unidentifiable selector,
	// or a selector absent from the registered ABI (a proxy / fallback /
	// unlisted function the caller is authorised to invoke) all mean we cannot
	// prove the return is address-free, so we fail closed. (A viewer with broad
	// access to a registered contract can call any selector — access.go gates
	// the contract, not every function — so this branch is reachable.)
	parsed, err := gethabi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return blank()
	}
	selector := selectorBytes(callData)
	if selector == nil {
		return blank()
	}
	method, err := parsed.MethodById(selector)
	if err != nil || method == nil {
		return blank()
	}

	// Nothing address-bearing in the declared outputs -> nothing to leak.
	// argsContainAddress catches an address anywhere (incl. nested); the
	// top-level bytes32 check catches a `bytes32` that may hold a left-packed
	// address, mirroring the log redactor (redactLogData). Dynamic bytes32
	// collections are deliberately NOT flagged here — they pass through rather
	// than over-blanking legitimate hash arrays (an accepted residual).
	if !argsContainAddress(method.Outputs) && !hasTopLevelBytes32(method.Outputs) {
		return respBody
	}

	// Address present. We can only word-zero a FLAT sequence of single-word
	// static outputs; any dynamic / array / tuple output that carries an
	// address defeats the static-slot scan -> fail closed.
	if !allSingleWordStatic(method.Outputs) {
		return blank()
	}

	resultBytes, err := decodeHexBytes(resultHex)
	if err != nil || len(resultBytes) != 32*len(method.Outputs) {
		return blank() // truncated / garbage / unexpected layout
	}

	// Collect the address outputs and batch-resolve their visibility.
	addrSet := make(map[string]struct{})
	addrWords := make(map[int]string) // output index -> lowercased address
	for i, out := range method.Outputs {
		word := resultBytes[i*32 : (i+1)*32]
		// A bytes32 output may carry a left-packed address (12 leading zero
		// bytes) — the same pattern the log redactor scrubs. Only treat it as an
		// address when it looks like one, so real 32-byte hashes pass untouched.
		isPackedAddr := out.Type.T == gethabi.FixedBytesTy && out.Type.Size == 32 && wordIsAddressLike(word)
		if out.Type.T == gethabi.AddressTy || isPackedAddr {
			a := strings.ToLower(gethcommon.BytesToAddress(word).Hex())
			addrWords[i] = a
			addrSet[a] = struct{}{}
		}
	}
	if len(addrWords) == 0 {
		return respBody // defensive — argsContainAddress was true, so unreachable
	}
	if vis == nil {
		return blank() // resolver unwired -> cannot prove safety
	}
	addrs := make([]string, 0, len(addrSet))
	for a := range addrSet {
		addrs = append(addrs, a)
	}
	visMap, err := vis.GetBatchVisibilityDetailed(ctx, viewerDID, addrs)
	if err != nil {
		return blank() // visibility lookup failed -> fail closed
	}

	out := make([]byte, len(resultBytes))
	copy(out, resultBytes)
	changed := false
	for i, addr := range addrWords {
		av, ok := visMap[addr]
		if !ok || av.Level != explorer.VisibilityFull {
			for b := i * 32; b < (i+1)*32; b++ {
				out[b] = 0
			}
			changed = true
		}
	}
	if !changed {
		return respBody
	}
	return []byte(`{"jsonrpc":"2.0","id":` + rpcResponseID(respBody) + `,"result":"0x` + hex.EncodeToString(out) + `"}`)
}

// hasTopLevelBytes32 reports whether any top-level output is a bytes32, which
// may hold a left-packed address. Intentionally NOT recursive: a dynamic
// bytes32 collection (bytes32[]) is a SliceTy at the top level and is left to
// pass through rather than over-blanked.
func hasTopLevelBytes32(args gethabi.Arguments) bool {
	for i := range args {
		if args[i].Type.T == gethabi.FixedBytesTy && args[i].Type.Size == 32 {
			return true
		}
	}
	return false
}

// wordIsAddressLike reports whether a 32-byte ABI word is a left-padded address
// (high 12 bytes all zero) — the heuristic the log redactor uses to decide a
// bytes32 slot is carrying an address rather than a hash.
func wordIsAddressLike(word []byte) bool {
	if len(word) != 32 {
		return false
	}
	for _, b := range word[:12] {
		if b != 0 {
			return false
		}
	}
	return true
}

// selectorBytes extracts the 4-byte function selector from calldata hex.
func selectorBytes(callData string) []byte {
	d := strings.TrimPrefix(strings.ToLower(callData), "0x")
	if len(d) < 8 {
		return nil
	}
	b, err := hex.DecodeString(d[:8])
	if err != nil {
		return nil
	}
	return b
}

// decodeHexBytes decodes a 0x-prefixed (or bare) hex string into bytes.
func decodeHexBytes(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

// argsContainAddress reports whether any argument's type embeds an address,
// recursing through slices, arrays, and tuples.
func argsContainAddress(args gethabi.Arguments) bool {
	for i := range args {
		if typeContainsAddress(args[i].Type) {
			return true
		}
	}
	return false
}

func typeContainsAddress(t gethabi.Type) bool {
	switch t.T {
	case gethabi.AddressTy:
		return true
	case gethabi.SliceTy, gethabi.ArrayTy:
		return t.Elem != nil && typeContainsAddress(*t.Elem)
	case gethabi.TupleTy:
		for _, et := range t.TupleElems {
			if et != nil && typeContainsAddress(*et) {
				return true
			}
		}
	}
	return false
}

// allSingleWordStatic reports whether every argument is a single 32-byte static
// type, so the return is a flat sequence of words (output i occupies word i).
// Anything dynamic, array, or tuple makes the word layout offset-based, which
// the address-zeroing scan does not handle -> caller fails closed.
func allSingleWordStatic(args gethabi.Arguments) bool {
	for i := range args {
		switch args[i].Type.T {
		case gethabi.AddressTy, gethabi.BoolTy, gethabi.IntTy, gethabi.UintTy,
			gethabi.FixedBytesTy, gethabi.HashTy, gethabi.FunctionTy:
			// single 32-byte word
		default:
			return false
		}
	}
	return true
}
