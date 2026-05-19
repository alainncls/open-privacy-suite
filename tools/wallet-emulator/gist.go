package main

// On-chain gist proof fetcher.
//
// The auth-v2 circuit requires a proof of inclusion (or non-inclusion) for
// the wallet's identity ID in the Privado state contract's global identity
// state tree (GIST). The state contract exposes
//
//	function getGISTProof(uint256 id) view returns (IStateGistProof)
//
// where IStateGistProof carries (root, existence, siblings[64], index,
// value, auxExistence, auxIndex, auxValue). We translate that on-the-wire
// shape into the iden3 `circuits.GISTProof` the AuthV2Inputs.InputsMarshal
// consumes.
//
// We use the official iden3 contract bindings
// (github.com/iden3/contracts-abi/state/go/abi) and go-ethereum's ethclient
// rather than hand-rolling the ABI call — both are already in the proxy's
// go.mod, and using the canonical bindings keeps us drift-free when the
// state contract layout changes.

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	stateabi "github.com/iden3/contracts-abi/state/go/abi"
	circuits "github.com/iden3/go-circuits/v2"
	"github.com/iden3/go-merkletree-sql/v2"
)

// defaultPrivadoRPCURL is the public Privado mainnet RPC endpoint. Override
// via PRIVADO_RPC_URL for staging / private deployments.
//
// Picked from go-iden3-auth/v2 resolver wiring (state.NewETHResolver in
// internal/auth/privado.go) — the proxy uses the same RPC for the verifier
// side. For the wallet side we need the same data, so same endpoint.
const defaultPrivadoRPCURL = "https://rpc-mainnet.privado.id"

// defaultPrivadoStateContract mirrors auth.PrivadoMainnetStateContract from
// internal/auth/privado.go. Keep these in sync — if the proxy verifier
// uses a different contract than the wallet, the JWZ will never verify.
const defaultPrivadoStateContract = "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"

// fetchGISTProof calls getGISTProof(id) on the Privado state contract and
// converts the result into the iden3 circuits.GISTProof shape that
// AuthV2Inputs expects. Both rpcURL and contractAddr are explicit args so
// the function stays unit-testable against a forked node or mock RPC.
func fetchGISTProof(ctx context.Context, rpcURL, contractAddr string, id *big.Int) (circuits.GISTProof, error) {
	if rpcURL == "" {
		return circuits.GISTProof{}, fmt.Errorf("RPC URL is required")
	}
	if !common.IsHexAddress(contractAddr) {
		return circuits.GISTProof{}, fmt.Errorf("invalid state contract address: %q", contractAddr)
	}
	if id == nil {
		return circuits.GISTProof{}, fmt.Errorf("nil identity ID")
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return circuits.GISTProof{}, fmt.Errorf("dial %s: %w", rpcURL, err)
	}
	defer client.Close()

	caller, err := stateabi.NewStateCaller(common.HexToAddress(contractAddr), client)
	if err != nil {
		return circuits.GISTProof{}, fmt.Errorf("bind state caller: %w", err)
	}

	raw, err := caller.GetGISTProof(&bind.CallOpts{Context: ctx}, id)
	if err != nil {
		return circuits.GISTProof{}, fmt.Errorf("getGISTProof(%s): %w", id.String(), err)
	}

	return convertGISTProof(raw)
}

// convertGISTProof translates the contract-side IStateGistProof into the
// iden3-circuit-side circuits.GISTProof. Logic mirrors
// driver-did-iden3/pkg/services/registry.go:gistInfoFrom — the canonical
// converter — so we stay consistent with how the rest of the iden3 stack
// reads the same on-chain data.
func convertGISTProof(raw stateabi.IStateGistProof) (circuits.GISTProof, error) {
	root, err := merkletree.NewHashFromBigInt(raw.Root)
	if err != nil {
		return circuits.GISTProof{}, fmt.Errorf("gist root: %w", err)
	}

	siblings := make([]*merkletree.Hash, len(raw.Siblings))
	for i := range raw.Siblings {
		h, err := merkletree.NewHashFromBigInt(raw.Siblings[i])
		if err != nil {
			return circuits.GISTProof{}, fmt.Errorf("gist sibling[%d]: %w", i, err)
		}
		siblings[i] = h
	}

	// NodeAux is only populated for non-existence proofs that also carry a
	// neighbouring node (see merkletree-sql semantics + the driver-did-iden3
	// converter at registry.go:108-120).
	var nodeAux *merkletree.NodeAux
	if !raw.Existence && raw.AuxExistence {
		auxKey, err := merkletree.NewHashFromBigInt(raw.AuxIndex)
		if err != nil {
			return circuits.GISTProof{}, fmt.Errorf("gist aux index: %w", err)
		}
		auxVal, err := merkletree.NewHashFromBigInt(raw.AuxValue)
		if err != nil {
			return circuits.GISTProof{}, fmt.Errorf("gist aux value: %w", err)
		}
		nodeAux = &merkletree.NodeAux{Key: auxKey, Value: auxVal}
	}

	proof, err := merkletree.NewProofFromData(raw.Existence, siblings, nodeAux)
	if err != nil {
		return circuits.GISTProof{}, fmt.Errorf("build merkle proof from contract data: %w", err)
	}

	return circuits.GISTProof{Root: root, Proof: proof}, nil
}
