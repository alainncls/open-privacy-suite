package main

// Authorization-flow orchestrator. Ties identity + circuit artifacts +
// HTTP plumbing into the canonical /auth/request → JWZ → /auth/verify
// → JWT pipeline.
//
// Phase 1 status (RD-947): identity bootstrap and HTTP plumbing are
// production-ready; the auth-v2 proof generation has its surface
// scaffolded but the input-preparation step (see proof.go) is the
// follow-up. Until that lands, `authFlow` returns the auth-request
// payload along with a clear "circuit-input prep not implemented"
// error so operators can confirm the proxy side is reachable without
// being misled into thinking auth succeeded.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// authFlow runs the end-to-end flow against `proxyURL` using the
// identity at `identityPath`. Circuit artifacts (`.wasm` + `.zkey`)
// are loaded from `artifactsDir`. On success returns the access JWT
// the proxy issued.
func authFlow(proxyURL, identityPath, artifactsDir string) (string, error) {
	idf, err := loadIdentity(identityPath)
	if err != nil {
		return "", err
	}

	wasm, provingKey, err := loadCircuitArtifacts(artifactsDir)
	if err != nil {
		return "", fmt.Errorf("circuit artifacts: %w", err)
	}

	ctx := context.Background()
	authReq, err := fetchAuthRequest(ctx, proxyURL)
	if err != nil {
		return "", fmt.Errorf("fetch auth-request: %w", err)
	}

	// Pack the wallet's authorization response into a JWZ. The packer
	// owns proof generation: it serialises the payload, invokes the
	// auth-v2 witness generator + groth16 prover, and wraps the proof
	// in a JWZ envelope per RFC-7519 conventions.
	jwz, err := packAuthResponse(idf, &authReq.Request, wasm, provingKey)
	if err != nil {
		// Surface the auth-request envelope alongside the error so the
		// operator can confirm the proxy side is reachable even when
		// proof generation is unwired (Phase 1 ↔ Phase 1b transition).
		raw, _ := json.MarshalIndent(authReq.Request, "", "  ")
		return "", fmt.Errorf("pack JWZ: %w\n\nauth-request from proxy (for debugging):\n%s", err, string(raw))
	}

	verify, err := postAuthVerify(ctx, proxyURL, authReq.SessionID, jwz)
	if err != nil {
		return "", fmt.Errorf("/auth/verify: %w", err)
	}
	return verify.AccessToken, nil
}

// loadCircuitArtifacts reads the auth-v2 circuit .wasm (witness
// generator) and .zkey (groth16 proving key) from disk. SHA-256
// integrity is enforced by the Makefile target that fetches them; we
// don't re-verify here because that would couple the binary to the
// pinned hashes and break local-build flexibility. The Makefile is
// the trust boundary.
func loadCircuitArtifacts(dir string) (wasm, provingKey []byte, err error) {
	wasmPath := filepath.Join(dir, "authV2.wasm")
	zkeyPath := filepath.Join(dir, "authV2.zkey")

	wasm, err = os.ReadFile(wasmPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w (run `make wallet-emulator-fetch-artifacts`)", wasmPath, err)
	}
	provingKey, err = os.ReadFile(zkeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w (run `make wallet-emulator-fetch-artifacts`)", zkeyPath, err)
	}
	return wasm, provingKey, nil
}
