// End-to-end auth flow: POST /auth/request → AuthRequest → js-sdk
// AuthHandler builds + packs the auth response (proof inside JWZ) →
// POST /auth/verify → JWT.
//
// The js-sdk's AuthHandler is the work-horse: it consumes the
// AuthorizationRequestMessage we get from the proxy, walks the
// requested ZK proof scope, generates each proof against the wallet's
// trees + state, and packs the response into a JWZ. We supply the
// wallet, the proof service, and the package manager — the SDK does
// the rest.

import {
  AuthHandler,
  PackageManager,
  ZKPPacker,
  PlainPacker,
  type IProofService,
  // ProofService deps (chained construction in createProofService)
  ProofService,
  CredentialStatusType,
  CredentialStatusResolverRegistry,
  IssuerResolver,
  RHSResolver,
  OnChainResolver,
  // Constants / types
  PROTOCOL_CONSTANTS,
} from "@0xpolygonid/js-sdk";

import { loadIdentity } from "./identity.js";
import { fetchAuthRequest, postAuthVerify } from "./client.js";

export async function runAuth(proxyURL: string, identityPath: string, _stateRPC: string | undefined): Promise<string> {
  const idf = await loadIdentity(identityPath);

  // Re-hydrate the wallet from the persisted state. Phase 1b will
  // restore the BabyJubJub seed into the KMS so the AuthHandler can
  // sign the challenge for `did` — until that lands, we throw a clear
  // error rather than silently producing a half-baked envelope.
  if (idf.wallet_state.babyjub_private_key.startsWith("TODO")) {
    throw new Error(
      "wallet state placeholder detected — Phase A-1b (persistent BJJ seed restore) is not landed yet. " +
        "Until then, `identity init` and `identity show` work; `auth` cannot finish. See README.md.",
    );
  }

  // 1. Pull the AuthorizationRequestMessage off the proxy.
  const { sessionId, authRequest } = await fetchAuthRequest(proxyURL);

  // 2. Build the AuthHandler with our wallet's PackageManager + proof
  //    service. The PackageManager registers both the ZKPPacker
  //    (signs+packs JWZ via the auth-v2 circuit) and a PlainPacker
  //    (for plain protocol messages, not used in this flow but
  //    expected to be present by the SDK).
  void PROTOCOL_CONSTANTS; // silence lint until we wire the packers
  void ZKPPacker;
  void PlainPacker;
  void PackageManager;
  void AuthHandler;
  void ProofService;
  void CredentialStatusResolverRegistry;
  void CredentialStatusType;
  void IssuerResolver;
  void RHSResolver;
  void OnChainResolver;

  // TODO(RD-948 Phase A-1b): instantiate PackageManager + AuthHandler +
  //                          ProofService, generate the JWZ via
  //                          AuthHandler.handleAuthorizationRequest, post
  //                          it to /auth/verify, and return the JWT.
  void authRequest;
  void sessionId;
  void proxyURL;
  // void postAuthVerify; void IProofService;
  throw new Error(
    "auth flow not yet wired (RD-948 Phase A-1b) — see TODO in src/auth.ts. " +
      "Phase A-1a ships identity init/show + HTTP plumbing + this stub; the proof-gen + verify call drops in here.",
  );
}

// Compile-time uses so the imports above don't trip --noUnusedLocals
// once we get to Phase A-1b. Kept colocated for grep-ability.
const _alwaysImported: ReadonlyArray<unknown> = [
  IProofService as unknown,
  postAuthVerify as unknown,
];
void _alwaysImported;
