// End-to-end auth flow:
//   POST /auth/request  →  AuthorizationRequestMessage
//   AuthHandler.handleAuthorizationRequest(did, requestBytes) → JWZ
//   POST /auth/verify   →  { access_token, ... }
//
// The SDK's AuthHandler is the work-horse. We give it:
//   - a PackageManager with DefaultZKPPacker registered (which knows
//     how to load the AuthV2 wasm + zkey from FSCircuitStorage and
//     call ProofService.generateAuthInputs under the hood),
//   - a ProofService bound to the rehydrated IdentityWallet +
//     CredentialWallet + EthStateStorage (gist proof) + circuit
//     storage,
// then call handleAuthorizationRequest(did, requestBytes). The DataPrepareHandlerFunc
// shim inside DefaultZKPPacker grabs the BJJ signer from the wallet and
// produces the AuthV2 inputs (verified in node_modules/@0xpolygonid/
// js-sdk/dist/node/esm/index.js lines 6796-6818).

import { homedir } from "node:os";
import { join } from "node:path";
import { stat } from "node:fs/promises";

import {
  AuthHandler,
  PackageManager,
  DefaultZKPPacker,
  PlainPacker,
  ProofService,
  PROTOCOL_CONSTANTS,
  byteEncoder,
  type AuthorizationRequestMessage,
} from "@0xpolygonid/js-sdk";
import { FSCircuitStorage } from "@0xpolygonid/js-sdk";

import { hydrateWalletFromFile } from "./identity.js";
import { fetchAuthRequest, postAuthVerify, postAuthCallback } from "./client.js";

export interface AuthOptions {
  proxyURL: string;
  identityPath: string;
  stateRpcURL?: string | undefined;
  artifactsDir?: string | undefined;
  useCallbackEndpoint?: boolean | undefined;
}

const DEFAULT_ARTIFACTS_DIR = join(homedir(), ".privado-circuits");

// Privado mainnet RPC default. Used by EthStateStorage in ProofService
// to fetch the gist proof for the auth-v2 circuit's public input. An
// operator can override with --state-rpc if they have a dedicated node.
const DEFAULT_PRIVADO_STATE_RPC = "https://rpc-mainnet.privado.id";

export async function runAuth(opts: AuthOptions): Promise<string> {
  const artifactsDir = opts.artifactsDir ?? DEFAULT_ARTIFACTS_DIR;
  await verifyArtifactsLayout(artifactsDir);

  const stateRpcURL = opts.stateRpcURL ?? DEFAULT_PRIVADO_STATE_RPC;
  process.stderr.write(`[wallet-emulator-js] using state RPC ${stateRpcURL}\n`);
  process.stderr.write(`[wallet-emulator-js] using circuits dir ${artifactsDir}\n`);

  // 1. Rehydrate the wallet from disk (same DID + state as `identity init`).
  const { wallet, credentialWallet, dataStorage, did, identity } = await hydrateWalletFromFile(
    opts.identityPath,
    stateRpcURL,
  );
  process.stderr.write(`[wallet-emulator-js] rehydrated DID ${identity.did} state ${identity.state}\n`);

  // 2. Build circuit storage + proof service + package manager.
  const circuitStorage = new FSCircuitStorage({ dirname: artifactsDir });
  const proofService = new ProofService(
    wallet,
    credentialWallet,
    circuitStorage,
    dataStorage.states,
  );

  const packageManager = new PackageManager();
  packageManager.registerPackers([
    new DefaultZKPPacker(circuitStorage, proofService),
    new PlainPacker(),
  ]);

  const authHandler = new AuthHandler(packageManager, proofService);

  // 3. Fetch the AuthorizationRequestMessage off the proxy.
  const { sessionId, authRequest } = await fetchAuthRequest(opts.proxyURL);
  process.stderr.write(
    `[wallet-emulator-js] received auth-request session=${sessionId} thid=${authRequest.thid ?? "?"}\n`,
  );

  // 4. Serialise the request back to bytes — AuthHandler.handleAuthorizationRequest
  //    expects the raw protocol envelope. The proxy returns it as a
  //    parsed JSON object, so we JSON-stringify and UTF-8 encode.
  const requestBytes = byteEncoder.encode(JSON.stringify(authRequest as AuthorizationRequestMessage));

  // 5. Generate the JWZ. AuthHandler walks the request's `scope` (empty
  //    for the proxy's basic auth flow) and packs an AuthV2-only JWZ.
  const { token } = await authHandler.handleAuthorizationRequest(did, requestBytes, {
    mediaType: PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
  });
  process.stderr.write(`[wallet-emulator-js] generated JWZ (${token.length} chars)\n`);

  // 6. Submit to the proxy. /auth/verify is the canonical dev path;
  //    /auth/callback?session=<id> is the production wallet-emulating
  //    path. Both return the same {access_token, ...} shape.
  let accessToken: string;
  if (opts.useCallbackEndpoint) {
    const resp = await postAuthCallback(opts.proxyURL, sessionId, token);
    accessToken = resp.accessToken;
  } else {
    const resp = await postAuthVerify(opts.proxyURL, sessionId, token);
    accessToken = resp.accessToken;
  }
  return accessToken;
}

// verifyArtifactsLayout checks that the expected AuthV2 circuit files
// are present under <dir>/authV2/. FSCircuitStorage will throw a less
// helpful error deep inside the proof generation step if they're
// missing; surface the operator-actionable message up-front.
async function verifyArtifactsLayout(dir: string): Promise<void> {
  const wasm = join(dir, "authV2", "circuit.wasm");
  const zkey = join(dir, "authV2", "circuit_final.zkey");
  const vkey = join(dir, "authV2", "verification_key.json");
  for (const f of [wasm, zkey, vkey]) {
    try {
      await stat(f);
    } catch {
      throw new Error(
        `missing circuit artifact ${f}.\n` +
          `Download the canonical Privado circuits and unpack them so the layout is:\n` +
          `    ${dir}/authV2/circuit.wasm\n` +
          `    ${dir}/authV2/circuit_final.zkey\n` +
          `    ${dir}/authV2/verification_key.json\n` +
          `Canonical source: https://circuits.privado.id/latest.zip (see the SDK README).\n` +
          `Override the location with \`--artifacts <dir>\`.`,
      );
    }
  }
}
