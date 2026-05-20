// HTTP client for the proxy's /auth/request → /auth/verify exchange.
// Mirrors the Go client (tools/wallet-emulator/client.go) so the two
// emulator tracks talk to the proxy identically.

import type { AuthorizationRequestMessage } from "@0xpolygonid/js-sdk";

export interface AuthRequestResponse {
  sessionId: string;
  authRequest: AuthorizationRequestMessage;
}

export interface AuthVerifyResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

const REQUEST_TIMEOUT_MS = 30_000;

export async function fetchAuthRequest(proxyURL: string): Promise<AuthRequestResponse> {
  const target = joinURL(proxyURL, "/auth/request");
  const resp = await fetchWithTimeout(target, { method: "POST" });
  const body = await resp.text();
  if (!resp.ok) {
    throw new Error(`${target}: ${resp.status} ${resp.statusText} — ${body}`);
  }
  let parsed: { session_id?: string; auth_request?: AuthorizationRequestMessage };
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(`decode auth-request body: ${(err as Error).message} (body: ${body})`);
  }
  if (!parsed.session_id || !parsed.auth_request) {
    throw new Error(`auth-request response missing session_id / auth_request (body: ${body})`);
  }
  return { sessionId: parsed.session_id, authRequest: parsed.auth_request };
}

export async function postAuthVerify(proxyURL: string, sessionId: string, jwzToken: string): Promise<AuthVerifyResponse> {
  const target = joinURL(proxyURL, "/auth/verify");
  const resp = await fetchWithTimeout(target, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId, jwz_token: jwzToken }),
  });
  return parseTokenResponse(target, resp);
}

// postAuthCallback submits the JWZ via the production-style callback
// endpoint: POST /auth/callback?session=<id> with `{"token": "..."}`
// as body. Mirrors what a real mobile wallet does. The proxy handler
// also accepts `{"jwz_token": "..."}` for parity (auth.go:407-410), but
// we send `token` since that's the canonical mobile-wallet shape.
export async function postAuthCallback(proxyURL: string, sessionId: string, jwzToken: string): Promise<AuthVerifyResponse> {
  const target = joinURL(proxyURL, `/auth/callback?session=${encodeURIComponent(sessionId)}`);
  const resp = await fetchWithTimeout(target, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token: jwzToken }),
  });
  return parseTokenResponse(target, resp);
}

async function parseTokenResponse(target: string, resp: Response): Promise<AuthVerifyResponse> {
  const body = await resp.text();
  if (!resp.ok) {
    throw new Error(`${target}: ${resp.status} ${resp.statusText} — ${body}`);
  }
  let parsed: { access_token?: string; refresh_token?: string; expires_in?: number };
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(`decode token-response body: ${(err as Error).message} (body: ${body})`);
  }
  if (!parsed.access_token) {
    throw new Error(`token-response missing access_token (body: ${body})`);
  }
  return {
    accessToken: parsed.access_token,
    refreshToken: parsed.refresh_token ?? "",
    expiresIn: parsed.expires_in ?? 0,
  };
}

function joinURL(base: string, path: string): string {
  return new URL(path, base.endsWith("/") ? base : base + "/").toString();
}

async function fetchWithTimeout(input: string, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}
