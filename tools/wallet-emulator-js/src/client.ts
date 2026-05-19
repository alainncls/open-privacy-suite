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
  const body = await resp.text();
  if (!resp.ok) {
    throw new Error(`${target}: ${resp.status} ${resp.statusText} — ${body}`);
  }
  let parsed: { access_token?: string; refresh_token?: string; expires_in?: number };
  try {
    parsed = JSON.parse(body);
  } catch (err) {
    throw new Error(`decode auth-verify body: ${(err as Error).message} (body: ${body})`);
  }
  if (!parsed.access_token) {
    throw new Error(`auth-verify response missing access_token (body: ${body})`);
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
