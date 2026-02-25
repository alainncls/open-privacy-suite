import axios, { AxiosHeaders } from 'axios';
import type { InternalAxiosRequestConfig } from 'axios';

const ADMIN_TOKEN_STORAGE_KEYS = [
  'privacy_proxy_admin_api_token',
  'privacy_proxy_admin_token',
  'admin_api_token',
] as const;

function getStoredAdminToken(): string {
  for (const key of ADMIN_TOKEN_STORAGE_KEYS) {
    const localValue = window.localStorage.getItem(key)?.trim();
    if (localValue) {
      return localValue;
    }

    const sessionValue = window.sessionStorage.getItem(key)?.trim();
    if (sessionValue) {
      return sessionValue;
    }
  }

  return '';
}

export function getAdminToken(): string {
  const envToken = (import.meta.env.VITE_ADMIN_API_TOKEN as string | undefined)?.trim();
  return envToken || getStoredAdminToken();
}

function applyAdminHeaders(config: InternalAxiosRequestConfig): InternalAxiosRequestConfig {
  const token = getAdminToken();
  if (!token) {
    return config;
  }

  const headers = config.headers instanceof AxiosHeaders
    ? config.headers
    : new AxiosHeaders(config.headers);

  if (!headers.has('X-Admin-Token') && !headers.has('Authorization')) {
    headers.set('X-Admin-Token', token);
  }
  config.headers = headers;

  return config;
}

export const adminApi = axios.create({
  baseURL: '/api/v1/admin',
  headers: {
    'Content-Type': 'application/json',
  },
});

adminApi.interceptors.request.use(applyAdminHeaders);

export function createAdminClient(extraHeaders?: Record<string, string>) {
  const client = axios.create({
    baseURL: '/api/v1/admin',
    headers: {
      'Content-Type': 'application/json',
      ...(extraHeaders ?? {}),
    },
  });

  client.interceptors.request.use(applyAdminHeaders);
  return client;
}
