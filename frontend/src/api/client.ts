import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface AccessLog {
  id: number;
  external_id: string;
  method: string;
  status_code: number;
  ip_address: string;
  created_at: string;
}

export const logsApi = {
  list: (limit?: number) =>
    api.get<AccessLog[]>('/logs', { params: { limit } }),
};

export interface StatusResponse {
  proxy: {
    status: string;
    port: string;
  };
  node: {
    status: string;
    url: string;
    latency_ms: number;
    error?: string;
  };
}

export interface TestRequestResponse {
  success: boolean;
  result?: unknown;
  error?: string;
  latency_ms: number;
  blocked: boolean;
}

export const statusApi = {
  get: () => api.get<StatusResponse>('/status'),
};

export const testApi = {
  send: (method: string, params: unknown[] = []) =>
    api.post<TestRequestResponse>('/test-request', { method, params }),
};

export default api;
