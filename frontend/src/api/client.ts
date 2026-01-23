import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
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
  result?: unknown;
  error?: string;
  latency_ms?: number;
  identity?: string;
}

export interface TestRequestResult {
  status: number;
  data: TestRequestResponse;
}

export const statusApi = {
  get: () => api.get<StatusResponse>('/status'),
};

export const testApi = {
  send: async (method: string, params: unknown[] = [], jwzToken?: string): Promise<TestRequestResult> => {
    try {
      const response = await api.post<TestRequestResponse>('/test-request', {
        method,
        params,
        ...(jwzToken && { jwz_token: jwzToken })
      });
      return { status: response.status, data: response.data };
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        // Return 4xx/5xx responses as results, not errors
        return { status: err.response.status, data: err.response.data as TestRequestResponse };
      }
      throw err;
    }
  },
};

export default api;
