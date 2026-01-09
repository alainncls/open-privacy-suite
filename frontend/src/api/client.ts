import axios from 'axios';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export interface AccessPolicy {
  external_id: string;
  kyc: boolean;
  allow_methods: string[];
  banned: boolean;
  note?: string;
}

export interface AccessLog {
  id: number;
  external_id: string;
  method: string;
  status_code: number;
  ip_address: string;
  created_at: string;
}

export const policiesApi = {
  list: () => api.get<AccessPolicy[]>('/policies'),
  get: (id: string) => api.get<AccessPolicy>(`/policies/${id}`),
  create: (policy: AccessPolicy) => api.post<AccessPolicy>('/policies', policy),
  update: (id: string, policy: Partial<AccessPolicy>) => 
    api.put<AccessPolicy>(`/policies/${id}`, policy),
  delete: (id: string) => api.delete(`/policies/${id}`),
};

export const logsApi = {
  list: (limit?: number) => 
    api.get<AccessLog[]>('/logs', { params: { limit } }),
};

export default api;
