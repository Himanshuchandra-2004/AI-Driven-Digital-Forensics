/** API client — all backend calls go through here. */

import axios from 'axios';
import type {
  AnalysisRun, AnomalyDetection, Case, ChainOfCustodyEntry,
  DashboardStats, Evidence, EvidenceVerification, Incident,
  ModelVersion, ReportInfo, ThreatDetection, TokenResponse,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: `${API_BASE}/api`,
  headers: { 'Content-Type': 'application/json' },
});

// Attach JWT token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 — redirect to login
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401 && !window.location.pathname.includes('/login')) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  },
);

// ---- Auth ----
export const authApi = {
  register: (data: { username: string; email: string; password: string; full_name: string }) =>
    api.post<TokenResponse>('/auth/register', data),
  login: (data: { username: string; password: string }) =>
    api.post<TokenResponse>('/auth/login', data),
  me: () => api.get<TokenResponse['user']>('/auth/me'),
};

// ---- Cases ----
export const casesApi = {
  list: () => api.get<Case[]>('/cases'),
  get: (id: string) => api.get<Case>(`/cases/${id}`),
  create: (data: { name: string; description: string }) => api.post<Case>('/cases', data),
  update: (id: string, data: Partial<Case>) => api.put<Case>(`/cases/${id}`, data),
  delete: (id: string) => api.delete(`/cases/${id}`),
  upload: (id: string, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return api.post(`/cases/${id}/upload`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },
};

// ---- Analysis ----
export const analysisApi = {
  start: (caseId: string, filename: string) =>
    api.post<AnalysisRun>(`/cases/${caseId}/analyze?filename=${encodeURIComponent(filename)}`),
  list: (caseId: string) => api.get<AnalysisRun[]>(`/cases/${caseId}/analysis`),
  get: (runId: string) => api.get<AnalysisRun>(`/analysis/${runId}`),
};

// ---- Threats ----
export const threatsApi = {
  list: (caseId: string, params?: Record<string, string>) =>
    api.get<ThreatDetection[]>(`/cases/${caseId}/threats`, { params }),
  get: (id: string) => api.get<ThreatDetection>(`/threats/${id}`),
};

// ---- Anomalies ----
export const anomaliesApi = {
  list: (caseId: string, params?: Record<string, string>) =>
    api.get<AnomalyDetection[]>(`/cases/${caseId}/anomalies`, { params }),
};

// ---- Evidence ----
export const evidenceApi = {
  list: (caseId: string, params?: Record<string, string>) =>
    api.get<Evidence[]>(`/cases/${caseId}/evidence`, { params }),
  get: (id: string) => api.get<Evidence>(`/evidence/${id}`),
  verify: (id: string) => api.post<EvidenceVerification>(`/evidence/${id}/verify`),
  custody: (id: string) => api.get<ChainOfCustodyEntry[]>(`/evidence/${id}/custody`),
};

// ---- Incidents ----
export const incidentsApi = {
  list: (caseId: string) => api.get<Incident[]>(`/cases/${caseId}/incidents`),
  get: (id: string) => api.get<Incident>(`/incidents/${id}`),
};

// ---- Reports ----
export const reportsApi = {
  list: (caseId: string) => api.get<ReportInfo[]>(`/cases/${caseId}/reports`),
  generate: (caseId: string, type: string = 'pdf') =>
    api.post<ReportInfo>(`/cases/${caseId}/report`, { report_type: type }),
  get: (id: string) => api.get<ReportInfo>(`/reports/${id}`),
  download: (id: string) =>
    api.get(`/reports/${id}/download`, { responseType: 'blob' }),
};

// ---- Models ----
export const modelsApi = {
  list: () => api.get<ModelVersion[]>('/models'),
  get: (id: string) => api.get<ModelVersion>(`/models/${id}`),
};

// ---- Dashboard ----
export const dashboardApi = {
  stats: () => api.get<DashboardStats>('/dashboard/stats'),
};

// ---- Demo ----
export const demoApi = {
  load: () => api.post('/demo/load'),
};

export default api;
