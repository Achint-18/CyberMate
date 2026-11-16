import {
  DashboardMetrics,
  IndicatorMetadata,
  DiagnosisReport,
  ChatDiagnosisResponse,
  IncidentSummary,
  IncidentDetail,
  ThreatProfile,
  AttackScenario,
  PasswordGenerateRequest,
  PasswordGenerateResponse,
  RuleDefinition,
  SecurityRiskScore
} from '../types';

const API_BASE = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `Request failed with status ${res.status}`;
    try {
      const errJson = await res.json();
      errorDetail = errJson.detail || errJson.message || errorDetail;
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

export const api = {
  // Health
  checkHealth: async () => {
    const res = await fetch(`${API_BASE}/health`);
    return handleResponse<{ status: string; system: string }>(res);
  },

  // Dashboard
  getDashboardMetrics: async (): Promise<DashboardMetrics> => {
    const res = await fetch(`${API_BASE}/dashboard/metrics`);
    return handleResponse<DashboardMetrics>(res);
  },

  // Indicators
  getIndicators: async (): Promise<IndicatorMetadata[]> => {
    const res = await fetch(`${API_BASE}/indicators`);
    return handleResponse<IndicatorMetadata[]>(res);
  },

  // Incident Analysis
  analyzeIncident: async (
    facts: Record<string, any>,
    title = 'Security Incident Analysis',
    inputMethod = 'structured',
    saveToHistory = true
  ): Promise<DiagnosisReport> => {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        facts,
        input_method: inputMethod,
        save_to_history: saveToHistory
      })
    });
    return handleResponse<DiagnosisReport>(res);
  },

  // Risk Score Only
  calculateRiskScore: async (facts: Record<string, any>): Promise<SecurityRiskScore> => {
    const res = await fetch(`${API_BASE}/risk-score`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(facts)
    });
    return handleResponse<SecurityRiskScore>(res);
  },

  // Chat Diagnosis
  chatDiagnose: async (query: string, saveToHistory = true): Promise<ChatDiagnosisResponse> => {
    const res = await fetch(`${API_BASE}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, save_to_history: saveToHistory })
    });
    return handleResponse<ChatDiagnosisResponse>(res);
  },

  // Threat Library
  getThreats: async (query?: string, category?: string): Promise<ThreatProfile[]> => {
    const params = new URLSearchParams();
    if (query) params.append('query', query);
    if (category && category !== 'All') params.append('category', category);
    const url = `${API_BASE}/threats${params.toString() ? `?${params.toString()}` : ''}`;
    const res = await fetch(url);
    return handleResponse<ThreatProfile[]>(res);
  },

  getThreat: async (id: string): Promise<ThreatProfile> => {
    const res = await fetch(`${API_BASE}/threats/${id}`);
    return handleResponse<ThreatProfile>(res);
  },

  getActiveRules: async (): Promise<RuleDefinition[]> => {
    const res = await fetch(`${API_BASE}/threats/system/rules`);
    return handleResponse<RuleDefinition[]>(res);
  },

  // Attack Scenarios
  getScenarios: async (): Promise<AttackScenario[]> => {
    const res = await fetch(`${API_BASE}/scenarios`);
    return handleResponse<AttackScenario[]>(res);
  },

  runScenario: async (scenarioId: string): Promise<DiagnosisReport> => {
    const res = await fetch(`${API_BASE}/scenarios/${scenarioId}/run`, {
      method: 'POST'
    });
    return handleResponse<DiagnosisReport>(res);
  },

  // Incident History
  getHistory: async (): Promise<IncidentSummary[]> => {
    const res = await fetch(`${API_BASE}/history`);
    return handleResponse<IncidentSummary[]>(res);
  },

  getIncidentDetail: async (id: string): Promise<IncidentDetail> => {
    const res = await fetch(`${API_BASE}/history/${id}`);
    return handleResponse<IncidentDetail>(res);
  },

  deleteIncident: async (id: string): Promise<void> => {
    const res = await fetch(`${API_BASE}/history/${id}`, { method: 'DELETE' });
    await handleResponse<{ status: string }>(res);
  },

  clearHistory: async (): Promise<void> => {
    const res = await fetch(`${API_BASE}/history`, { method: 'DELETE' });
    await handleResponse<{ status: string }>(res);
  },

  // Password Generator
  generatePassword: async (req: PasswordGenerateRequest): Promise<PasswordGenerateResponse> => {
    const res = await fetch(`${API_BASE}/password/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req)
    });
    return handleResponse<PasswordGenerateResponse>(res);
  }
};
