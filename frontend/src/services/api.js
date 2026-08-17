// CyberSentinel Frontend API Client connecting to Python FastAPI backend

const API_BASE = 'http://localhost:8000/api/v1';

export const api = {
  // Health
  checkHealth: async () => {
    try {
      const res = await fetch(`${API_BASE}/health`);
      return await res.json();
    } catch (e) {
      return { status: 'offline', error: e.message };
    }
  },

  // Spyware Scanner
  scanSpyware: async (content) => {
    const res = await fetch(`${API_BASE}/spyware/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    return await res.json();
  },

  analyzeDeviceTelemetry: async (metrics) => {
    const res = await fetch(`${API_BASE}/spyware/analyze-device`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metrics),
    });
    return await res.json();
  },

  // SQLi Scanner
  scanSqlPayload: async (payload) => {
    const res = await fetch(`${API_BASE}/sqli/scan-payload`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload }),
    });
    return await res.json();
  },

  scanSqlUrl: async (url) => {
    const res = await fetch(`${API_BASE}/sqli/scan-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return await res.json();
  },

  // Repo Scanner
  scanCode: async (code, filename = 'source_code.txt') => {
    const res = await fetch(`${API_BASE}/repo/scan-code`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename }),
    });
    return await res.json();
  },

  // Network Telemetry
  analyzeNetworkTraffic: async (connections) => {
    const res = await fetch(`${API_BASE}/network/analyze-traffic`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ connections }),
    });
    return await res.json();
  },

  checkIpReputation: async (ip) => {
    const res = await fetch(`${API_BASE}/network/ip-reputation/${encodeURIComponent(ip)}`);
    return await res.json();
  },

  // Alerts & Stats
  getAlertsFeed: async () => {
    const res = await fetch(`${API_BASE}/alerts/feed`);
    return await res.json();
  },

  getDashboardStats: async () => {
    const res = await fetch(`${API_BASE}/alerts/stats`);
    return await res.json();
  },

  // MITRE ATT&CK Matrix
  getMitreMatrix: async () => {
    const res = await fetch(`${API_BASE}/mitre/matrix`);
    return await res.json();
  },

  // Compliance & STIX Exporter
  getComplianceReport: async (summary) => {
    const res = await fetch(`${API_BASE}/compliance/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(summary),
    });
    return await res.json();
  },

  exportStixBundle: async (findings) => {
    const res = await fetch(`${API_BASE}/compliance/stix`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(findings),
    });
    return await res.json();
  },

  // YARA Sandbox
  scanYaraPayload: async (payload) => {
    const res = await fetch(`${API_BASE}/yara/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload }),
    });
    return await res.json();
  },

  // Incident Response Playbooks
  generatePlaybook: async (category, targetIp, processName, c2Domain) => {
    const res = await fetch(`${API_BASE}/playbooks/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ category, target_ip: targetIp, process_name: processName, c2_domain: c2Domain }),
    });
    return await res.json();
  },

  // System Security Audit
  getSystemAudit: async () => {
    const res = await fetch(`${API_BASE}/system-audit/check`);
    return await res.json();
  }
};
