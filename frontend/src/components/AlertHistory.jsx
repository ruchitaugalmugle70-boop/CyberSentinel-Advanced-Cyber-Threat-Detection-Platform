import { useState } from 'react';
import { generateAlert, SEVERITY_LEVELS } from '../utils/threatData';

export default function AlertHistory() {
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterCategory, setFilterCategory] = useState('all');
  const [alerts] = useState(() => {
    const list = [];
    for (let i = 0; i < 25; i++) {
      const a = generateAlert();
      a.timestamp = new Date(Date.now() - i * 180000);
      list.push(a);
    }
    return list;
  });

  const filteredAlerts = alerts.filter((a) => {
    if (filterSeverity !== 'all' && a.severity !== filterSeverity) return false;
    if (filterCategory !== 'all' && a.category !== filterCategory) return false;
    return true;
  });

  return (
    <div className="page-content">
      <div className="scan-section">
        {/* Filters */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span className="title-icon">🔔</span>
              Security Event Audit Log
            </div>
            <div className="panel-actions" style={{ gap: 10 }}>
              <select
                className="scan-input"
                style={{ padding: '4px 10px', fontSize: '0.75rem', width: 'auto' }}
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
              </select>

              <select
                className="scan-input"
                style={{ padding: '4px 10px', fontSize: '0.75rem', width: 'auto' }}
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
              >
                <option value="all">All Categories</option>
                <option value="spyware">Spyware</option>
                <option value="sqli">SQLi</option>
                <option value="repo">Repo</option>
                <option value="network">Network</option>
              </select>
            </div>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            <table className="threat-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Severity</th>
                  <th>Category</th>
                  <th>Event Description</th>
                  <th>Origin / Source</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.map((a) => (
                  <tr key={a.id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {new Date(a.timestamp).toLocaleTimeString()}
                    </td>
                    <td>
                      <span className={`result-severity ${a.severity}`}>{a.severity}</span>
                    </td>
                    <td>
                      <span className={`alert-tag ${a.category}`}>{a.category.toUpperCase()}</span>
                    </td>
                    <td style={{ fontWeight: 500 }}>{a.message}</td>
                    <td className="ip-address">{a.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
