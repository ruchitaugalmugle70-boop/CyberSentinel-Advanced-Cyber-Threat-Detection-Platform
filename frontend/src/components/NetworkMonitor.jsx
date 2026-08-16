import { useState, useEffect } from 'react';
import { analyzeNetworkTraffic, checkIPReputation, generateNetworkTraffic } from '../engines/networkAnalyzer';

export default function NetworkMonitor() {
  const [trafficData, setTrafficData] = useState(() => generateNetworkTraffic());
  const [ipQuery, setIpQuery] = useState('');
  const [ipResult, setIpResult] = useState(null);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  useEffect(() => {
    // Run initial analysis
    const findings = analyzeNetworkTraffic(trafficData);
    setAnalysisResults(findings);
  }, [trafficData]);

  const handleAnalyze = () => {
    setIsAnalyzing(true);
    setTimeout(() => {
      const findings = analyzeNetworkTraffic(trafficData);
      setAnalysisResults(findings);
      setIsAnalyzing(false);
    }, 800);
  };

  const handleRefreshStream = () => {
    const fresh = generateNetworkTraffic();
    setTrafficData(fresh);
  };

  const handleLookupIp = (e) => {
    e.preventDefault();
    if (!ipQuery.trim()) return;
    const res = checkIPReputation(ipQuery.trim());
    setIpResult(res);
  };

  return (
    <div className="page-content">
      <div className="scan-section">
        {/* Top Controls & IP Lookup */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20 }}>
          {/* Live Packet Stream Table */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🌐</span>
                Active Socket Connections & Telemetry
              </div>
              <div className="panel-actions">
                <button className="scan-btn" onClick={handleRefreshStream} style={{ fontSize: '0.72rem', padding: '6px 12px' }}>
                  🔄 New Capture
                </button>
                <button className="scan-btn danger" onClick={handleAnalyze} style={{ fontSize: '0.72rem', padding: '6px 12px' }}>
                  {isAnalyzing ? 'Analyzing...' : '⚡ Scan Traffic'}
                </button>
              </div>
            </div>
            <div className="panel-body" style={{ padding: 0, overflowX: 'auto' }}>
              <table className="threat-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Port</th>
                    <th>Outbound</th>
                    <th>Payload / Query</th>
                  </tr>
                </thead>
                <tbody>
                  {trafficData.connections.map((c, i) => (
                    <tr key={i}>
                      <td>
                        <span className="alert-tag network" style={{ fontSize: '0.65rem' }}>{c.protocol}</span>
                      </td>
                      <td className="ip-address">{c.srcIp}</td>
                      <td className="ip-address" style={{ color: c.dstIp.startsWith('185.') || c.dstIp.startsWith('103.') ? 'var(--red)' : 'var(--cyan)' }}>
                        {c.dstIp}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{c.port}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: c.bytesOut > 1000000 ? 'var(--red)' : 'var(--text-primary)' }}>
                        {(c.bytesOut / 1024).toFixed(1)} KB
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {c.query || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* IP Intelligence Lookup */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">🔎</span>
                IP Threat Intelligence
              </div>
            </div>
            <div className="panel-body">
              <form onSubmit={handleLookupIp} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <input
                  className="scan-input"
                  type="text"
                  placeholder="e.g. 185.220.101.42 or 103.24.77.12"
                  value={ipQuery}
                  onChange={(e) => setIpQuery(e.target.value)}
                />
                <button type="submit" className="scan-btn" style={{ width: '100%' }}>
                  Check Reputation
                </button>
              </form>

              {ipResult && (
                <div style={{ marginTop: 16, padding: 14, background: 'var(--bg-secondary)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--cyan)' }}>{ipResult.ip}</span>
                    <span className={`result-severity ${ipResult.severity}`}>{ipResult.status.toUpperCase()}</span>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                    {ipResult.description}
                  </div>
                  {ipResult.recommendation && (
                    <div style={{ fontSize: '0.72rem', color: 'var(--amber)' }}>
                      ⚠️ {ipResult.recommendation}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Anomaly Analysis Results */}
        {analysisResults && analysisResults.length > 0 && (
          <div className="scan-results animate-fade-in-up">
            <div className="scan-results-header">
              <div className="results-title">
                ⚡ Network Telemetry Findings
                <span className="results-count">{analysisResults.length} anomalies</span>
              </div>
            </div>
            {analysisResults.map((r, i) => (
              <div key={i} className="result-item">
                <span className="result-icon">{r.severity === 'critical' ? '🔴' : '🟠'}</span>
                <div className="result-details">
                  <div className="result-name">{r.name}</div>
                  <div className="result-desc">{r.description}</div>
                  {r.recommendation && (
                    <div className="result-desc" style={{ color: 'var(--cyan)', marginTop: 4 }}>
                      💡 {r.recommendation}
                    </div>
                  )}
                </div>
                <span className={`result-severity ${r.severity}`}>{r.severity}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
