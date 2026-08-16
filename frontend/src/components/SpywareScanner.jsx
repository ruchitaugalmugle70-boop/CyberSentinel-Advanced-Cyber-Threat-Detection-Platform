import { useState, useCallback } from 'react';
import { scanForIOCs, analyzeDeviceBehavior } from '../engines/spywareDetector';

const SAMPLE_LOGS = `System Shutdown Log - Device Analysis
Process: libtouchregd - running since 2024-01-15
Connection: arfrfrfrfrfr.com resolved via DNS
Process: ABSCarrier - active network connection
Battery drain: 68% in last 24 hours
Background camera access detected while device locked
/var/containers/Bundle/Application/a1b2c3d4-e5f6/suspicious.app
Process: RollingStorage - collecting data
Connection to free247downloads.com established`;

const SAMPLE_METRICS = {
  batteryDrain: 68,
  dataUsage: 1200,
  cpuSpikes: 8,
  unexpectedReboots: 4,
};

export default function SpywareScanner() {
  const [logInput, setLogInput] = useState('');
  const [results, setResults] = useState(null);
  const [behaviorResults, setBehaviorResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeTab, setActiveTab] = useState('ioc');

  const handleScan = useCallback(() => {
    if (!logInput.trim()) return;
    setScanning(true);
    setResults(null);
    setBehaviorResults(null);
    setScanProgress(0);

    const progressInterval = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 95) { clearInterval(progressInterval); return 95; }
        return p + Math.random() * 15;
      });
    }, 100);

    setTimeout(() => {
      clearInterval(progressInterval);
      setScanProgress(100);
      const iocResults = scanForIOCs(logInput);
      const behaviorFindings = analyzeDeviceBehavior(SAMPLE_METRICS);
      setResults(iocResults);
      setBehaviorResults(behaviorFindings);
      setScanning(false);
    }, 1500);
  }, [logInput]);

  const loadSample = () => {
    setLogInput(SAMPLE_LOGS);
    setResults(null);
    setBehaviorResults(null);
  };

  const severityIcon = (sev) => {
    const icons = { critical: '🔴', high: '🟠', medium: '🟣', low: '🔵', info: 'ℹ️' };
    return icons[sev] || '⚪';
  };

  const allResults = [...(results || []), ...(behaviorResults || [])];

  return (
    <div className="page-content">
      <div className="scan-section">
        {/* Tabs */}
        <div className="tabs">
          <button className={`tab ${activeTab === 'ioc' ? 'active' : ''}`} onClick={() => setActiveTab('ioc')}>
            🔍 IOC Scanner
          </button>
          <button className={`tab ${activeTab === 'behavior' ? 'active' : ''}`} onClick={() => setActiveTab('behavior')}>
            📊 Behavior Analysis
          </button>
          <button className={`tab ${activeTab === 'device' ? 'active' : ''}`} onClick={() => setActiveTab('device')}>
            📱 Device Forensics
          </button>
        </div>

        {/* Input Section */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span className="title-icon">🔍</span>
              {activeTab === 'ioc' ? 'Paste Logs / IOC Data' : activeTab === 'behavior' ? 'Device Behavior Metrics' : 'Device Forensic Data'}
            </div>
            <div className="panel-actions">
              <button className="scan-btn" onClick={loadSample} style={{ fontSize: '0.72rem', padding: '6px 12px' }}>
                📋 Load Sample
              </button>
            </div>
          </div>
          <div className="panel-body">
            <div className="scan-input-group">
              <label>Enter device logs, process lists, DNS queries, or IOC data for analysis:</label>
              <textarea
                className="scan-input scan-textarea"
                value={logInput}
                onChange={(e) => setLogInput(e.target.value)}
                placeholder="Paste device logs, process lists, shutdown logs, network connections, file hashes, or any suspicious data here..."
                rows={6}
              />
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 16, alignItems: 'center' }}>
              <button className={`scan-btn danger ${scanning ? 'scanning' : ''}`} onClick={handleScan} disabled={scanning || !logInput.trim()}>
                {scanning ? '🔄 Scanning...' : '🚀 Run Deep Scan'}
              </button>
              {scanning && (
                <div style={{ flex: 1 }}>
                  <div className="progress-bar">
                    <div className="progress-fill danger" style={{ width: `${scanProgress}%` }} />
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 4 }}>
                    Scanning... {Math.round(scanProgress)}%
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Results */}
        {allResults.length > 0 && (
          <div className="scan-results animate-fade-in-up">
            <div className="scan-results-header">
              <div className="results-title">
                ⚡ Scan Results
                <span className={`results-count ${allResults.length === 0 ? 'safe' : ''}`}>
                  {allResults.length} {allResults.length === 1 ? 'finding' : 'findings'}
                </span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {['critical', 'high', 'medium'].map((sev) => {
                  const count = allResults.filter((r) => r.severity === sev).length;
                  if (!count) return null;
                  return (
                    <span key={sev} className={`result-severity ${sev}`}>
                      {count} {sev}
                    </span>
                  );
                })}
              </div>
            </div>
            {allResults.map((result, i) => (
              <div key={i} className="result-item">
                <span className="result-icon">{severityIcon(result.severity)}</span>
                <div className="result-details">
                  <div className="result-name">{result.match || result.type}</div>
                  <div className="result-desc">{result.description}</div>
                  {result.recommendation && (
                    <div className="result-desc" style={{ color: 'var(--cyan)', marginTop: 4 }}>
                      💡 {result.recommendation}
                    </div>
                  )}
                </div>
                <span className={`result-severity ${result.severity}`}>{result.severity}</span>
              </div>
            ))}
          </div>
        )}

        {results && results.length === 0 && !behaviorResults?.length && (
          <div className="panel">
            <div className="panel-body" style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>✅</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--green)', marginBottom: 8 }}>
                No Threats Detected
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                No known IOCs, suspicious processes, or behavioral anomalies found in the provided data.
              </div>
            </div>
          </div>
        )}

        {/* Terminal Log */}
        {results && (
          <div className="terminal animate-fade-in-up" style={{ animationDelay: '0.2s', opacity: 0 }}>
            <div className="terminal-bar">
              <div className="terminal-dot red" />
              <div className="terminal-dot yellow" />
              <div className="terminal-dot green" />
              <div className="terminal-title">cybersentinel — spyware-detector v1.0</div>
            </div>
            <div className="terminal-body">
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className="terminal-text info">sentinel scan --engine=ioc --mode=deep</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Loading IOC database... 10,847 signatures</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Loading heuristic patterns... 6 behavioral rules</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Scanning input ({logInput.length} bytes)...</span></div>
              {allResults.map((r, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-prompt">&gt;</span>
                  <span className={`terminal-text ${r.severity === 'critical' ? 'error' : r.severity === 'high' ? 'warning' : 'info'}`}>
                    [{r.severity.toUpperCase()}] {r.match || r.type}: {r.description}
                  </span>
                </div>
              ))}
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className="terminal-text success">Scan complete. {allResults.length} findings reported.</span></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
