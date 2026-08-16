import { useState, useCallback } from 'react';
import { scanForSQLInjection, scanURL } from '../engines/sqlScanner';

const SAMPLE_PAYLOADS = [
  "' OR 1=1 --",
  "admin'--",
  "' UNION SELECT NULL, username, password FROM users --",
  "'; DROP TABLE users; --",
  "' AND 1=1; WAITFOR DELAY '0:0:10' --",
  "'; EXEC xp_cmdshell('net user') --",
  "1; UPDATE users SET role='admin' WHERE username='attacker'",
  "' OR EXISTS(SELECT * FROM information_schema.tables) --",
];

const SAMPLE_URL = "https://example.com/search?id=1' OR 1=1--&category=electronics&sort=price";

export default function SQLInjectionScanner() {
  const [input, setInput] = useState('');
  const [scanMode, setScanMode] = useState('payload');
  const [results, setResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);

  const handleScan = useCallback(() => {
    if (!input.trim()) return;
    setScanning(true);
    setResults(null);
    setScanProgress(0);

    const progressInterval = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 95) { clearInterval(progressInterval); return 95; }
        return p + Math.random() * 20;
      });
    }, 80);

    setTimeout(() => {
      clearInterval(progressInterval);
      setScanProgress(100);
      const scanResults = scanMode === 'url' ? scanURL(input) : scanForSQLInjection(input);
      setResults(scanResults);
      setScanning(false);
    }, 1200);
  }, [input, scanMode]);

  const loadSamplePayload = (payload) => {
    setInput(payload);
    setResults(null);
    setScanMode('payload');
  };

  const loadSampleURL = () => {
    setInput(SAMPLE_URL);
    setResults(null);
    setScanMode('url');
  };

  const severityIcon = (sev) => {
    const icons = { critical: '🔴', high: '🟠', medium: '🟣', low: '🔵', info: 'ℹ️' };
    return icons[sev] || '⚪';
  };

  return (
    <div className="page-content">
      <div className="scan-section">
        {/* Mode Tabs */}
        <div className="tabs">
          <button className={`tab ${scanMode === 'payload' ? 'active' : ''}`} onClick={() => { setScanMode('payload'); setResults(null); }}>
            💉 Payload Scanner
          </button>
          <button className={`tab ${scanMode === 'url' ? 'active' : ''}`} onClick={() => { setScanMode('url'); setResults(null); }}>
            🔗 URL Scanner
          </button>
          <button className={`tab ${scanMode === 'waf' ? 'active' : ''}`} onClick={() => { setScanMode('waf'); setResults(null); }}>
            🛡️ WAF Test
          </button>
        </div>

        {/* Sample Payloads */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span className="title-icon">📋</span>
              Quick Test Payloads
            </div>
          </div>
          <div className="panel-body" style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {SAMPLE_PAYLOADS.map((payload, i) => (
              <button
                key={i}
                onClick={() => loadSamplePayload(payload)}
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '6px 12px',
                  color: 'var(--amber)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.72rem',
                  cursor: 'pointer',
                  transition: 'all 150ms',
                }}
                onMouseEnter={(e) => { e.target.style.borderColor = 'var(--amber)'; e.target.style.boxShadow = '0 0 10px rgba(255,170,0,0.15)'; }}
                onMouseLeave={(e) => { e.target.style.borderColor = 'var(--border)'; e.target.style.boxShadow = 'none'; }}
              >
                {payload.length > 40 ? payload.substring(0, 40) + '...' : payload}
              </button>
            ))}
            <button
              onClick={loadSampleURL}
              style={{
                background: 'var(--cyan-dim)',
                border: '1px solid rgba(0,240,255,0.2)',
                borderRadius: 'var(--radius-sm)',
                padding: '6px 12px',
                color: 'var(--cyan)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.72rem',
                cursor: 'pointer',
              }}
            >
              🔗 Sample URL
            </button>
          </div>
        </div>

        {/* Scanner Input */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span className="title-icon">💉</span>
              {scanMode === 'url' ? 'URL to Analyze' : 'Input / Payload to Analyze'}
            </div>
          </div>
          <div className="panel-body">
            <div className="scan-input-group">
              <label>
                {scanMode === 'url'
                  ? 'Enter URL with parameters to scan for SQL injection vulnerabilities:'
                  : 'Enter user input, form data, or SQL payload to analyze:'}
              </label>
              {scanMode === 'url' ? (
                <input
                  className="scan-input"
                  type="text"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="https://example.com/api?id=1&search=test"
                />
              ) : (
                <textarea
                  className="scan-input scan-textarea"
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Enter SQL injection payload or suspicious user input..."
                  rows={4}
                />
              )}
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 16, alignItems: 'center' }}>
              <button className={`scan-btn ${scanning ? 'scanning' : ''}`} onClick={handleScan} disabled={scanning || !input.trim()}>
                {scanning ? '🔄 Analyzing...' : '🔬 Analyze Input'}
              </button>
              {scanning && (
                <div style={{ flex: 1 }}>
                  <div className="progress-bar">
                    <div className="progress-fill danger" style={{ width: `${scanProgress}%` }} />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Results */}
        {results && results.length > 0 && (
          <div className="scan-results animate-fade-in-up">
            <div className="scan-results-header">
              <div className="results-title">
                ⚡ SQL Injection Analysis Results
                <span className="results-count">{results.length} {results.length === 1 ? 'threat' : 'threats'}</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {['critical', 'high', 'medium', 'low'].map((sev) => {
                  const count = results.filter((r) => r.severity === sev).length;
                  if (!count) return null;
                  return <span key={sev} className={`result-severity ${sev}`}>{count} {sev}</span>;
                })}
              </div>
            </div>
            {results.map((result, i) => (
              <div key={i} className="result-item">
                <span className="result-icon">{severityIcon(result.severity)}</span>
                <div className="result-details">
                  <div className="result-name">{result.name}</div>
                  <div className="result-desc">{result.description}</div>
                  {result.pattern && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--amber)', marginTop: 6, padding: '4px 8px', background: 'var(--amber-dim)', borderRadius: 4, display: 'inline-block' }}>
                      Pattern: {result.pattern}
                    </div>
                  )}
                  {result.location && (
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 4 }}>📍 {result.location}</div>
                  )}
                  {result.recommendation && (
                    <div className="result-desc" style={{ color: 'var(--cyan)', marginTop: 6 }}>
                      💡 {result.recommendation}
                    </div>
                  )}
                </div>
                <span className={`result-severity ${result.severity}`}>{result.severity}</span>
              </div>
            ))}
          </div>
        )}

        {results && results.length === 0 && (
          <div className="panel">
            <div className="panel-body" style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>✅</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--green)', marginBottom: 8 }}>
                Input Appears Safe
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                No SQL injection patterns detected. However, always use parameterized queries for defense in depth.
              </div>
            </div>
          </div>
        )}

        {/* Terminal */}
        {results && (
          <div className="terminal animate-fade-in-up" style={{ animationDelay: '0.15s', opacity: 0 }}>
            <div className="terminal-bar">
              <div className="terminal-dot red" />
              <div className="terminal-dot yellow" />
              <div className="terminal-dot green" />
              <div className="terminal-title">cybersentinel — sqli-scanner v1.0</div>
            </div>
            <div className="terminal-body">
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className="terminal-text info">sentinel scan --engine=sqli --mode={scanMode}</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Loaded {20} SQL injection signatures + {12} regex patterns</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Analyzing input ({input.length} chars)...</span></div>
              {results.map((r, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-prompt">&gt;</span>
                  <span className={`terminal-text ${r.severity === 'critical' ? 'error' : r.severity === 'high' ? 'warning' : 'info'}`}>
                    [{r.severity.toUpperCase()}] {r.name}: {r.description}
                  </span>
                </div>
              ))}
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className={`terminal-text ${results.length > 0 ? 'error' : 'success'}`}>Analysis complete. {results.length} {results.length === 1 ? 'threat' : 'threats'} identified.</span></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
