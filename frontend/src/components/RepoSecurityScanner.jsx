import { useState, useCallback } from 'react';
import { scanForSecrets, analyzeAccessPatterns, generateRepoEvents } from '../engines/repoMonitor';

const SAMPLE_CODE = `// config.js - Application Configuration
const AWS_ACCESS_KEY = "AKIA_SAMPLE_MOCK_KEY_PLACEHOLDER";
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY12";

// Database Configuration  
const DATABASE_URL = "postgres://admin:P@ssw0rd123@prod-db.example.com:5432/maindb";
const REDIS_URL = "redis://default:secretpass@redis.example.com:6379";

// API Keys
const api_key = "sk_test_sample_mock_stripe_key_placeholder";
const GITHUB_TOKEN = "ghp_SAMPLE_MOCK_GITHUB_TOKEN_PLACEHOLDER_1234";
const GOOGLE_API = "AIzaSy_SAMPLE_MOCK_GOOGLE_KEY_PLACEHOLDER";

// TODO: remove this hardcoded password before production
const password = "SuperSecretP@ssw0rd2024!";

// Disable SSL for local testing
// WARNING: disable ssl verify for staging environment  
const skipSSL = process.env.NODE_ENV !== 'production';

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyD8...
-----END RSA PRIVATE KEY-----

// chmod 777 /var/www/uploads
// eval(req.query.code)
// http://api.external-service.com/v2/data`;

export default function RepoSecurityScanner() {
  const [codeInput, setCodeInput] = useState('');
  const [results, setResults] = useState(null);
  const [accessResults, setAccessResults] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeTab, setActiveTab] = useState('secrets');

  const handleScan = useCallback(() => {
    if (!codeInput.trim() && activeTab === 'secrets') return;
    setScanning(true);
    setResults(null);
    setAccessResults(null);
    setScanProgress(0);

    const progressInterval = setInterval(() => {
      setScanProgress((p) => {
        if (p >= 95) { clearInterval(progressInterval); return 95; }
        return p + Math.random() * 18;
      });
    }, 80);

    setTimeout(() => {
      clearInterval(progressInterval);
      setScanProgress(100);
      if (activeTab === 'secrets') {
        setResults(scanForSecrets(codeInput));
      } else {
        const events = generateRepoEvents();
        setAccessResults(analyzeAccessPatterns(events));
      }
      setScanning(false);
    }, 1300);
  }, [codeInput, activeTab]);

  const loadSample = () => {
    setCodeInput(SAMPLE_CODE);
    setResults(null);
    setAccessResults(null);
  };

  const severityIcon = (sev) => {
    const icons = { critical: '🔴', high: '🟠', medium: '🟣', low: '🔵', info: 'ℹ️' };
    return icons[sev] || '⚪';
  };

  const currentResults = activeTab === 'secrets' ? results : accessResults;

  return (
    <div className="page-content">
      <div className="scan-section">
        {/* Tabs */}
        <div className="tabs">
          <button className={`tab ${activeTab === 'secrets' ? 'active' : ''}`} onClick={() => { setActiveTab('secrets'); setResults(null); setAccessResults(null); }}>
            🔐 Secret Scanner
          </button>
          <button className={`tab ${activeTab === 'access' ? 'active' : ''}`} onClick={() => { setActiveTab('access'); setResults(null); setAccessResults(null); }}>
            👁️ Access Monitor
          </button>
          <button className={`tab ${activeTab === 'deps' ? 'active' : ''}`} onClick={() => { setActiveTab('deps'); }}>
            📦 Dependency Audit
          </button>
        </div>

        {/* Input */}
        {activeTab === 'secrets' && (
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">📝</span>
                Code to Analyze
              </div>
              <div className="panel-actions">
                <button className="scan-btn" onClick={loadSample} style={{ fontSize: '0.72rem', padding: '6px 12px' }}>
                  📋 Load Sample
                </button>
              </div>
            </div>
            <div className="panel-body">
              <div className="scan-input-group">
                <label>Paste source code, configuration files, or commit diffs:</label>
                <textarea
                  className="scan-input scan-textarea"
                  value={codeInput}
                  onChange={(e) => setCodeInput(e.target.value)}
                  placeholder="Paste your source code, config files, .env contents, or git diffs here..."
                  rows={8}
                  style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}
                />
              </div>
              <div style={{ display: 'flex', gap: 12, marginTop: 16, alignItems: 'center' }}>
                <button className={`scan-btn ${scanning ? 'scanning' : ''}`} onClick={handleScan} disabled={scanning || !codeInput.trim()}>
                  {scanning ? '🔄 Scanning...' : '🔬 Scan for Secrets'}
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
        )}

        {activeTab === 'access' && (
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <span className="title-icon">👁️</span>
                Repository Access Monitoring
              </div>
            </div>
            <div className="panel-body">
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: 16 }}>
                Analyze repository access events for suspicious patterns including bulk cloning, off-hours access, geographic anomalies, and unauthorized permission changes.
              </p>
              <button className={`scan-btn ${scanning ? 'scanning' : ''}`} onClick={handleScan} disabled={scanning}>
                {scanning ? '🔄 Analyzing...' : '📊 Analyze Access Patterns'}
              </button>
              {scanning && (
                <div style={{ marginTop: 12 }}>
                  <div className="progress-bar">
                    <div className="progress-fill" style={{ width: `${scanProgress}%` }} />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {activeTab === 'deps' && (
          <div className="panel">
            <div className="panel-body" style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>📦</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
                Dependency Audit
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Connect a repository URL or upload a package manifest (package.json, requirements.txt, Gemfile) to scan for known vulnerabilities in dependencies.
              </div>
              <div style={{ marginTop: 20 }}>
                <input className="scan-input" placeholder="https://github.com/org/repo" style={{ maxWidth: 400, margin: '0 auto' }} />
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {currentResults && currentResults.length > 0 && (
          <div className="scan-results animate-fade-in-up">
            <div className="scan-results-header">
              <div className="results-title">
                ⚡ {activeTab === 'secrets' ? 'Secret Scan' : 'Access Analysis'} Results
                <span className="results-count">{currentResults.length} findings</span>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {['critical', 'high', 'medium'].map((sev) => {
                  const count = currentResults.filter((r) => r.severity === sev).length;
                  if (!count) return null;
                  return <span key={sev} className={`result-severity ${sev}`}>{count} {sev}</span>;
                })}
              </div>
            </div>
            {currentResults.map((result, i) => (
              <div key={i} className="result-item">
                <span className="result-icon">{severityIcon(result.severity)}</span>
                <div className="result-details">
                  <div className="result-name">{result.name}</div>
                  <div className="result-desc">{result.description}</div>
                  {result.line && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 4 }}>
                      📍 Line {result.line}
                    </div>
                  )}
                  {result.match && (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--red)', marginTop: 6, padding: '4px 8px', background: 'var(--red-dim)', borderRadius: 4, display: 'inline-block', wordBreak: 'break-all' }}>
                      {result.match}
                    </div>
                  )}
                  {result.recommendation && (
                    <div className="result-desc" style={{ color: 'var(--cyan)', marginTop: 6 }}>💡 {result.recommendation}</div>
                  )}
                </div>
                <span className={`result-severity ${result.severity}`}>{result.severity}</span>
              </div>
            ))}
          </div>
        )}

        {currentResults && currentResults.length === 0 && (
          <div className="panel">
            <div className="panel-body" style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ fontSize: '2.5rem', marginBottom: 12 }}>✅</div>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--green)', marginBottom: 8 }}>No Issues Found</div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>No secrets or security issues detected in the provided code.</div>
            </div>
          </div>
        )}

        {/* Terminal */}
        {currentResults && (
          <div className="terminal animate-fade-in-up" style={{ animationDelay: '0.15s', opacity: 0 }}>
            <div className="terminal-bar">
              <div className="terminal-dot red" />
              <div className="terminal-dot yellow" />
              <div className="terminal-dot green" />
              <div className="terminal-title">cybersentinel — repo-scanner v1.0</div>
            </div>
            <div className="terminal-body">
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className="terminal-text info">sentinel scan --engine=repo --mode={activeTab}</span></div>
              <div className="terminal-line"><span className="terminal-prompt">&gt;</span><span className="terminal-text">Loaded {12} secret patterns + {6} vulnerability rules</span></div>
              {currentResults.map((r, i) => (
                <div key={i} className="terminal-line">
                  <span className="terminal-prompt">&gt;</span>
                  <span className={`terminal-text ${r.severity === 'critical' ? 'error' : r.severity === 'high' ? 'warning' : 'info'}`}>
                    [{r.severity.toUpperCase()}] {r.name}: {r.description}
                  </span>
                </div>
              ))}
              <div className="terminal-line"><span className="terminal-prompt">$</span><span className={`terminal-text ${currentResults.length > 0 ? 'error' : 'success'}`}>Scan complete. {currentResults.length} findings.</span></div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
