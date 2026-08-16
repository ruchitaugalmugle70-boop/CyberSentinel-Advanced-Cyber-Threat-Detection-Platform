import { useState } from 'react';

export default function Settings() {
  const [backendUrl, setBackendUrl] = useState('http://localhost:8000/api/v1');
  const [autoScan, setAutoScan] = useState(true);
  const [realtimeAlerts, setRealtimeAlerts] = useState(true);
  const [iocAutoUpdate, setIocAutoUpdate] = useState(true);
  const [saved, setSaved] = useState(false);

  const handleSave = (e) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="page-content">
      <div className="scan-section" style={{ maxWidth: 700 }}>
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <span className="title-icon">⚙️</span>
              CyberSentinel System Configuration
            </div>
          </div>
          <div className="panel-body">
            <form onSubmit={handleSave} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              <div className="scan-input-group">
                <label>Backend API Endpoint URL:</label>
                <input
                  className="scan-input"
                  type="text"
                  value={backendUrl}
                  onChange={(e) => setBackendUrl(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={autoScan}
                    onChange={(e) => setAutoScan(e.target.checked)}
                    style={{ accentColor: 'var(--cyan)' }}
                  />
                  <span>Enable Automatic Real-Time Forensic Scanning on Upload</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={realtimeAlerts}
                    onChange={(e) => setRealtimeAlerts(e.target.checked)}
                    style={{ accentColor: 'var(--cyan)' }}
                  />
                  <span>Enable Live Alert Streaming & Sound Notification Triggers</span>
                </label>

                <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', fontSize: '0.82rem' }}>
                  <input
                    type="checkbox"
                    checked={iocAutoUpdate}
                    onChange={(e) => setIocAutoUpdate(e.target.checked)}
                    style={{ accentColor: 'var(--cyan)' }}
                  />
                  <span>Auto-Sync Threat Intelligence Feeds (NSO, Intellexa, Citizen Lab)</span>
                </label>
              </div>

              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="submit" className="scan-btn">
                  Save Changes
                </button>
                {saved && (
                  <span style={{ fontSize: '0.78rem', color: 'var(--green)' }}>
                    ✅ Configuration saved successfully!
                  </span>
                )}
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
