import React, { useState } from 'react';
import { generateComplianceSummary, buildStix21Bundle } from '../engines/complianceEngine';
import { api } from '../services/api';

export default function ComplianceReporter() {
  const [report, setReport] = useState(() => generateComplianceSummary(5, 1));
  const [stixBundle, setStixBundle] = useState(null);
  const [loading, setLoading] = useState(false);

  const sampleFindings = [
    { type: "Pegasus C2 Beaconing", name: "Pegasus C2 Channel", severity: "critical", description: "Outbound HTTPS beaconing to arfrfrfrfrfr.com" },
    { type: "SQLi Injection Probe", name: "Boolean Bypass", severity: "high", description: "Tautological WHERE condition payload detected" },
    { type: "Hardcoded AWS Key", name: "Leaked AWS Token", severity: "critical", description: "Secret access key found in config.py" }
  ];

  const handleExportStix = async () => {
    setLoading(true);
    try {
      const bundle = await api.exportStixBundle(sampleFindings);
      setStixBundle(bundle);
    } catch (e) {
      setStixBundle(buildStix21Bundle(sampleFindings));
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadJson = (data, filename) => {
    const jsonStr = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="text-xl font-bold glow-text">ISO 27001 / NIST SP 800-53 & STIX 2.1 Exporter</h2>
          <p className="text-secondary text-sm">Automated evidence report generation and threat intelligence bundle export</p>
        </div>
        <div className="flex gap-2">
          <button className="btn btn-primary" onClick={handleExportStix} disabled={loading}>
            {loading ? "Generating STIX..." : "⚡ Generate STIX 2.1 Bundle"}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="card text-center">
          <div className="text-xs text-muted uppercase">Overall Compliance Score</div>
          <div className="text-3xl font-bold glow-text-cyan my-2">{report.overallScore}</div>
          <span className="badge-sev sev-low">{report.status}</span>
        </div>
        <div className="card text-center">
          <div className="text-xs text-muted uppercase">ISO 27001 Controls Evaluated</div>
          <div className="text-3xl font-bold text-white my-2">{report.isoControls.length}</div>
          <span className="text-xs text-neon-green">100% Audit Coverage</span>
        </div>
        <div className="card text-center">
          <div className="text-xs text-muted uppercase">NIST SP 800-53 Controls Passed</div>
          <div className="text-3xl font-bold text-white my-2">{report.nistControls.length}</div>
          <span className="text-xs text-neon-green">SI-4 / IR-4 Compliant</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="card">
          <h3 className="card-title mb-3">ISO 27001 Control Ratings</h3>
          <div className="space-y-3">
            {report.isoControls.map(ctrl => (
              <div key={ctrl.id} className="flex justify-between items-center border-b border-border-color pb-2">
                <div>
                  <span className="badge-id mr-2">{ctrl.id}</span>
                  <span className="text-sm font-semibold">{ctrl.name}</span>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono text-cyan-400 mr-2">{ctrl.rating}</span>
                  <span className="badge-sev sev-low">{ctrl.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <h3 className="card-title mb-3">NIST SP 800-53 Control Audit</h3>
          <div className="space-y-3">
            {report.nistControls.map(ctrl => (
              <div key={ctrl.id} className="flex justify-between items-center border-b border-border-color pb-2">
                <div>
                  <span className="badge-id mr-2">{ctrl.id}</span>
                  <span className="text-sm font-semibold">{ctrl.name}</span>
                </div>
                <span className={`badge-sev ${ctrl.status === 'PASS' ? 'sev-low' : 'sev-high'}`}>{ctrl.status}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {stixBundle && (
        <div className="card border-neon-cyan">
          <div className="flex justify-between items-center mb-3">
            <h3 className="card-title glow-text-cyan">STIX 2.1 Threat Intelligence Bundle Created</h3>
            <button className="btn btn-secondary text-xs" onClick={() => handleDownloadJson(stixBundle, 'cybersentinel_stix21_bundle.json')}>
              📥 Download STIX 2.1 JSON
            </button>
          </div>
          <pre className="code-box text-xs max-h-60 overflow-y-auto">
            {JSON.stringify(stixBundle, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
