import React, { useState } from 'react';
import { evaluateYaraPayload } from '../engines/yaraEngine';
import { api } from '../services/api';

export default function YaraSandbox() {
  const [payloadText, setPayloadText] = useState("SELECT * FROM users WHERE id = '1' OR '1'='1'; --");
  const [analysis, setAnalysis] = useState(null);
  const [scanning, setScanning] = useState(false);

  const handleScan = async () => {
    setScanning(true);
    try {
      const res = await api.scanYaraPayload(payloadText);
      if (res && res.matched_rules_count !== undefined) {
        setAnalysis({
          payloadLength: res.payload_length,
          entropy: res.shannon_entropy,
          isObfuscated: res.is_obfuscated,
          matchedCount: res.matched_rules_count,
          matches: res.matches.map(m => ({
            ruleName: m.rule_name,
            severity: m.severity,
            desc: m.description,
            count: m.match_count,
            snippets: m.snippets
          })),
          threatScore: res.threat_score
        });
      } else {
        setAnalysis(evaluateYaraPayload(payloadText));
      }
    } catch (e) {
      setAnalysis(evaluateYaraPayload(payloadText));
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="text-xl font-bold glow-text">YARA Rule Sandbox & Payload Inspection</h2>
          <p className="text-secondary text-sm">Dynamic YARA signature matching & Shannon entropy calculation engine</p>
        </div>
      </div>

      <div className="card mb-6">
        <label className="text-xs text-muted block mb-2 uppercase font-semibold">Target Payload / Binary String / Code Snippet</label>
        <textarea
          rows={5}
          className="input-textarea code-box mb-4 w-full"
          value={payloadText}
          onChange={e => setPayloadText(e.target.value)}
          placeholder="Paste raw memory dump, URL payload, or script snippet here..."
        />
        <div className="flex justify-between items-center">
          <div className="text-xs text-muted">Length: {payloadText.length} characters</div>
          <button className="btn btn-primary" onClick={handleScan} disabled={scanning || !payloadText.trim()}>
            {scanning ? "Analyzing YARA..." : "🔬 Execute YARA Inspection"}
          </button>
        </div>
      </div>

      {analysis && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card text-center">
              <div className="text-xs text-muted uppercase">Shannon Entropy</div>
              <div className="text-2xl font-bold glow-text-cyan my-1">{analysis.entropy}</div>
              <div className="text-xs text-secondary">{analysis.isObfuscated ? "⚠️ Highly Obfuscated" : "Standard Text"}</div>
            </div>
            <div className="card text-center">
              <div className="text-xs text-muted uppercase">Matched YARA Rules</div>
              <div className="text-2xl font-bold text-white my-1">{analysis.matchedCount}</div>
              <div className="text-xs text-secondary">Active Signature Rules</div>
            </div>
            <div className="card text-center">
              <div className="text-xs text-muted uppercase">Threat Risk Score</div>
              <div className="text-2xl font-bold text-neon-pink my-1">{analysis.threatScore} / 100</div>
              <span className={`badge-sev ${analysis.threatScore > 45 ? 'sev-critical' : 'sev-low'}`}>
                {analysis.threatScore > 45 ? "HIGH_RISK" : "LOW_RISK"}
              </span>
            </div>
            <div className="card text-center">
              <div className="text-xs text-muted uppercase">Payload Size</div>
              <div className="text-2xl font-bold text-white my-1">{analysis.payloadLength} B</div>
              <div className="text-xs text-secondary">Byte Inspection</div>
            </div>
          </div>

          <div className="card">
            <h3 className="card-title mb-3">YARA Rule Match Breakdown</h3>
            {analysis.matches.length === 0 ? (
              <div className="text-neon-green text-sm p-4 text-center">No YARA rule signature matches found. Payload clean.</div>
            ) : (
              <div className="space-y-3">
                {analysis.matches.map((m, idx) => (
                  <div key={idx} className="border border-border-color p-3 rounded bg-surface">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-bold text-sm text-neon-cyan">{m.ruleName}</span>
                      <span className={`badge-sev sev-${m.severity.toLowerCase()}`}>{m.severity}</span>
                    </div>
                    <p className="text-xs text-muted mb-2">{m.desc}</p>
                    {m.snippets && m.snippets.length > 0 && (
                      <div className="code-box text-xs">
                        {m.snippets.join('\n')}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
