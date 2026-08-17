import React, { useState, useEffect } from 'react';
import { MITRE_TACTICS, MITRE_TECHNIQUES_DATA } from '../engines/mitreEngine';
import { api } from '../services/api';

export default function MitreMatrixView() {
  const [matrixData, setMatrixData] = useState(MITRE_TECHNIQUES_DATA);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [activeFilter, setActiveFilter] = useState('ALL');

  useEffect(() => {
    async function loadMatrix() {
      try {
        const data = await api.getMitreMatrix();
        if (data && data.length) setMatrixData(data);
      } catch (e) {
        // Fallback to client data
      }
    }
    loadMatrix();
  }, []);

  const filteredTechniques = matrixData.filter(tech => {
    if (activeFilter === 'ALL') return true;
    return tech.severity === activeFilter;
  });

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="text-xl font-bold glow-text">MITRE ATT&CK® Threat Mapping Matrix</h2>
          <p className="text-secondary text-sm">Categorized Enterprise & Mobile Tactics, Techniques & Procedures (TTPs)</p>
        </div>
        <div className="filter-group">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
            <button
              key={sev}
              className={`filter-btn ${activeFilter === sev ? 'active' : ''}`}
              onClick={() => setActiveFilter(sev)}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      <div className="mitre-grid">
        {MITRE_TACTICS.map(tactic => {
          const techniques = filteredTechniques.filter(t => t.tactic === tactic);
          return (
            <div key={tactic} className="mitre-column card">
              <h3 className="tactic-header">{tactic}</h3>
              <div className="technique-list">
                {techniques.length === 0 ? (
                  <div className="text-muted text-xs p-2 text-center">No techniques match filter</div>
                ) : (
                  techniques.map(tech => (
                    <div
                      key={tech.id}
                      className={`technique-card severity-${tech.severity.toLowerCase()}`}
                      onClick={() => setSelectedTechnique(tech)}
                    >
                      <div className="flex justify-between items-center mb-1">
                        <span className="badge-id">{tech.id}</span>
                        <span className={`badge-sev sev-${tech.severity.toLowerCase()}`}>{tech.severity}</span>
                      </div>
                      <div className="tech-name">{tech.name}</div>
                      <div className="tech-domain text-xs text-muted">{tech.domain}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>

      {selectedTechnique && (
        <div className="modal-overlay" onClick={() => setSelectedTechnique(null)}>
          <div className="modal-content card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <span className="badge-id mr-2">{selectedTechnique.id}</span>
                <span className="text-lg font-bold">{selectedTechnique.name}</span>
              </div>
              <button className="close-btn" onClick={() => setSelectedTechnique(null)}>✕</button>
            </div>
            <div className="modal-body space-y-4">
              <div>
                <label className="text-xs text-muted block uppercase">Tactic & Domain</label>
                <div className="font-semibold">{selectedTechnique.tactic} ({selectedTechnique.domain})</div>
              </div>
              <div>
                <label className="text-xs text-muted block uppercase">Technique Description</label>
                <p className="text-sm">{selectedTechnique.description}</p>
              </div>
              <div>
                <label className="text-xs text-muted block uppercase text-neon-green">Recommended Defense & Mitigation</label>
                <div className="code-box text-xs">{selectedTechnique.mitigation}</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
