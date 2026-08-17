import React, { useState } from 'react';
import { buildContainmentPlaybook } from '../engines/playbookEngine';
import { api } from '../services/api';

export default function IncidentPlaybooks() {
  const [category, setCategory] = useState("spyware");
  const [targetIp, setTargetIp] = useState("192.168.1.105");
  const [processName, setProcessName] = useState("netd_agent");
  const [playbook, setPlaybook] = useState(() => buildContainmentPlaybook("spyware", { targetIp: "192.168.1.105" }));
  const [executingStep, setExecutingStep] = useState(null);
  const [executedSteps, setExecutedSteps] = useState({});

  const handleGenerate = async () => {
    try {
      const res = await api.generatePlaybook(category, targetIp, processName);
      if (res && res.containment_steps) {
        setPlaybook({
          title: res.playbook_title,
          steps: res.containment_steps
        });
      } else {
        setPlaybook(buildContainmentPlaybook(category, { targetIp, processName }));
      }
    } catch (e) {
      setPlaybook(buildContainmentPlaybook(category, { targetIp, processName }));
    }
  };

  const handleRunStep = (stepNumber) => {
    setExecutingStep(stepNumber);
    setTimeout(() => {
      setExecutingStep(null);
      setExecutedSteps(prev => ({ ...prev, [stepNumber]: true }));
    }, 1200);
  };

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h2 className="text-xl font-bold glow-text">Automated Incident Containment Playbooks</h2>
          <p className="text-secondary text-sm">Interactive step-by-step threat isolation & automated remediation CLI scripts</p>
        </div>
      </div>

      <div className="card mb-6 grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
        <div>
          <label className="text-xs text-muted block mb-1 uppercase font-semibold">Threat Category</label>
          <select className="input-field" value={category} onChange={e => setCategory(e.target.value)}>
            <option value="spyware">Pegasus / Surveillance Spyware</option>
            <option value="sqli">SQL Injection Exploitation</option>
            <option value="repo">Leaked Secret / Credential Leak</option>
            <option value="network">C2 Beaconing / DNS Tunnel</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-muted block mb-1 uppercase font-semibold">Target Endpoint / IP</label>
          <input className="input-field" value={targetIp} onChange={e => setTargetIp(e.target.value)} />
        </div>
        <div>
          <label className="text-xs text-muted block mb-1 uppercase font-semibold">Process Name</label>
          <input className="input-field" value={processName} onChange={e => setProcessName(e.target.value)} />
        </div>
        <div>
          <button className="btn btn-primary w-full" onClick={handleGenerate}>
            ⚡ Build Containment Playbook
          </button>
        </div>
      </div>

      {playbook && (
        <div className="card border-neon-pink">
          <div className="flex justify-between items-center mb-4">
            <h3 className="card-title glow-text-pink">{playbook.title}</h3>
            <span className="badge-sev sev-critical">CONTAINMENT MODE</span>
          </div>

          <div className="space-y-4">
            {playbook.steps.map(s => {
              const isDone = executedSteps[s.step];
              const isRunning = executingStep === s.step;

              return (
                <div key={s.step} className={`border p-4 rounded bg-surface ${isDone ? 'border-neon-green' : 'border-border-color'}`}>
                  <div className="flex justify-between items-center mb-2">
                    <div className="flex items-center gap-2">
                      <span className="badge-id">STEP {s.step}</span>
                      <span className="font-bold text-sm text-white">{s.action}</span>
                    </div>
                    <button
                      className={`btn text-xs ${isDone ? 'btn-success' : 'btn-primary'}`}
                      onClick={() => handleRunStep(s.step)}
                      disabled={isRunning || isDone}
                    >
                      {isRunning ? "Executing CLI..." : isDone ? "✓ Step Executed" : "Execute Command"}
                    </button>
                  </div>
                  <p className="text-xs text-muted mb-2">{s.purpose}</p>
                  <div className="code-box text-xs flex justify-between items-center">
                    <code>{s.command}</code>
                    <button className="text-xs text-secondary hover:text-white" onClick={() => navigator.clipboard.writeText(s.command)}>
                      📋 Copy
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
