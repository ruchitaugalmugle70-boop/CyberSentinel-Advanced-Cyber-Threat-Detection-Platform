# CyberSentinel - Advanced Pegasus Spyware Forensic & Cyber Threat Defense Suite

CyberSentinel is an enterprise-grade threat detection, forensic analysis, and static/dynamic security suite designed to detect sophisticated surveillance spyware (NSO Group Pegasus, Intellexa Predator, Hermit, Chrysaor), SQL Injection exploits, repository credential leaks, and network C2 beaconing.

---

## 🛡️ Architecture & Components

```
├── backend/                  # FastAPI Python Detection Engine
│   ├── app/
│   │   ├── api/v1/endpoints/ # REST API endpoints (spyware, sqli, repo, network, alerts)
│   │   ├── core/             # Configuration & environment settings
│   │   ├── data/             # Threat intelligence feeds & IOC databases
│   │   ├── engines/          # Modular detection engines (MVT heuristics, AST SAST, DLP)
│   │   └── models/           # Pydantic schemas
│   ├── requirements.txt      # Python dependencies
│   └── run.py                # Server runner
│
└── frontend/                 # High-Performance React + Vite Cyberpunk UI
    ├── src/
    │   ├── components/       # Dashboard, SpywareScanner, SQLiScanner, RepoScanner, ThreatMap...
    │   ├── engines/          # Client-side fallback heuristics & analyzers
    │   ├── services/         # API integration client
    │   └── utils/            # Threat feeds & visual telemetry generators
    └── package.json
```

---

## 🚀 Key Modules & Capabilities

1. **Pegasus & Predator Spyware Forensic Scanner**:
   - Deep inspection of iOS shutdown logs, process trees, and application containers.
   - Known C2 domain matching and SHA-256 binary hash verification.
   - Behavioral metrics anomaly evaluation (battery drain spikes, silent exfiltration bursts).

2. **SQL Injection DAST Engine**:
   - Comprehensive pattern matching against Boolean bypasses, stacked queries, UNION extractions, and time-based blind probes.
   - Live URL parameter auditor and WAF evasion detector.

3. **Repository SAST & Secrets Auditor**:
   - High-entropy credential scanner for 50+ token types (AWS, GitHub, Slack, Private Keys, Stripe, JWT).
   - Insecure permission (`chmod 777`) and dangerous dynamic execution (`eval`, `exec`) identification.
   - Git repository access pattern audit (bulk cloning, geo-dispersion impossible travel).

4. **Network Telemetry & C2 Monitor**:
   - C2 heartbeat beaconing detector using low-variance statistical analysis.
   - DNS tunneling and covert data channel identifier.
   - IP threat intelligence reputation lookup.

---

## 💻 Getting Started

### 1. Backend Setup
```bash
cd backend
pip install -r requirements.txt
python3 run.py
```
API Documentation available at: `http://localhost:8000/api/v1/docs`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.
