# CyberSentinel - Advanced Pegasus Spyware Forensic & Cyber Threat Defense Suite

CyberSentinel is an enterprise-grade threat detection, forensic analysis, and static/dynamic security suite designed to detect sophisticated surveillance spyware (NSO Group Pegasus, Intellexa Predator, Hermit, Chrysaor), SQL Injection exploits, repository credential leaks, network C2 beaconing, MITRE ATT&CK TTP mapping, STIX 2.1 compliance reporting, and YARA rule payload analysis.

---

## 🛡️ Architecture & Components

```
├── backend/                  # FastAPI Python Threat Defense & Forensic Engine
│   ├── app/
│   │   ├── api/v1/endpoints/ # REST API endpoints (spyware, sqli, repo, network, mitre, compliance, yara, playbooks, audit)
│   │   ├── core/             # Configuration & environment settings
│   │   ├── data/             # Threat intelligence feeds & IOC databases
│   │   ├── engines/          # Detection engines (MVT heuristics, AST SAST, DLP, YARA, MITRE, STIX)
│   │   └── models/           # Pydantic schemas
│   ├── tests/                # Automated pytest & unittest suite (18 test cases)
│   ├── requirements.txt      # Python dependencies
│   └── run.py                # Server runner
│
└── frontend/                 # High-Performance React + Vite Cyberpunk UI
    ├── src/
    │   ├── components/       # Dashboard, SpywareScanner, SQLiScanner, RepoScanner, ThreatMap, MitreMatrixView, ComplianceReporter, YaraSandbox, IncidentPlaybooks, SystemAuditView...
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

5. **MITRE ATT&CK® Threat Mapping Matrix**:
   - Maps indicators directly to Mobile & Enterprise TTPs (T1430, T1071, T1552, T1190, T1041, T1059).
   - Dynamic technique card filtering and actionable mitigation modal breakdowns.

6. **ISO 27001 / NIST & STIX 2.1 Exporter**:
   - Generates standardized STIX 2.1 JSON threat intelligence bundles.
   - Automated executive compliance auditing for ISO 27001 & NIST SP 800-53 controls.

7. **YARA Rule Sandbox & Shannon Entropy Calculator**:
   - Dynamic signature matching for binary strings, custom YARA rules, and payload dumps.
   - Real-time Shannon entropy calculation (0.0 to 8.0) for detecting obfuscation.

8. **Automated Incident Response Containment Playbooks**:
   - Step-by-step containment playbooks generating shell commands, firewall rules, and API token revocations.

9. **Host System Security Audit**:
   - Evaluates system posture, environment variable leaks, CORS policies, and TLS 1.3 baseline configurations.

---

## 💻 Getting Started

### 1. Backend Setup & Testing
```bash
cd backend
pip install -r requirements.txt
python3 -m unittest discover -s tests
python3 run.py
```
API Documentation available at: `http://localhost:8000/api/v1/docs`

### 2. Frontend Setup
```bash
cd frontend
npm install
npm run build
npm run dev
```
Open `http://localhost:5173` in your browser.
