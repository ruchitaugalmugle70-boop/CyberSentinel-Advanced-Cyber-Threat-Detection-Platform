# CyberSentinel Threat Detection - Backend API

High-performance Python FastAPI engine for Pegasus spyware forensic detection, SQL injection analysis, SAST repository secrets scanning, network C2 traffic telemetry analysis, MITRE ATT&CK mapping, STIX 2.1 exporter, YARA rule sandbox, incident response playbooks, and host security audits.

## Features

- **Spyware & Pegasus IOC Engine**:
  - Full matchers for known NSO Pegasus, Predator, and Hermit C2 domains, hashes, and process anomalies.
  - Heuristic parser for iOS shutdown.log, sysdiagnose dumps, and suspicious application containers.
  - Battery/cellular telemetry anomaly evaluator.

- **SQL Injection (DAST & Heuristics)**:
  - Boolean-based, UNION-based, time-based, and stacked query analyzers.
  - URL parameter fuzzer and WAF evasion detector.

- **Repository Security (SAST)**:
  - Scans for 50+ hardcoded secrets (AWS, GitHub, Slack, Private Keys, Stripe, JWT).
  - Flags insecure file permissions and dangerous runtime execution (`eval`, `exec`).
  - Git repository access pattern audit (bulk cloning, multi-region impossible travel).

- **Network Anomaly & C2 Analyzer**:
  - Statistical C2 periodic beaconing detector (variance + standard deviation).
  - DNS tunneling detection on port 53.
  - High-risk destination port and port scan detection.
  - IP reputation threat intelligence feed.

- **MITRE ATT&CK Threat Mapping**:
  - Direct mapping to Enterprise and Mobile TTPs (T1430, T1071, T1552, T1190, T1041, T1059).
  - Severity scoring and mitigation strategy catalog.

- **ISO 27001 / NIST & STIX 2.1 Exporter**:
  - Standard STIX 2.1 JSON threat intelligence bundle generator.
  - Executive compliance summary generator for ISO 27001 & NIST SP 800-53 controls.

- **YARA Rule Sandbox & Entropy Calculator**:
  - Signature matcher for dynamic YARA pattern rules.
  - Shannon entropy calculator for detecting obfuscated and encrypted payloads.

- **Automated Incident Response Playbooks**:
  - Containment playbook generator for active threat mitigation (iptables, AWS WAF, IAM revocation, BGP null routes).

- **Host System Security Audit**:
  - Evaluates local host posture, environment variable leaks, CORS settings, and TLS 1.3 baseline.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Backend Unit & Integration Tests
```bash
python3 -m unittest discover -s tests
```

### 3. Run the Server
```bash
python3 run.py
```
Or with uvicorn directly:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. API Documentation
Once running, explore the interactive documentation:
- Swagger UI: `http://localhost:8000/api/v1/docs`
- ReDoc: `http://localhost:8000/api/v1/redoc`
