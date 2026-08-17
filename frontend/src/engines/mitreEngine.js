/**
 * MITRE ATT&CK Matrix Client Engine for CyberSentinel.
 * Provides client-side technique mapping, tactic categorization, and risk scoring.
 */

export const MITRE_TACTICS = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Credential Access",
  "Collection",
  "Command and Control",
  "Exfiltration"
];

export const MITRE_TECHNIQUES_DATA = [
  {
    id: "T1430",
    name: "Location Tracking & Surveillance",
    tactic: "Collection",
    domain: "Mobile",
    severity: "CRITICAL",
    description: "Spyware covertly tracks GPS location, cell tower IDs, and WiFi BSSIDs.",
    mitigation: "Enforce strict location permissions, inspect locationd logs, disable background location."
  },
  {
    id: "T1071.001",
    name: "Web Protocols (HTTP/S)",
    tactic: "Command and Control",
    domain: "Enterprise",
    severity: "HIGH",
    description: "Adversaries communicate with C2 servers using standard HTTPS beaconing.",
    mitigation: "Use SSL/TLS inspection, analyze domain entropy, block suspicious user-agents."
  },
  {
    id: "T1552.001",
    name: "Unsecured Credentials In Files",
    tactic: "Credential Access",
    domain: "Enterprise",
    severity: "HIGH",
    description: "Hardcoded API keys, private keys, or tokens in source code repositories.",
    mitigation: "Implement pre-commit secret scanners, rotate exposed keys, use secret managers."
  },
  {
    id: "T1190",
    name: "Exploit Public Application (SQLi)",
    tactic: "Initial Access",
    domain: "Enterprise",
    severity: "CRITICAL",
    description: "Adversaries exploit web dynamic queries using SQL injection to extract databases.",
    mitigation: "Use parameterized queries, ORM abstractions, WAF rule sets, input validation."
  },
  {
    id: "T1041",
    name: "Exfiltration Over C2 Channel",
    tactic: "Exfiltration",
    domain: "Enterprise",
    severity: "CRITICAL",
    description: "Stolen data is exfiltrated over existing C2 beacon connections in burst intervals.",
    mitigation: "Implement egress data rate limiting, DLP network sensors, anomaly detection."
  },
  {
    id: "T1059.006",
    name: "Command Scripting: Python/Eval",
    tactic: "Execution",
    domain: "Enterprise",
    severity: "MEDIUM",
    description: "Adversaries execute malicious scripts or dynamic code evaluation (eval/exec).",
    mitigation: "Restrict dynamic code execution, use AST SAST scanners, sandbox dynamic code."
  }
];

export function mapThreatToMitre(threatType = "") {
  const typeLower = threatType.toLowerCase();
  if (typeLower.includes("spyware") || typeLower.includes("pegasus")) {
    return [MITRE_TECHNIQUES_DATA[0], MITRE_TECHNIQUES_DATA[1]];
  }
  if (typeLower.includes("sqli") || typeLower.includes("sql")) {
    return [MITRE_TECHNIQUES_DATA[3]];
  }
  if (typeLower.includes("secret") || typeLower.includes("repo")) {
    return [MITRE_TECHNIQUES_DATA[2], MITRE_TECHNIQUES_DATA[5]];
  }
  return [MITRE_TECHNIQUES_DATA[1], MITRE_TECHNIQUES_DATA[4]];
}
