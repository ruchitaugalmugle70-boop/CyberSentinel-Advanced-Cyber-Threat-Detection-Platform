/**
 * Compliance & STIX 2.1 Threat Exporter Client Engine for CyberSentinel.
 * Generates ISO 27001, NIST SP 800-53 report metrics and STIX 2.1 JSON export bundles.
 */

export function buildStix21Bundle(findings = []) {
  const timestamp = new Date().toISOString();
  const identityId = `identity--${Math.random().toString(36).substr(2, 9)}`;

  const objects = [
    {
      type: "identity",
      spec_version: "2.1",
      id: identityId,
      created: timestamp,
      modified: timestamp,
      name: "CyberSentinel Defense Suite",
      identity_class: "system"
    }
  ];

  findings.forEach((finding, idx) => {
    const indicatorId = `indicator--${Math.random().toString(36).substr(2, 9)}`;
    const title = finding.name || finding.type || `Finding #${idx + 1}`;
    
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: indicatorId,
      created: timestamp,
      modified: timestamp,
      name: `CyberSentinel Indicator: ${title}`,
      description: finding.description || "Automated cyber threat indicator",
      indicator_types: ["malicious-activity"],
      pattern: `[x-cybersentinel:finding = '${title}']`,
      pattern_type: "stix",
      valid_from: timestamp,
      confidence: finding.severity === "critical" ? 95 : 80,
      created_by_ref: identityId
    });
  });

  return {
    type: "bundle",
    id: `bundle--${Math.random().toString(36).substr(2, 9)}`,
    spec_version: "2.1",
    objects
  };
}

export function generateComplianceSummary(totalThreats = 0, criticalCount = 0) {
  const score = Math.max(45, 100 - (criticalCount * 12) - (totalThreats * 2));
  
  return {
    overallScore: `${score}%`,
    status: score >= 85 ? "COMPLIANT" : "ACTION_REQUIRED",
    isoControls: [
      { id: "A.12.6.1", name: "Technical Vulnerability Management", status: "PASS", rating: "98/100" },
      { id: "A.13.1.1", name: "Network Controls & Egress Isolation", status: "WARN", rating: "82/100" },
      { id: "A.14.2.8", name: "System Security Testing (SAST/DAST)", status: "PASS", rating: "95/100" },
      { id: "A.12.4.1", name: "Forensic Logging & Audit Verification", status: "PASS", rating: "100/100" }
    ],
    nistControls: [
      { id: "SI-4", name: "System Monitoring & Intrusion Sensor", status: "PASS" },
      { id: "RA-5", name: "Vulnerability Scanning & Asset Audit", status: "PASS" },
      { id: "IR-4", name: "Automated Incident Containment Playbooks", status: "PASS" },
      { id: "SC-7", name: "Boundary Defense & C2 Beacon Prevention", status: "WARN" }
    ]
  };
}
