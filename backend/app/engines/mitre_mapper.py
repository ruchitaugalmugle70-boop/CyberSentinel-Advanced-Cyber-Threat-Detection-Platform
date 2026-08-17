"""
MITRE ATT&CK Threat Mapping Engine for CyberSentinel.
Maps detected spyware artifacts, SQL injection vulnerabilities, leaked credentials,
and network C2 beaconing to standard MITRE ATT&CK Enterprise and Mobile Tactics and Techniques.
"""

from typing import List, Dict, Any

MITRE_TECHNIQUES_CATALOG = [
    {
        "id": "T1430",
        "name": "Location Tracking & Device Surveillance",
        "tactic": "Collection",
        "domain": "Mobile",
        "severity": "CRITICAL",
        "description": "Spyware covertly tracks GPS location, cell tower IDs, and WiFi BSSIDs.",
        "mitigation": "Enforce strict location permissions, inspect locationd logs, disable background location."
    },
    {
        "id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols (HTTP/S)",
        "tactic": "Command and Control",
        "domain": "Enterprise",
        "severity": "HIGH",
        "description": "Adversaries communicate with C2 servers using standard HTTPS beaconing.",
        "mitigation": "Use SSL/TLS inspection, analyze domain entropy, block suspicious user-agents."
    },
    {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "domain": "Enterprise",
        "severity": "HIGH",
        "description": "Hardcoded API keys, private keys, or tokens in source code repositories.",
        "mitigation": "Implement pre-commit secret scanners, rotate exposed keys, use secret managers."
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application (SQL Injection)",
        "tactic": "Initial Access",
        "domain": "Enterprise",
        "severity": "CRITICAL",
        "description": "Adversaries exploit web dynamic queries using SQL injection to extract databases.",
        "mitigation": "Use parameterized queries, ORM abstractions, WAF rule sets, input validation."
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "domain": "Enterprise",
        "severity": "CRITICAL",
        "description": "Stolen data is exfiltrated over existing C2 beacon connections in burst intervals.",
        "mitigation": "Implement egress data rate limiting, DLP network sensors, anomaly detection."
    },
    {
        "id": "T1059.006",
        "name": "Command and Scripting Interpreter: Python",
        "tactic": "Execution",
        "domain": "Enterprise",
        "severity": "MEDIUM",
        "description": "Adversaries execute malicious scripts or dynamic code evaluation (eval/exec).",
        "mitigation": "Restrict dynamic code execution, use AST SAST scanners, sandbox dynamic code."
    }
]

class MitreMapperEngine:
    """Engine for mapping threat indicators to MITRE ATT&CK framework."""

    def __init__(self):
        self.catalog = {t["id"]: t for t in MITRE_TECHNIQUES_CATALOG}

    def get_full_matrix(self) -> List[Dict[str, Any]]:
        return MITRE_TECHNIQUES_CATALOG

    def get_technique_by_id(self, technique_id: str) -> Dict[str, Any]:
        return self.catalog.get(technique_id, {
            "id": technique_id,
            "name": "Unknown Technique",
            "tactic": "Unknown",
            "domain": "Enterprise",
            "severity": "LOW",
            "description": "No catalog entry found for this ID.",
            "mitigation": "Conduct forensic investigation."
        })

    def map_threat(self, threat_type: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Maps a given threat finding to relevant MITRE ATT&CK techniques."""
        threat_type_lower = threat_type.lower()
        mapped_techniques = []

        if "spyware" in threat_type_lower or "pegasus" in threat_type_lower:
            mapped_techniques.extend([self.catalog["T1430"], self.catalog["T1071.001"]])
        elif "sqli" in threat_type_lower or "sql" in threat_type_lower:
            mapped_techniques.append(self.catalog["T1190"])
        elif "secret" in threat_type_lower or "repo" in threat_type_lower:
            mapped_techniques.extend([self.catalog["T1552.001"], self.catalog["T1059.006"]])
        elif "network" in threat_type_lower or "c2" in threat_type_lower or "beacon" in threat_type_lower:
            mapped_techniques.extend([self.catalog["T1071.001"], self.catalog["T1041"]])
        else:
            mapped_techniques.append(self.catalog["T1071.001"])

        return {
            "threat_type": threat_type,
            "techniques_count": len(mapped_techniques),
            "techniques": mapped_techniques,
            "overall_mitre_score": "CRITICAL" if any(t["severity"] == "CRITICAL" for t in mapped_techniques) else "HIGH"
        }

mitre_mapper_engine = MitreMapperEngine()
