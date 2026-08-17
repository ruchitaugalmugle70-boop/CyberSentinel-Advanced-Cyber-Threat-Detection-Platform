"""
YARA Rule Sandbox & Zero-Day Threat Inspection Engine for CyberSentinel.
Analyzes suspicious binary strings, dynamic memory logs, and raw code payloads against custom YARA rules and entropy indicators.
"""

import re
import math
from typing import Dict, Any, List

DEFAULT_YARA_RULES = [
    {
        "rule_name": "Pegasus_C2_Domain_Injector",
        "author": "CyberSentinel Labs",
        "description": "Detects obfuscated Pegasus C2 communication domain patterns.",
        "pattern": r"(?:https?:\/\/)?(?:[a-z0-9-]+\.)*(?:pegasus-c2|apple-cloud-check|nsogroup-telemetry|icloud-verify)\.[a-z]{2,}",
        "severity": "CRITICAL"
    },
    {
        "rule_name": "SQLi_Boolean_Bypass_Probe",
        "author": "CyberSentinel Labs",
        "description": "Detects classic OR 1=1 boolean bypass probes in request payloads.",
        "pattern": r"(?i)(?:'|\")?\s*(?:or|and)\s+(?:'|\")?[\w\d]+(?:'|\")?\s*=\s*(?:'|\")?[\w\d]+(?:'|\")?",
        "severity": "HIGH"
    },
    {
        "rule_name": "AWS_Secret_Access_Key_Leak",
        "author": "CyberSentinel Labs",
        "description": "Identifies hardcoded AWS Secret Access Key patterns.",
        "pattern": r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[:=]\s*[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?",
        "severity": "CRITICAL"
    },
    {
        "rule_name": "Hermit_Spyware_Exploit_Payload",
        "author": "CyberSentinel Labs",
        "description": "Detects Hermit mobile surveillance payload artifacts and root escalation scripts.",
        "pattern": r"(?i)(libhermit|sys_exploit_root|hermit_exfil|su_priv_escalate)",
        "severity": "CRITICAL"
    }
]

class YaraSandboxEngine:
    """Engine for compiling dynamic YARA rules and analyzing payload samples."""

    def __init__(self):
        self.rules = list(DEFAULT_YARA_RULES)

    def calculate_entropy(self, data: str) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0) of a data string to detect encryption/obfuscation."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        frequency = {}
        for char in data:
            frequency[char] = frequency.get(char, 0) + 1
        for count in frequency.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def add_rule(self, rule_name: str, pattern: str, description: str, severity: str = "HIGH") -> Dict[str, Any]:
        """Adds a custom YARA rule to the sandbox catalog."""
        new_rule = {
            "rule_name": rule_name,
            "author": "User Defined",
            "description": description,
            "pattern": pattern,
            "severity": severity
        }
        self.rules.append(new_rule)
        return new_rule

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def analyze_payload(self, payload_text: str) -> Dict[str, Any]:
        """Analyzes string payload for YARA rule matches and entropy metrics."""
        entropy = self.calculate_entropy(payload_text)
        matches = []

        for rule in self.rules:
            try:
                pattern = re.compile(rule["pattern"])
                found = pattern.findall(payload_text)
                if found:
                    matches.append({
                        "rule_name": rule["rule_name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "match_count": len(found),
                        "snippets": [str(m)[:60] for m in found[:3]]
                    })
            except Exception:
                continue

        threat_score = min(100, len(matches) * 25 + (30 if entropy > 5.8 else 0))
        
        return {
            "payload_length": len(payload_text),
            "shannon_entropy": entropy,
            "is_obfuscated": entropy > 5.8,
            "matched_rules_count": len(matches),
            "matches": matches,
            "threat_score": threat_score,
            "risk_assessment": "HIGH_RISK" if threat_score >= 50 else "LOW_RISK"
        }

yara_sandbox_engine = YaraSandboxEngine()
