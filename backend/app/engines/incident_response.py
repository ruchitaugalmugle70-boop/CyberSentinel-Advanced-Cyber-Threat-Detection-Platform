"""
Automated Incident Containment & Response Playbook Engine for CyberSentinel.
Generates actionable remediation playbooks, shell commands, firewall rules, and token revocations.
"""

from typing import Dict, Any, List

PLAYBOOK_TEMPLATES = {
    "spyware": {
        "title": "Pegasus / Surveillance Spyware Isolation Playbook",
        "description": "Remediates active mobile or host surveillance compromises.",
        "steps": [
            {
                "step": 1,
                "action": "Network Isolation",
                "command": "sudo iptables -A OUTPUT -d {target_ip} -j DROP",
                "purpose": "Terminate active C2 socket connections immediately."
            },
            {
                "step": 2,
                "action": "Process Termination",
                "command": "sudo pkill -9 -f {process_name}",
                "purpose": "Kill suspect spyware child processes."
            },
            {
                "step": 3,
                "action": "Forensic Dump",
                "command": "sudo sysdiagnose -f /var/log/cybersentinel_evidence/",
                "purpose": "Capture full iOS / Linux system state for post-mortem analysis."
            }
        ]
    },
    "sqli": {
        "title": "SQL Injection & WAF Defense Playbook",
        "description": "Mitigates live SQL injection exploitation attempts.",
        "steps": [
            {
                "step": 1,
                "action": "WAF Rule Deployment",
                "command": "aws wafv2 update-ip-set --name BlockedSQLiIPs --addresses {target_ip}/32",
                "purpose": "Block malicious IP at AWS WAF layer."
            },
            {
                "step": 2,
                "action": "Database Session Termination",
                "command": "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE client_addr = '{target_ip}';",
                "purpose": "Kill active backend database connections from suspect IP."
            }
        ]
    },
    "repo": {
        "title": "Leaked Credential & Secret Revocation Playbook",
        "description": "Revokes exposed API tokens and hardcoded private keys.",
        "steps": [
            {
                "step": 1,
                "action": "Revoke Exposed AWS Key",
                "command": "aws iam update-access-key --access-key-id {secret_id} --status Inactive",
                "purpose": "Deactivate compromised IAM credentials."
            },
            {
                "step": 2,
                "action": "Git History Sanitization",
                "command": "git filter-repo --invert-paths --path {file_path}",
                "purpose": "Purge compromised file from all git repository commits."
            }
        ]
    },
    "network": {
        "title": "C2 Beaconing & DNS Tunnel Mitigation Playbook",
        "description": "Shields network egress against malware beaconing.",
        "steps": [
            {
                "step": 1,
                "action": "DNS Sinkhole",
                "command": "echo '127.0.0.1 {c2_domain}' | sudo tee -a /etc/hosts",
                "purpose": "Reroute outbound C2 DNS requests to loopback interface."
            },
            {
                "step": 2,
                "action": "Border Gateway Protocol (BGP) Null Route",
                "command": "sudo ip route add blackhole {target_ip}",
                "purpose": "Drop all outbound traffic to C2 IP range."
            }
        ]
    }
}

class IncidentResponseEngine:
    """Engine for generating containment playbooks based on threat findings."""

    def generate_playbook(self, threat_category: str, params: Dict[str, str] = None) -> Dict[str, Any]:
        params = params or {}
        cat_lower = threat_category.lower()

        if "spyware" in cat_lower or "pegasus" in cat_lower:
            template = PLAYBOOK_TEMPLATES["spyware"]
        elif "sqli" in cat_lower or "sql" in cat_lower:
            template = PLAYBOOK_TEMPLATES["sqli"]
        elif "repo" in cat_lower or "secret" in cat_lower:
            template = PLAYBOOK_TEMPLATES["repo"]
        else:
            template = PLAYBOOK_TEMPLATES["network"]

        target_ip = params.get("target_ip", "192.168.1.105")
        process_name = params.get("process_name", "netd_agent")
        secret_id = params.get("secret_id", "AKIAIOSFODNN7EXAMPLE")
        file_path = params.get("file_path", ".env")
        c2_domain = params.get("c2_domain", "pegasus-telemetry.org")

        formatted_steps = []
        for s in template["steps"]:
            cmd = s["command"].format(
                target_ip=target_ip,
                process_name=process_name,
                secret_id=secret_id,
                file_path=file_path,
                c2_domain=c2_domain
            )
            formatted_steps.append({
                "step": s["step"],
                "action": s["action"],
                "command": cmd,
                "purpose": s["purpose"]
            })

        return {
            "playbook_title": template["title"],
            "category": threat_category,
            "description": template["description"],
            "total_steps": len(formatted_steps),
            "containment_steps": formatted_steps,
            "verification_check": "Execute health endpoint `/api/v1/health` and verify zero active C2 connections."
        }

incident_response_engine = IncidentResponseEngine()
