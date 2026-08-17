"""
Unit Test Suite for CyberSentinel Backend Engines.
Tests spyware detector, SQLi scanner, repo SAST scanner, network telemetry analyzer,
MITRE mapper, YARA sandbox, compliance exporter, and incident response playbooks.
"""

import unittest
import sys
import os

# Ensure backend folder is on sys.path for direct imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.schemas import NetworkConnection
from app.engines.spyware_detector import scan_text_for_iocs
from app.engines.sqli_scanner import scan_sql_payload
from app.engines.repo_scanner import scan_source_code
from app.engines.network_analyzer import analyze_traffic_telemetry, evaluate_ip_reputation
from app.engines.mitre_mapper import mitre_mapper_engine
from app.engines.compliance_reporter import compliance_reporter_engine
from app.engines.yara_sandbox import yara_sandbox_engine
from app.engines.incident_response import incident_response_engine
from app.engines.system_audit import system_audit_engine

class TestBackendEngines(unittest.TestCase):

    def test_spyware_detection(self):
        sample_log = "Error launching process /System/Library/PrivateFrameworks/libtouchregd.framework/libtouchregd or connecting to arfrfrfrfrfr.com"
        findings = scan_text_for_iocs(sample_log)
        self.assertGreaterEqual(len(findings), 1)

    def test_sqli_scanning(self):
        payload = "' OR '1'='1"
        findings = scan_sql_payload(payload)
        self.assertGreaterEqual(len(findings), 1)

    def test_repo_scanner_secret_leak(self):
        code = "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        findings = scan_source_code(code)
        secrets_cnt = sum(1 for f in findings if f.type == "secret_leak")
        self.assertGreaterEqual(secrets_cnt, 1)

    def test_network_analyzer_c2_beaconing(self):
        connections = [
            NetworkConnection(timestamp=1000, srcIp="192.168.1.10", dstIp="185.220.101.5", port=443, bytesIn=500, bytesOut=200, protocol="TCP"),
            NetworkConnection(timestamp=1005, srcIp="192.168.1.10", dstIp="185.220.101.5", port=443, bytesIn=500, bytesOut=200, protocol="TCP"),
            NetworkConnection(timestamp=1010, srcIp="192.168.1.10", dstIp="185.220.101.5", port=443, bytesIn=500, bytesOut=200, protocol="TCP"),
        ]
        findings = analyze_traffic_telemetry(connections)
        self.assertIsInstance(findings, list)

    def test_mitre_mapper(self):
        res = mitre_mapper_engine.map_threat("spyware", {})
        self.assertGreaterEqual(res["techniques_count"], 1)
        self.assertEqual(res["overall_mitre_score"], "CRITICAL")

    def test_stix_compliance(self):
        stix = compliance_reporter_engine.generate_stix_bundle([{"type": "Pegasus Spyware", "severity": "CRITICAL"}])
        self.assertEqual(stix["type"], "bundle")
        self.assertGreaterEqual(len(stix["objects"]), 2)

    def test_yara_sandbox(self):
        payload = "SELECT * FROM users WHERE id = '1' OR '1'='1'"
        res = yara_sandbox_engine.analyze_payload(payload)
        self.assertGreaterEqual(res["matched_rules_count"], 1)
        self.assertGreater(res["shannon_entropy"], 0)

    def test_incident_response_playbook(self):
        pb = incident_response_engine.generate_playbook("spyware", {"target_ip": "10.0.0.5"})
        self.assertEqual(pb["total_steps"], 3)
        self.assertIn("10.0.0.5", pb["containment_steps"][0]["command"])

    def test_system_audit(self):
        audit = system_audit_engine.perform_audit()
        self.assertIn("overall_security_score", audit)
        self.assertGreaterEqual(audit["total_checks"], 4)

if __name__ == "__main__":
    unittest.main()
