"""
API Endpoint Integration Tests for CyberSentinel.
Tests FastAPI endpoints for spyware, sqli, repo, network, mitre, compliance, yara, playbooks, system_audit, and health.
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient
from app.main import app

class TestApiEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_root_endpoint(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("version", response.json())

    def test_health_endpoint(self):
        response = self.client.get("/api/v1/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_spyware_scan_api(self):
        payload = {"content": "Sample log with arfrfrfrfrfr.com C2 domain", "source_type": "generic_log"}
        response = self.client.post("/api/v1/spyware/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()["total_findings"], 1)

    def test_sqli_scan_api(self):
        payload = {"payload": "' OR '1'='1"}
        response = self.client.post("/api/v1/sqli/scan-payload", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["is_vulnerable"])

    def test_repo_scan_api(self):
        payload = {"code": "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'", "filename": "config.py"}
        response = self.client.post("/api/v1/repo/scan-code", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()["secrets_count"], 1)

    def test_mitre_matrix_api(self):
        response = self.client.get("/api/v1/mitre/matrix")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.json()), 4)

    def test_yara_scan_api(self):
        payload = {"payload": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}
        response = self.client.post("/api/v1/yara/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()["matched_rules_count"], 1)

    def test_playbook_generate_api(self):
        payload = {"category": "spyware", "target_ip": "192.168.1.50"}
        response = self.client.post("/api/v1/playbooks/generate", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn("containment_steps", response.json())

    def test_system_audit_api(self):
        response = self.client.get("/api/v1/system-audit/check")
        self.assertEqual(response.status_code, 200)
        self.assertIn("overall_security_score", response.json())

if __name__ == "__main__":
    unittest.main()
