import random
import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter
from app.models.schemas import AlertItem, DashboardStatsResponse

router = APIRouter(prefix="/alerts", tags=["Threat Alerts & Telemetry Feed"])

SAMPLE_ALERT_TEMPLATES = [
    {"message": "Suspicious outbound TLS session to known Pegasus C2 domain (arfrfrfrfrfr.com)", "severity": "critical", "category": "spyware", "source": "192.168.1.45"},
    {"message": "SQL injection attempt blocked: UNION SELECT admin hash probe", "severity": "high", "category": "sqli", "source": "103.24.77.12"},
    {"message": "Hardcoded production AWS Secret Access Key identified in commit", "severity": "critical", "category": "repo", "source": "git-sast"},
    {"message": "Periodic C2 beaconing detected (interval 10s, low jitter)", "severity": "critical", "category": "network", "source": "net-analyzer"},
    {"message": "Covert DNS tunneling query on port 53 (>50 bytes base64)", "severity": "high", "category": "network", "source": "10.0.0.15"},
    {"message": "Process 'libtouchregd' executed from unusual iOS container directory", "severity": "critical", "category": "spyware", "source": "sysdiagnose-agent"},
    {"message": "Anomalous bulk repository cloning event detected from foreign IP", "severity": "high", "category": "repo", "source": "185.220.101.42"},
    {"message": "Time-based blind SQLi probe injected into /api/v1/users", "severity": "medium", "category": "sqli", "source": "45.33.128.91"}
]

@router.get("/feed", response_model=List[AlertItem])
def get_recent_alerts(limit: int = 15):
    alerts = []
    for i in range(min(limit, len(SAMPLE_ALERT_TEMPLATES))):
        template = SAMPLE_ALERT_TEMPLATES[i]
        alerts.append(AlertItem(
            id=str(uuid.uuid4()),
            message=template["message"],
            severity=template["severity"],
            category=template["category"],
            source=template["source"],
            timestamp=datetime.utcnow()
        ))
    return alerts

@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_summary():
    return DashboardStatsResponse(
        threatsDetected={"value": 1247, "trend": "+12%", "direction": "up"},
        activeScans={"value": 8, "trend": "3 pending", "direction": "neutral"},
        securityScore={"value": 73, "trend": "+5pts", "direction": "down"},
        vulnerabilities={"value": 23, "trend": "-8%", "direction": "down"},
        distribution=[
            {"label": "Zero-Click Exploit", "value": 18, "color": "#ff3366"},
            {"label": "SQL Injection", "value": 28, "color": "#ffaa00"},
            {"label": "Code Secrets Leak", "value": 12, "color": "#a855f7"},
            {"label": "Network C2 Intrusion", "value": 25, "color": "#00f0ff"},
            {"label": "Phishing Delivery", "value": 10, "color": "#00ff88"},
            {"label": "Brute Force Recon", "value": 7, "color": "#3b82f6"}
        ]
    )
