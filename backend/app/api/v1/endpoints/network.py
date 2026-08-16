import time
from fastapi import APIRouter
from app.models.schemas import (
    TrafficAnalysisRequest,
    IPReputationResponse,
    ThreatFinding
)
from app.engines.network_analyzer import analyze_traffic_telemetry, evaluate_ip_reputation

router = APIRouter(prefix="/network", tags=["Network Telemetry & C2 Analyzer"])

@router.post("/analyze-traffic")
def analyze_network_traffic(payload: TrafficAnalysisRequest):
    findings = analyze_traffic_telemetry(payload.connections)
    return {
        "status": "complete",
        "total_connections": len(payload.connections),
        "threats_detected": len(findings),
        "findings": findings
    }

@router.get("/ip-reputation/{ip}", response_model=IPReputationResponse)
def get_ip_threat_reputation(ip: str):
    return evaluate_ip_reputation(ip)

@router.get("/simulate-stream")
def generate_simulated_stream():
    now = int(time.time() * 1000)
    return {
        "connections": [
            {
                "timestamp": now - 60000,
                "srcIp": "192.168.1.45",
                "dstIp": "185.220.101.42",
                "port": 443,
                "bytesIn": 1024,
                "bytesOut": 5242880,
                "protocol": "HTTPS",
                "query": None
            },
            {
                "timestamp": now - 50000,
                "srcIp": "192.168.1.45",
                "dstIp": "185.220.101.42",
                "port": 443,
                "bytesIn": 512,
                "bytesOut": 256,
                "protocol": "HTTPS",
                "query": None
            },
            {
                "timestamp": now - 40000,
                "srcIp": "192.168.1.45",
                "dstIp": "185.220.101.42",
                "port": 443,
                "bytesIn": 512,
                "bytesOut": 256,
                "protocol": "HTTPS",
                "query": None
            },
            {
                "timestamp": now - 30000,
                "srcIp": "192.168.1.45",
                "dstIp": "185.220.101.42",
                "port": 443,
                "bytesIn": 512,
                "bytesOut": 256,
                "protocol": "HTTPS",
                "query": None
            },
            {
                "timestamp": now - 20000,
                "srcIp": "10.0.0.15",
                "dstIp": "103.24.77.12",
                "port": 53,
                "bytesIn": 64,
                "bytesOut": 2048,
                "protocol": "DNS",
                "query": "aW1wb3J0YW50LXNlY3JldC1kYXRhLWV4ZmlsdHJhdGlvbi5leGFtcGxl.evil-dns.com"
            }
        ]
    }
