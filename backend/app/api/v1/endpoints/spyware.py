import time
from fastapi import APIRouter, HTTPException
from app.models.schemas import (
    SpywareScanRequest,
    DeviceBehaviorMetrics,
    SpywareScanResponse,
    ThreatFinding
)
from app.engines.spyware_detector import scan_text_for_iocs, evaluate_device_metrics
from app.data.threat_intelligence import KNOWN_SPYWARE_DOMAINS, KNOWN_SPYWARE_PROCESSES, KNOWN_MALWARE_HASHES

router = APIRouter(prefix="/spyware", tags=["Spyware Forensic Scanner"])

@router.post("/scan", response_model=SpywareScanResponse)
def scan_spyware_logs(payload: SpywareScanRequest):
    start = time.perf_counter()
    findings = scan_text_for_iocs(payload.content)
    duration = (time.perf_counter() - start) * 1000.0

    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")

    return SpywareScanResponse(
        status="complete",
        total_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        findings=findings,
        scan_duration_ms=round(duration, 2)
    )

@router.post("/analyze-device", response_model=SpywareScanResponse)
def analyze_device_telemetry(metrics: DeviceBehaviorMetrics):
    start = time.perf_counter()
    findings = evaluate_device_metrics(metrics)
    duration = (time.perf_counter() - start) * 1000.0

    critical_count = sum(1 for f in findings if f.severity == "critical")
    high_count = sum(1 for f in findings if f.severity == "high")
    medium_count = sum(1 for f in findings if f.severity == "medium")

    return SpywareScanResponse(
        status="complete",
        total_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        findings=findings,
        scan_duration_ms=round(duration, 2)
    )

@router.get("/iocs")
def get_known_iocs():
    return {
        "domains_count": len(KNOWN_SPYWARE_DOMAINS),
        "processes_count": len(KNOWN_SPYWARE_PROCESSES),
        "hashes_count": len(KNOWN_MALWARE_HASHES),
        "domains": KNOWN_SPYWARE_DOMAINS,
        "processes": KNOWN_SPYWARE_PROCESSES,
        "hashes": KNOWN_MALWARE_HASHES
    }
