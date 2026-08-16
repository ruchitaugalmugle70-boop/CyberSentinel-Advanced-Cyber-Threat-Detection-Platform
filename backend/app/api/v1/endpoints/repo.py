from fastapi import APIRouter
from app.models.schemas import (
    CodeScanRequest,
    RepoAccessAnalysisRequest,
    RepoScanResponse,
    ThreatFinding
)
from app.engines.repo_scanner import (
    scan_source_code,
    audit_repository_access,
    SECRET_DETECTION_RULES,
    CODE_VULNERABILITY_RULES
)

router = APIRouter(prefix="/repo", tags=["Repository SAST & Security"])

@router.post("/scan-code", response_model=RepoScanResponse)
def scan_code_secrets_and_vulns(payload: CodeScanRequest):
    findings = scan_source_code(payload.code)
    secrets_count = sum(1 for f in findings if f.type == "secret_leak")
    vulns_count = sum(1 for f in findings if f.type == "code_vulnerability")

    return RepoScanResponse(
        status="complete",
        findings=findings,
        secrets_count=secrets_count,
        vulnerabilities_count=vulns_count
    )

@router.post("/analyze-access")
def analyze_git_telemetry(payload: RepoAccessAnalysisRequest):
    findings = audit_repository_access(payload.events)
    return {
        "status": "complete",
        "total_anomalies": len(findings),
        "findings": findings
    }

@router.get("/rules")
def get_sast_rules():
    return {
        "secret_rules": [
            {"name": r["name"], "severity": r["severity"], "description": r["desc"]}
            for r in SECRET_DETECTION_RULES
        ],
        "vulnerability_rules": [
            {"name": r["name"], "severity": r["severity"], "description": r["desc"]}
            for r in CODE_VULNERABILITY_RULES
        ]
    }
