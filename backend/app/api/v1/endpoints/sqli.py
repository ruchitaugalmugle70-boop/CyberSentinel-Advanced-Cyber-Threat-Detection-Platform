from fastapi import APIRouter
from app.models.schemas import SQLiScanRequest, SQLiURLScanRequest, SQLiScanResponse
from app.engines.sqli_scanner import scan_sql_payload, scan_url_parameters, ADVANCED_SQLI_RULES

router = APIRouter(prefix="/sqli", tags=["SQL Injection Scanner"])

@router.post("/scan-payload", response_model=SQLiScanResponse)
def test_sql_payload(payload: SQLiScanRequest):
    findings = scan_sql_payload(payload.payload)
    return SQLiScanResponse(
        status="complete",
        is_vulnerable=len(findings) > 0,
        findings=findings,
        total_findings=len(findings)
    )

@router.post("/scan-url", response_model=SQLiScanResponse)
def audit_url_endpoint(payload: SQLiURLScanRequest):
    findings = scan_url_parameters(payload.url)
    return SQLiScanResponse(
        status="complete",
        is_vulnerable=len(findings) > 0,
        findings=findings,
        total_findings=len(findings)
    )

@router.get("/rules")
def get_sqli_rules():
    return {
        "total_rules": len(ADVANCED_SQLI_RULES),
        "rules": [
            {"name": r["name"], "severity": r["severity"], "description": r["desc"]}
            for r in ADVANCED_SQLI_RULES
        ]
    }
