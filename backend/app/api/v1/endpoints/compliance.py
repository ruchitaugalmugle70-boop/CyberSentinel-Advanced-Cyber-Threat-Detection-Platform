from fastapi import APIRouter
from typing import Dict, Any, List
from ....engines.compliance_reporter import compliance_reporter_engine
from ....models.schemas import ComplianceExportRequest

router = APIRouter(prefix="/compliance", tags=["Compliance & STIX Exporter"])

@router.post("/report", response_model=Dict[str, Any])
def generate_compliance_report(req: ComplianceExportRequest):
    """Generate ISO 27001 & NIST SP 800-53 security evidence report."""
    summary = req.dict()
    return compliance_reporter_engine.generate_compliance_report(summary)

@router.post("/stix", response_model=Dict[str, Any])
def generate_stix_bundle(findings: List[Dict[str, Any]]):
    """Generate STIX 2.1 JSON threat intelligence export bundle."""
    return compliance_reporter_engine.generate_stix_bundle(findings)
