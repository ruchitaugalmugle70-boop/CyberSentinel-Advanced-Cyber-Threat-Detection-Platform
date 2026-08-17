from fastapi import APIRouter
from typing import Dict, Any, List
from ....engines.yara_sandbox import yara_sandbox_engine
from ....models.schemas import YaraScanRequest, YaraRuleCreateRequest

router = APIRouter(prefix="/yara", tags=["YARA Rule Sandbox"])

@router.get("/rules", response_model=List[Dict[str, Any]])
def get_rules():
    """Get catalog of active YARA rules."""
    return yara_sandbox_engine.get_rules()

@router.post("/scan", response_model=Dict[str, Any])
def scan_payload(req: YaraScanRequest):
    """Scan payload text against active YARA rules and calculate Shannon entropy."""
    return yara_sandbox_engine.analyze_payload(req.payload)

@router.post("/rule", response_model=Dict[str, Any])
def add_custom_rule(req: YaraRuleCreateRequest):
    """Add a custom YARA rule to the active catalog."""
    return yara_sandbox_engine.add_rule(
        rule_name=req.rule_name,
        pattern=req.pattern,
        description=req.description,
        severity=req.severity or "HIGH"
    )
