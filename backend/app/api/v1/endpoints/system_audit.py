from fastapi import APIRouter
from typing import Dict, Any
from ....engines.system_audit import system_audit_engine

router = APIRouter(prefix="/system-audit", tags=["System Security Audit"])

@router.get("/check", response_model=Dict[str, Any])
def run_system_audit():
    """Perform security posture audit on backend host and environment."""
    return system_audit_engine.perform_audit()
