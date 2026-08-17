from fastapi import APIRouter
from typing import Dict, Any
from ....engines.incident_response import incident_response_engine
from ....models.schemas import PlaybookGenerateRequest

router = APIRouter(prefix="/playbooks", tags=["Incident Response Playbooks"])

@router.post("/generate", response_model=Dict[str, Any])
def generate_playbook(req: PlaybookGenerateRequest):
    """Generate dynamic incident containment playbook for detected threat category."""
    params = {
        "target_ip": req.target_ip or "192.168.1.105",
        "process_name": req.process_name or "netd_agent",
        "c2_domain": req.c2_domain or "pegasus-telemetry.org"
    }
    return incident_response_engine.generate_playbook(req.category, params)
