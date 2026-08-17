from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from ....engines.mitre_mapper import mitre_mapper_engine
from ....models.schemas import MitreMapRequest

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK Mapping"])

@router.get("/matrix", response_model=List[Dict[str, Any]])
def get_mitre_matrix():
    """Retrieve full catalog of MITRE ATT&CK Enterprise & Mobile techniques."""
    return mitre_mapper_engine.get_full_matrix()

@router.get("/technique/{technique_id}", response_model=Dict[str, Any])
def get_technique(technique_id: str):
    """Lookup specific MITRE technique by ID (e.g., T1430, T1071.001)."""
    return mitre_mapper_engine.get_technique_by_id(technique_id)

@router.post("/map", response_model=Dict[str, Any])
def map_threat_finding(req: MitreMapRequest):
    """Map detected threat finding to relevant MITRE ATT&CK techniques."""
    return mitre_mapper_engine.map_threat(req.threat_type, req.threat_data or {})
