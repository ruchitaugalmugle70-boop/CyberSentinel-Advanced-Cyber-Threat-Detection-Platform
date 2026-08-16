from fastapi import APIRouter
from datetime import datetime

router = APIRouter(prefix="/health", tags=["Health & Status"])

@router.get("")
def health_check():
    return {
        "status": "healthy",
        "service": "CyberSentinel Threat Defense Backend",
        "engines": {
            "spyware_detector": "active",
            "sqli_scanner": "active",
            "repo_sast_engine": "active",
            "network_c2_analyzer": "active"
        },
        "timestamp": datetime.utcnow().isoformat()
    }
