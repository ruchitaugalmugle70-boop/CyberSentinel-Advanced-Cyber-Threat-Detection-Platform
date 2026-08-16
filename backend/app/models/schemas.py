from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

# Common Finding Model
class ThreatFinding(BaseModel):
    id: Optional[str] = None
    type: str
    match: Optional[str] = None
    name: Optional[str] = None
    category: Optional[str] = None
    severity: str  # critical, high, medium, low, info
    description: str
    recommendation: Optional[str] = None
    location: Optional[str] = None
    line: Optional[int] = None
    raw: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# Spyware Models
class SpywareScanRequest(BaseModel):
    content: str = Field(..., description="Logs, process lists, hashes, or sysdiagnose text")
    source_type: Optional[str] = "generic_log"  # ios_shutdown, sysdiagnose, process_list, url_history

class DeviceBehaviorMetrics(BaseModel):
    batteryDrain: float = Field(..., description="Battery drain % per day")
    dataUsage: float = Field(..., description="Data usage in MB per day")
    cpuSpikes: int = Field(..., description="Count of unexplained CPU spikes")
    unexpectedReboots: int = Field(..., description="Count of unexpected reboots")

class SpywareScanResponse(BaseModel):
    status: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    findings: List[ThreatFinding]
    scan_duration_ms: float

# SQLi Models
class SQLiScanRequest(BaseModel):
    payload: str = Field(..., description="SQL query or form input to test")

class SQLiURLScanRequest(BaseModel):
    url: str = Field(..., description="Full URL with query parameters")

class SQLiScanResponse(BaseModel):
    status: str
    is_vulnerable: bool
    findings: List[ThreatFinding]
    total_findings: int

# Repo SAST Models
class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Source code or config file content")
    filename: Optional[str] = "source_code.txt"

class RepoAccessEvent(BaseModel):
    type: str
    user: str
    timestamp: datetime
    location: Optional[str] = None
    ip: Optional[str] = None

class RepoAccessAnalysisRequest(BaseModel):
    events: List[RepoAccessEvent]

class RepoScanResponse(BaseModel):
    status: str
    findings: List[ThreatFinding]
    secrets_count: int
    vulnerabilities_count: int

# Network Models
class NetworkConnection(BaseModel):
    timestamp: int
    srcIp: str
    dstIp: str
    port: int
    bytesIn: int
    bytesOut: int
    protocol: str
    query: Optional[str] = None

class TrafficAnalysisRequest(BaseModel):
    connections: List[NetworkConnection]

class IPReputationResponse(BaseModel):
    ip: str
    status: str  # malicious, clean, internal
    severity: str
    description: str
    recommendation: Optional[str] = None

# Alert Feed
class AlertItem(BaseModel):
    id: str
    message: str
    severity: str
    category: str
    source: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class DashboardStatsResponse(BaseModel):
    threatsDetected: Dict[str, Any]
    activeScans: Dict[str, Any]
    securityScore: Dict[str, Any]
    vulnerabilities: Dict[str, Any]
    distribution: List[Dict[str, Any]]
