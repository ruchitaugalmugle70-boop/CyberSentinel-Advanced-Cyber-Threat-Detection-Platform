import math
import uuid
from typing import List, Dict, Any
from app.data.threat_intelligence import MALICIOUS_IP_RANGES
from app.models.schemas import ThreatFinding, NetworkConnection, IPReputationResponse

SUSPICIOUS_MALICIOUS_PORTS = {
    4444: "Metasploit default reverse handler",
    5555: "Android ADB remote exploitation port",
    1337: "Custom backdoor listener",
    31337: "Classic Back Orifice trojan port",
    6667: "IRC botnet command & control",
    8888: "Unauthenticated proxy / payload stager",
    9999: "Abuse payload delivery port",
    54321: "SubSeven RAT default listener"
}

def analyze_traffic_telemetry(connections: List[NetworkConnection]) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    if not connections:
        return findings

    # 1. C2 Beaconing Periodic Analysis
    sorted_conns = sorted(connections, key=lambda c: c.timestamp)
    if len(sorted_conns) >= 5:
        intervals = []
        for i in range(1, len(sorted_conns)):
            diff = (sorted_conns[i].timestamp - sorted_conns[i - 1].timestamp) / 1000.0
            if diff > 0:
                intervals.append(diff)

        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)

            if std_dev < (avg_interval * 0.15) and len(intervals) >= 4:
                findings.append(ThreatFinding(
                    id=str(uuid.uuid4()),
                    type="network_beaconing",
                    match=f"Interval ~{round(avg_interval, 1)}s (σ={round(std_dev, 2)})",
                    name="Command & Control (C2) Heartbeat Beaconing",
                    category="Active C2 Infrastructure",
                    severity="critical",
                    description=f"Periodic heartbeat beacon detected every ~{round(avg_interval, 1)} seconds with minimal jitter (std dev {round(std_dev, 2)}s). Classic NSO Pegasus / Cobalt Strike keepalive cadence.",
                    recommendation="Sever network socket, apply firewall block rule to destination IP, and isolate host."
                ))

    # 2. Large Data Exfiltration Check
    large_outbounds = [c for c in connections if c.bytesOut > 1_000_000]
    if large_outbounds:
        total_exfil = sum(c.bytesOut for c in large_outbounds)
        mb_exfil = round(total_exfil / (1024 * 1024), 2)
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="data_exfiltration",
            match=f"{mb_exfil} MB outbound burst",
            name="Anomalous Bulk Data Exfiltration Stream",
            category="Data Loss Prevention (DLP)",
            severity="critical" if mb_exfil > 10 else "high",
            description=f"Detected {len(large_outbounds)} high-volume outbound packet transmissions totaling {mb_exfil} MB to external address.",
            recommendation="Inspect process PID owning the outbound socket via ss/lsof commands."
        ))

    # 3. DNS Tunneling Detection
    dns_queries = [c for c in connections if c.port == 53 and c.query]
    long_dns = [c for c in dns_queries if len(c.query) > 45]
    if len(long_dns) >= 3:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="dns_tunneling",
            match=f"{len(long_dns)} long DNS query payloads",
            name="DNS Tunneling / Covert Data Channel",
            category="Covert Channels",
            severity="critical",
            description=f"Identified {len(long_dns)} excessively long (>45 chars) base64/hex DNS queries. Indicates covert data encoding via authoritative nameservers.",
            recommendation="Configure DNS sinkholing and enforce maximum DNS label length constraints in local resolver."
        ))

    # 4. Suspicious Target Ports
    for c in connections:
        if c.port in SUSPICIOUS_MALICIOUS_PORTS:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="suspicious_port",
                match=f"Port {c.port} ({c.protocol})",
                name=f"Connection on High-Risk Port {c.port}",
                category="Port Telemetry",
                severity="high",
                description=f"Direct outbound packet stream to port {c.port} ({SUSPICIOUS_MALICIOUS_PORTS[c.port]}).",
                recommendation=f"Block outbound egress on TCP/UDP port {c.port} at the perimeter boundary."
            ))

    # 5. Port Scan Activity
    unique_ports = set(c.port for c in connections)
    if len(unique_ports) >= 15:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="port_scan",
            match=f"{len(unique_ports)} probed ports",
            name="Horizontal / Vertical Port Scan Sweep",
            category="Reconnaissance",
            severity="high",
            description=f"Host initiated connection attempts across {len(unique_ports)} distinct port endpoints.",
            recommendation="Enable automatic IP blocking via fail2ban / network IDS rules."
        ))

    return findings

def evaluate_ip_reputation(ip: str) -> IPReputationResponse:
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip == "127.0.0.1":
        return IPReputationResponse(
            ip=ip,
            status="internal",
            severity="info",
            description="RFC1918 Private / Internal Local Network Address",
            recommendation="Internal traffic. Ensure internal network segmentation is maintained."
        )

    for bad in MALICIOUS_IP_RANGES:
        if ip.startswith(bad["prefix"]):
            return IPReputationResponse(
                ip=ip,
                status="malicious",
                severity=bad["severity"],
                description=bad["desc"],
                recommendation=f"Immediately block IP {ip} in edge firewall and proxy blocklists."
            )

    return IPReputationResponse(
        ip=ip,
        status="clean",
        severity="info",
        description="No malicious reputation records in current threat intelligence feeds."
    )
