import re
import uuid
from typing import List
from app.data.threat_intelligence import KNOWN_SPYWARE_DOMAINS, KNOWN_SPYWARE_PROCESSES, KNOWN_MALWARE_HASHES
from app.models.schemas import ThreatFinding, DeviceBehaviorMetrics

HEURISTIC_PATTERNS = [
    {
        "regex": re.compile(r'/var/containers/Bundle/Application/[a-f0-9-]+/(?!com\.apple)', re.IGNORECASE),
        "name": "Sideloaded Suspicious Application Bundle",
        "severity": "medium",
        "desc": "Unsigned or sideloaded app bundle path detected in iOS application sandbox.",
        "remediation": "Audit enterprise profile signatures and remove unauthorized MDM configuration profiles."
    },
    {
        "regex": re.compile(r'shutdown\.log.*(?:libtouchregd|bh|roleaborede|com\.apple\.WebKit\.WebContent\.helper)', re.IGNORECASE),
        "name": "Pegasus Artifacts in iOS Shutdown Log",
        "severity": "critical",
        "desc": "Shutdown log exhibits sticky process anomalies consistent with NSO Group Pegasus zero-click persistence.",
        "remediation": "Immediate device isolation required. Back up sysdiagnose logs for forensic verification (MVT analysis)."
    },
    {
        "regex": re.compile(r'datausage\.sqlite.*(?:unknown|untitled|[a-z0-9]{16,}).*network', re.IGNORECASE),
        "name": "Stealth Background Data Exfiltration",
        "severity": "high",
        "desc": "Obfuscated process name recorded transmitting packets in cellular/Wi-Fi data usage database.",
        "remediation": "Capture network pcap and inspect routing table."
    },
    {
        "regex": re.compile(r'(?:microphone|camera).*(?:background|inactive|locked|headless)', re.IGNORECASE),
        "name": "Headless Sensor Eavesdropping",
        "severity": "critical",
        "desc": "Hardware microphone or camera driver activated without foreground user interaction or screen activation.",
        "remediation": "Power off device immediately. Suspect active zero-click surveillance implant."
    },
    {
        "regex": re.compile(r'(?:root|ca[-_]certificate).*install.*(?:untrusted|self-signed|profile)', re.IGNORECASE),
        "name": "Rogue CA Certificate Injection",
        "severity": "high",
        "desc": "Untrusted root authority injected into system trust store enabling full HTTPS MITM decryption.",
        "remediation": "Remove untrusted certificates from Settings -> General -> About -> Certificate Trust Settings."
    },
    {
        "regex": re.compile(r'(?:cydia|substrate|sileo|checkra1n|unc0ver|taurine|palera1n)', re.IGNORECASE),
        "name": "Jailbreak / Root Exploitation Found",
        "severity": "high",
        "desc": "Jailbreak framework signatures found, reducing core kernel protections (KPP/KTRR bypassed).",
        "remediation": "Restore device firmware using official signed DFU recovery image."
    }
]

def scan_text_for_iocs(content: str) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    text_lower = content.lower()

    # 1. Known malicious domain check
    for domain_entry in KNOWN_SPYWARE_DOMAINS:
        if domain_entry["pattern"].lower() in text_lower:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="domain_ioc",
                match=domain_entry["pattern"],
                name=f"Spyware C2 Domain: {domain_entry['pattern']}",
                category=domain_entry["type"],
                severity=domain_entry["severity"],
                description=f"Matched known Pegasus/Predator C2 endpoint '{domain_entry['pattern']}'.",
                recommendation="Block domain at DNS/firewall tier. Quarantine associated endpoints immediately."
            ))

    # 2. Known process check
    for proc in KNOWN_SPYWARE_PROCESSES:
        if proc["name"].lower() in text_lower:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="process_ioc",
                match=proc["name"],
                name=f"Disguised Spyware Process: {proc['name']}",
                category="Active Spyware Process",
                severity=proc["severity"],
                description=f"{proc['desc']}. Process name matches documented Pegasus/Predator payload.",
                recommendation="Terminate process, preserve crashdump memory images, and conduct offline forensic analysis."
            ))

    # 3. Hash matching
    for file_hash in KNOWN_MALWARE_HASHES:
        if file_hash.lower() in text_lower:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="hash_match",
                match=f"{file_hash[:16]}...",
                name="Known Spyware Binary Hash Match",
                category="Malware Hash",
                severity="critical",
                description=f"File SHA-256 hash {file_hash[:32]}... matches known NSO Pegasus payload binary.",
                recommendation="Quarantine the target file and submit to incident response team."
            ))

    # 4. Heuristic pattern checks
    for hp in HEURISTIC_PATTERNS:
        match = hp["regex"].search(content)
        if match:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="heuristic_anomaly",
                match=hp["name"],
                name=hp["name"],
                category="Heuristic Forensic Analysis",
                severity=hp["severity"],
                description=hp["desc"],
                recommendation=hp["remediation"],
                raw=match.group(0)[:120]
            ))

    return findings

def evaluate_device_metrics(metrics: DeviceBehaviorMetrics) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []

    if metrics.batteryDrain > 30:
        sev = "critical" if metrics.batteryDrain > 55 else "high"
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="behavior_metric",
            match=f"{metrics.batteryDrain}% / day battery drain",
            name="Abnormal Power Consumption Anomaly",
            category="Device Telemetry",
            severity=sev,
            description=f"Battery discharge rate of {metrics.batteryDrain}%/day exceeds baseline by >250%. Indicates unthrottled audio encoding or continuous background sensor capture.",
            recommendation="Inspect background execution time per app in system analytics."
        ))

    if metrics.dataUsage > 500:
        sev = "critical" if metrics.dataUsage > 1000 else "high"
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="behavior_metric",
            match=f"{metrics.dataUsage} MB / day network transfer",
            name="Excessive Outbound Exfiltration Flow",
            category="Data Exfiltration",
            severity=sev,
            description=f"Monitored device transmitted {metrics.dataUsage} MB over cellular/Wi-Fi during idle state.",
            recommendation="Inspect per-socket transmission stats in sysdiagnose netstat tables."
        ))

    if metrics.cpuSpikes > 5:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="behavior_metric",
            match=f"{metrics.cpuSpikes} unexplained CPU spikes",
            name="Unexplained CPU Burst Activity",
            category="Processor Anomalies",
            severity="medium",
            description=f"Identified {metrics.cpuSpikes} recurring high-load CPU spikes while the device display was locked.",
            recommendation="Analyze spin logs and core dumps to identify executing thread symbols."
        ))

    if metrics.unexpectedReboots > 2:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="behavior_metric",
            match=f"{metrics.unexpectedReboots} panics / reboots",
            name="Kernel Panic / Exploit Triggered Crashes",
            category="Kernel Stability",
            severity="high",
            description=f"{metrics.unexpectedReboots} unexpected reboots or kernel panics detected. Often caused by failed heap spray or race condition exploits.",
            recommendation="Extract panic.ips files from DiagnosticReports and analyze register state."
        ))

    return findings
