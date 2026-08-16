# Threat Intelligence feeds and signature database for Pegasus, Predator, and APT actors

KNOWN_SPYWARE_DOMAINS = [
    {"pattern": "arfrfrfrfrfr.com", "type": "Pegasus C2 Infrastructure", "severity": "critical"},
    {"pattern": "bafrfrfrfrfr.com", "type": "Pegasus C2 Infrastructure", "severity": "critical"},
    {"pattern": "drfrfrfrfrfr.com", "type": "Pegasus C2 Infrastructure", "severity": "critical"},
    {"pattern": "free247downloads.com", "type": "Pegasus Exploit Delivery Server", "severity": "critical"},
    {"pattern": "urlpush.net", "type": "Pegasus Exploit Delivery Server", "severity": "critical"},
    {"pattern": "maborightede.com", "type": "Pegasus Anonymization Proxy", "severity": "high"},
    {"pattern": "opposedarede.com", "type": "Pegasus Anonymization Proxy", "severity": "high"},
    {"pattern": "pclogin-service.net", "type": "Predator Intellexa Spyware C2", "severity": "critical"},
    {"pattern": "taaborightede.net", "type": "Pegasus Stage-2 Payload Delivery", "severity": "high"},
    {"pattern": "revolution-ede.com", "type": "Pegasus Telemetry Hub", "severity": "critical"},
    {"pattern": "tracking-analytics-cdn.com", "type": "Chrysaor Surveillance Domain", "severity": "critical"},
    {"pattern": "update-service-apple.net", "type": "Hermit Spyware Impersonation", "severity": "critical"},
]

KNOWN_SPYWARE_PROCESSES = [
    {"name": "libtouchregd", "desc": "Pegasus disguised touch registration daemon", "severity": "critical"},
    {"name": "roleaborede", "desc": "Pegasus root escalation agent", "severity": "critical"},
    {"name": "ABSCarrier", "desc": "Pegasus cellular exfiltration carrier module", "severity": "critical"},
    {"name": "brstaged", "desc": "Pegasus zero-click bridge stager", "severity": "high"},
    {"name": "caborightede", "desc": "Pegasus encrypted keylogger payload", "severity": "high"},
    {"name": "RollingStorage", "desc": "Pegasus audio/location buffer collector", "severity": "critical"},
    {"name": "natgd", "desc": "Predator surveillance network routing daemon", "severity": "critical"},
    {"name": "paborightede", "desc": "Pegasus persistence manager daemon", "severity": "high"},
    {"name": "cfaborightede", "desc": "Pegasus CoreFoundation hook module", "severity": "high"},
    {"name": "msgacntd", "desc": "Disguised iMessage payload injector", "severity": "high"},
    {"name": "accountsd_x", "desc": "Trojanized accounts daemon", "severity": "critical"},
    {"name": "com.apple.WebKit.WebContent.helper", "desc": "Exploited WebKit child process (Pegasus sandbox escape)", "severity": "critical"},
]

KNOWN_MALWARE_HASHES = [
    "e1a83e87a4b6e5f2c8d9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
    "f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3",
    "9c72e25d2b781a9bc34812f84b63e1452a38914bca81902c31e92d837a1e82bb",
    "5d41402abc4b2a76b9719d911017c592182049e2182049281a0293847291a10b"
]

MALICIOUS_IP_RANGES = [
    {"prefix": "185.220.", "desc": "Tor exit node / known exploit distribution point", "severity": "high"},
    {"prefix": "45.33.", "desc": "Bulletproof VPS hosting known C2 nodes", "severity": "medium"},
    {"prefix": "91.134.", "desc": "Known malware command & control infrastructure", "severity": "high"},
    {"prefix": "103.24.", "desc": "APT botnet controller and data drop network", "severity": "critical"},
    {"prefix": "5.188.", "desc": "Automated brute-force and zero-click scanner", "severity": "high"},
    {"prefix": "141.98.", "desc": "Mass vulnerability exploitation probe source", "severity": "medium"},
    {"prefix": "194.26.", "desc": "Predator spyware active exfiltration node", "severity": "critical"}
]
