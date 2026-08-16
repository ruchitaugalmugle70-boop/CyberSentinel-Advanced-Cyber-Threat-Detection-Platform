import re
import urllib.parse
import uuid
from typing import List
from ..models.schemas import ThreatFinding

ADVANCED_SQLI_RULES = [
    {
        "pattern": re.compile(r"(['\"]\s*(?:OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
        "name": "Boolean-Based Authentication Bypass",
        "severity": "critical",
        "desc": "Tautological boolean expression designed to force WHERE condition evaluation to TRUE.",
        "remediation": "Replace dynamic string concatenation with parameterized prepared statements."
    },
    {
        "pattern": re.compile(r"(['\"];\s*(?:DROP|DELETE|TRUNCATE|ALTER|UPDATE)\s+[\w]+)", re.IGNORECASE),
        "name": "Stacked Destructive Query Execution",
        "severity": "critical",
        "desc": "Stacked semicolon SQL statement attempting destructive database modification.",
        "remediation": "Disable multi-statement query support in database driver and enforce least-privilege DB user permissions."
    },
    {
        "pattern": re.compile(r"(UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL|[\d]+|[\w]+)(?:\s*,\s*(?:NULL|[\d]+|[\w]+))*)", re.IGNORECASE),
        "name": "UNION-Based Data Extraction Attack",
        "severity": "critical",
        "desc": "UNION query operator used to append unauthorized result sets from system or user tables.",
        "remediation": "Ensure parameterized queries and validate input against strict whitelist schemas."
    },
    {
        "pattern": re.compile(r"((?:WAITFOR\s+DELAY|SLEEP\s*\(|BENCHMARK\s*\(|pg_sleep\s*\())", re.IGNORECASE),
        "name": "Time-Based Blind SQL Injection Probe",
        "severity": "high",
        "desc": "Time delay payload injected to infer database response timing through side-channel delays.",
        "remediation": "Implement query timeout thresholds and enforce rigorous input sanitation."
    },
    {
        "pattern": re.compile(r"((?:INFORMATION_SCHEMA|sys\.tables|sysobjects|all_tables|sqlite_master))", re.IGNORECASE),
        "name": "Database Schema Meta-Enumeration",
        "severity": "critical",
        "desc": "Targeted probe querying metadata tables to extract database structure and table definitions.",
        "remediation": "Restrict metadata schema visibility to high-privilege administrative accounts."
    },
    {
        "pattern": re.compile(r"((?:xp_cmdshell|sp_executesql|EXEC\s*\(|EXECUTE\s*IMMEDIATE))", re.IGNORECASE),
        "name": "Stored Procedure / Remote Code Execution Probe",
        "severity": "critical",
        "desc": "Attempting execution of extended stored procedures or dynamic SQL execution bridges.",
        "remediation": "Revoke execute privileges on master system procedures and disable xp_cmdshell."
    },
    {
        "pattern": re.compile(r"((?:LOAD_FILE\s*\(|INTO\s+(?:OUT|DUMP)FILE|UTL_FILE))", re.IGNORECASE),
        "name": "Arbitrary File I/O via SQL Engine",
        "severity": "critical",
        "desc": "Attempt to read or write files directly from the underlying operating system file system.",
        "remediation": "Run database daemon under restricted non-root UID and disable file privilege grants (secure_file_priv)."
    },
    {
        "pattern": re.compile(r"((?:\/\*.*?\*\/){2,}|(?:--[^\n]*\n?){2,})", re.IGNORECASE),
        "name": "Comment Obfuscation / WAF Bypass",
        "severity": "medium",
        "desc": "Multi-comment delimiters structured to fragment keyword tokens and evade Web Application Firewall inspection.",
        "remediation": "Normalize incoming requests prior to regex rule evaluation in reverse proxy layers."
    },
    {
        "pattern": re.compile(r"(0x[0-9a-f]{6,}|CHAR\s*\(\s*\d+\s*(?:,\s*\d+\s*)*\))", re.IGNORECASE),
        "name": "Hexadecimal / Character Encoding Evasion",
        "severity": "medium",
        "desc": "Hexadecimal or ASCII numeric function encoding used to disguise injected SQL string literals.",
        "remediation": "Decode all input encodings before tokenization and validation."
    }
]

def scan_sql_payload(payload: str) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    
    # URL decode in case payload was URL-encoded
    decoded_payload = urllib.parse.unquote(payload)

    for rule in ADVANCED_SQLI_RULES:
        match = rule["pattern"].search(decoded_payload)
        if match:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="sqli_payload_match",
                match=match.group(0)[:80],
                name=rule["name"],
                category="SQL Injection Vulnerability",
                severity=rule["severity"],
                description=rule["desc"],
                recommendation=rule["remediation"],
                raw=match.group(0)
            ))

    # Basic heuristic check if no specific regex triggered but suspicious characters combine
    if not findings:
        has_keywords = any(kw in decoded_payload.upper() for kw in ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "WHERE"])
        has_symbols = any(sym in decoded_payload for sym in ["'", '"', "--", ";", "/*"])
        if has_keywords and has_symbols:
            findings.append(ThreatFinding(
                id=str(uuid.uuid4()),
                type="sqli_heuristic",
                match="SQL Keywords + Meta Characters",
                name="Suspicious SQL Keyword / Delimiter Combination",
                category="Heuristic Anomaly",
                severity="medium",
                description="Input contains database DDL/DML keywords combined with quotation/comment characters.",
                recommendation="Validate and strongly type all user inputs."
            ))

    return findings

def scan_url_parameters(url: str) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    try:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        for param_name, values in params.items():
            for val in values:
                param_findings = scan_sql_payload(val)
                for f in param_findings:
                    f.location = f"URL Query Parameter: '{param_name}'"
                    findings.append(f)

                # Flag raw numeric parameter manipulation
                if val.isdigit():
                    findings.append(ThreatFinding(
                        id=str(uuid.uuid4()),
                        type="sqli_numeric_probe",
                        match=f"{param_name}={val}",
                        name=f"Unvalidated Integer Parameter: {param_name}",
                        category="Parameter Fuzzing Candidate",
                        severity="low",
                        description=f"Parameter '{param_name}' accepts raw numbers. Test with: {param_name}={val} OR 1=1 to confirm type safety.",
                        location=f"URL Parameter: {param_name}",
                        recommendation="Enforce explicit type casting (e.g., int(param)) before querying database."
                    ))
    except Exception as e:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="error",
            name="URL Parsing Failure",
            severity="info",
            description=f"Could not parse URL structure: {str(e)}"
        ))

    return findings
