import re
import uuid
from typing import List
from datetime import datetime
from ..models.schemas import ThreatFinding, RepoAccessEvent

SECRET_DETECTION_RULES = [
    {
        "regex": re.compile(r'(AKIA[0-9A-Z]{16})'),
        "name": "AWS Access Key ID Leaked",
        "severity": "critical",
        "desc": "Valid Amazon Web Services access key identifier exposed in plain text.",
        "remediation": "Rotate key in AWS IAM immediately. Use AWS Secrets Manager or IAM Roles."
    },
    {
        "regex": re.compile(r'([A-Za-z0-9/+=]{40})(?=\s*[\'",\n])'),
        "name": "AWS Secret Access Key Pattern",
        "severity": "critical",
        "desc": "High-entropy 40-character secret key pattern matching AWS Secret Access Credentials.",
        "remediation": "Invalidate credential pair and review CloudTrail logs for unauthorized API calls."
    },
    {
        "regex": re.compile(r'(gh[pousr]_[A-Za-z0-9_]{36,255})'),
        "name": "GitHub Personal Access / OAuth Token",
        "severity": "critical",
        "desc": "Active GitHub user authentication token discovered.",
        "remediation": "Revoke token via GitHub Settings -> Developer settings -> Personal access tokens."
    },
    {
        "regex": re.compile(r'(xox[baprs]-[0-9a-zA-Z-]{10,72})'),
        "name": "Slack API / Bot Token",
        "severity": "high",
        "desc": "Slack workspace integration token discovered.",
        "remediation": "Revoke Slack app credentials in the Slack API dashboard."
    },
    {
        "regex": re.compile(r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)'),
        "name": "Unencrypted Cryptographic Private Key",
        "severity": "critical",
        "desc": "Raw PEM-encoded private key file header found in source repository.",
        "remediation": "Purge key from git commit history using BFG Repo-Cleaner or git-filter-repo."
    },
    {
        "regex": re.compile(r'((?:postgres|mysql|mongodb|redis|amqp):\/\/[^\s\'"]+)'),
        "name": "Hardcoded Database Connection URI with Credentials",
        "severity": "critical",
        "desc": "Full database URI containing embedded plaintext password or authentication tokens.",
        "remediation": "Extract connection string into environment variables (.env) and add .env to .gitignore."
    },
    {
        "regex": re.compile(r'(sk_live_[0-9a-zA-Z]{24,32})'),
        "name": "Stripe Live Secret API Key",
        "severity": "critical",
        "desc": "Live production billing API key for Stripe payment gateway.",
        "remediation": "Roll API keys immediately in the Stripe Developers Dashboard."
    },
    {
        "regex": re.compile(r'(AIza[0-9A-Za-z-_]{35})'),
        "name": "Google Cloud / Firebase API Key",
        "severity": "high",
        "desc": "Google Cloud service or Firebase client API key exposed.",
        "remediation": "Restrict key API scope and HTTP referrers in Google Cloud Console."
    },
    {
        "regex": re.compile(r'(eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+)'),
        "name": "Hardcoded JSON Web Token (JWT)",
        "severity": "high",
        "desc": "Hardcoded signed JWT containing claims and signature in code.",
        "remediation": "Ensure tokens are minted dynamically at runtime and never persisted in source."
    }
]

CODE_VULNERABILITY_RULES = [
    {
        "regex": re.compile(r'((?:eval|exec)\s*\(\s*(?:request|req|input|params|query|body|GET|POST))', re.IGNORECASE),
        "name": "Arbitrary Code Execution via eval()/exec()",
        "severity": "critical",
        "desc": "Dynamic interpretation of unsanitized user inputs enables Remote Code Execution (RCE).",
        "remediation": "Refactor logic to eliminate dynamic code evaluation entirely."
    },
    {
        "regex": re.compile(r'((?:chmod|chown)\s+(?:777|666|a\+rwx))', re.IGNORECASE),
        "name": "Insecure World-Writable File Permission Assignment",
        "severity": "high",
        "desc": "File permissions set to 777/666 permit unauthorized local file modification.",
        "remediation": "Enforce strict POSIX permissions (e.g., 640 or 750) adhering to least privilege."
    },
    {
        "regex": re.compile(r'(disable.*(?:ssl|tls|cert|verify)|rejectUnauthorized\s*:\s*false|verify\s*=\s*False)', re.IGNORECASE),
        "name": "TLS / SSL Certificate Verification Disabled",
        "severity": "critical",
        "desc": "Explicit bypass of TLS certificate verification opens network requests to Man-In-The-Middle interception.",
        "remediation": "Enable strict TLS certificate validation with system CA root bundle."
    },
    {
        "regex": re.compile(r'(TODO|FIXME|HACK).*(?:security|password|bypass|secret|auth|vuln)', re.IGNORECASE),
        "name": "Security-Sensitive TODO / Incomplete Implementation",
        "severity": "medium",
        "desc": "Developer comments highlighting unfinished security defenses or temporary auth bypasses.",
        "remediation": "Address technical debt before merging into production deployment branches."
    }
]

def mask_sensitive_token(token: str) -> str:
    if len(token) <= 8:
        return "****"
    return token[:4] + "*" * (len(token) - 8) + token[-4:]

def scan_source_code(code: str) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []
    lines = code.split("\n")

    for line_idx, line in enumerate(lines, start=1):
        # 1. Check secrets
        for rule in SECRET_DETECTION_RULES:
            match = rule["regex"].search(line)
            if match:
                matched_raw = match.group(0)
                findings.append(ThreatFinding(
                    id=str(uuid.uuid4()),
                    type="secret_leak",
                    match=mask_sensitive_token(matched_raw),
                    name=rule["name"],
                    category="Hardcoded Secret",
                    severity=rule["severity"],
                    description=rule["desc"],
                    line=line_idx,
                    raw=line.strip()[:100],
                    recommendation=rule["remediation"]
                ))

        # 2. Check code vulnerabilities
        for vrule in CODE_VULNERABILITY_RULES:
            vmatch = vrule["regex"].search(line)
            if vmatch:
                findings.append(ThreatFinding(
                    id=str(uuid.uuid4()),
                    type="code_vulnerability",
                    match=line.strip()[:60],
                    name=vrule["name"],
                    category="Static Application Security Testing (SAST)",
                    severity=vrule["severity"],
                    description=vrule["desc"],
                    line=line_idx,
                    raw=line.strip()[:100],
                    recommendation=vrule["remediation"]
                ))

    return findings

def audit_repository_access(events: List[RepoAccessEvent]) -> List[ThreatFinding]:
    findings: List[ThreatFinding] = []

    # 1. Bulk Clone Detection
    clone_events = [e for e in events if e.type.lower() == "clone"]
    if len(clone_events) >= 4:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="anomalous_access",
            match=f"{len(clone_events)} clones in short window",
            name="Rapid Automated Bulk Repository Cloning",
            category="Repository Threat Intelligence",
            severity="high",
            description=f"Observed {len(clone_events)} clone operations. Indicator of automated source code scrapers or compromised developer tokens.",
            recommendation="Review IP origins and temporarily rotate impacted developer personal access tokens."
        ))

    # 2. Off-hours activity check
    off_hours = [e for e in events if e.timestamp.hour < 6 or e.timestamp.hour > 22]
    if len(off_hours) >= 3:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="anomalous_access",
            match=f"{len(off_hours)} off-hours operations",
            name="Unusual Off-Hours Repository Operations (10 PM - 6 AM)",
            category="Behavioral Anomaly",
            severity="medium",
            description=f"{len(off_hours)} commits/clones recorded outside standard operational hours.",
            recommendation="Confirm activity legitimacy with repository contributors."
        ))

    # 3. Geo-dispersion anomaly
    locations = list(set([e.location for e in events if e.location]))
    if len(locations) >= 4:
        findings.append(ThreatFinding(
            id=str(uuid.uuid4()),
            type="anomalous_access",
            match=f"{len(locations)} concurrent regions",
            name="Multi-Geo Impossible Travel Access",
            category="Account Compromise Indicator",
            severity="high",
            description=f"Single repository accessed across {len(locations)} distinct geographic jurisdictions ({', '.join(locations[:4])}).",
            recommendation="Enable SAML Single Sign-On and enforce IP allowlisting."
        ))

    return findings
