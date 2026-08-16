// Repository Security Monitor Engine
import { SECRET_PATTERNS } from '../utils/threatData';

// Scan code for hardcoded secrets and credentials
export function scanForSecrets(code) {
  const results = [];
  const lines = code.split('\n');

  lines.forEach((line, index) => {
    SECRET_PATTERNS.forEach((pattern) => {
      const match = line.match(pattern.regex);
      if (match) {
        results.push({
          type: 'secret',
          name: pattern.name,
          severity: pattern.severity,
          description: pattern.desc,
          line: index + 1,
          match: maskSecret(match[0]),
          raw: match[0],
          recommendation: getSecretRemediation(pattern.name),
        });
      }
    });
  });

  // Check for common dangerous patterns
  const dangerousPatterns = [
    { regex: /\.env.*(?:production|prod)/i, name: 'Production .env Reference', severity: 'high', desc: 'Reference to production environment file detected' },
    { regex: /(?:TODO|FIXME|HACK).*(?:password|secret|key|token)/i, name: 'Security TODO', severity: 'medium', desc: 'Security-related TODO comment found — incomplete security implementation' },
    { regex: /(?:disable|skip|bypass).*(?:auth|ssl|tls|verify|certificate)/i, name: 'Security Bypass', severity: 'critical', desc: 'Code appears to disable security mechanisms' },
    { regex: /(?:eval|exec)\s*\(.*(?:request|input|param|query)/i, name: 'Code Injection Risk', severity: 'critical', desc: 'Dynamic code execution with user input — high risk of code injection' },
    { regex: /(?:chmod|chown)\s+(?:777|666)/i, name: 'Insecure Permissions', severity: 'high', desc: 'World-writable file permissions set — security risk' },
    { regex: /(?:http:\/\/)(?!localhost|127\.0\.0\.1)/i, name: 'Insecure HTTP', severity: 'medium', desc: 'Non-localhost HTTP URL found — data transmitted without encryption' },
  ];

  lines.forEach((line, index) => {
    dangerousPatterns.forEach((dp) => {
      if (dp.regex.test(line)) {
        results.push({
          type: 'vulnerability',
          name: dp.name,
          severity: dp.severity,
          description: dp.desc,
          line: index + 1,
          match: line.trim().substring(0, 80),
          recommendation: 'Review and fix this security issue before deploying.',
        });
      }
    });
  });

  return results;
}

// Analyze repository access patterns for suspicious activity
export function analyzeAccessPatterns(events) {
  const findings = [];

  // Detect bulk cloning
  const cloneEvents = events.filter((e) => e.type === 'clone');
  if (cloneEvents.length > 5) {
    findings.push({
      type: 'access_pattern',
      name: 'Bulk Clone Detected',
      severity: 'high',
      description: `${cloneEvents.length} repository clones detected in a short period — possible code theft`,
      recommendation: 'Verify all clone operations are from authorized team members.',
    });
  }

  // Detect off-hours access
  const offHoursEvents = events.filter((e) => {
    const hour = new Date(e.timestamp).getHours();
    return hour < 6 || hour > 22;
  });
  if (offHoursEvents.length > 3) {
    findings.push({
      type: 'access_pattern',
      name: 'Off-Hours Access',
      severity: 'medium',
      description: `${offHoursEvents.length} repository accesses during off-hours (10PM-6AM)`,
      recommendation: 'Confirm these accesses with team members. Consider enforcing access time restrictions.',
    });
  }

  // Detect unusual geographic access
  const uniqueLocations = [...new Set(events.map((e) => e.location).filter(Boolean))];
  if (uniqueLocations.length > 3) {
    findings.push({
      type: 'access_pattern',
      name: 'Multi-Location Access',
      severity: 'high',
      description: `Repository accessed from ${uniqueLocations.length} different locations: ${uniqueLocations.join(', ')}`,
      recommendation: 'Verify geographic access patterns. Enable geo-based access restrictions.',
    });
  }

  // Detect permission changes
  const permChanges = events.filter((e) => e.type === 'permission_change');
  if (permChanges.length > 0) {
    findings.push({
      type: 'access_pattern',
      name: 'Permission Changes Detected',
      severity: 'high',
      description: `${permChanges.length} permission changes detected — potential privilege escalation`,
      recommendation: 'Audit all permission changes. Revert unauthorized changes immediately.',
    });
  }

  return findings;
}

// Generate simulated repo events for demo
export function generateRepoEvents() {
  return [
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3600000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3500000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3400000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3300000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3200000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'clone', user: 'unknown-user-42', timestamp: new Date(Date.now() - 3100000), location: 'Moscow, Russia', ip: '185.220.101.42' },
    { type: 'push', user: 'dev-team-lead', timestamp: new Date(Date.now() - 7200000), location: 'San Francisco, USA', ip: '104.28.12.96' },
    { type: 'push', user: 'junior-dev-03', timestamp: new Date(Date.now() - 1800000), location: 'Bangalore, India', ip: '49.37.200.15' },
    { type: 'permission_change', user: 'admin-account', timestamp: new Date(Date.now() - 900000), location: 'Lagos, Nigeria', ip: '41.190.3.22' },
    { type: 'clone', user: 'contractor-ext', timestamp: new Date(Date.now() - 500000), location: 'Beijing, China', ip: '111.13.101.208' },
    { type: 'push', user: 'dev-ops-bot', timestamp: new Date(Date.now() - 120000), location: 'AWS us-east-1', ip: '54.234.0.0' },
  ];
}

function maskSecret(secret) {
  if (secret.length <= 8) return '***';
  return secret.substring(0, 4) + '*'.repeat(Math.min(secret.length - 8, 20)) + secret.substring(secret.length - 4);
}

function getSecretRemediation(secretType) {
  const remediations = {
    'AWS Access Key': 'Rotate AWS credentials immediately. Use IAM roles and environment variables instead.',
    'GitHub Token': 'Revoke the token in GitHub settings and generate a new one. Never commit tokens to repos.',
    'Private Key': 'Remove from repository history using git filter-branch. Store in a secrets manager.',
    'Database URL': 'Move connection strings to environment variables. Use a secrets manager like AWS Secrets Manager or HashiCorp Vault.',
    'Stripe Key': 'Roll the Stripe key immediately in the Stripe Dashboard. Use environment variables.',
    default: 'Remove the secret from code and repository history. Use environment variables or a secrets manager.',
  };
  return remediations[secretType] || remediations.default;
}
