// SQL Injection Detection Engine
import { SQL_INJECTION_PATTERNS } from '../utils/threatData';

// Scan input text for SQL injection patterns
export function scanForSQLInjection(input) {
  const results = [];
  const text = input;
  const lowerText = input.toLowerCase();

  // Check against known patterns
  SQL_INJECTION_PATTERNS.forEach((pattern) => {
    if (lowerText.includes(pattern.pattern.toLowerCase())) {
      results.push({
        type: 'pattern_match',
        pattern: pattern.pattern,
        name: pattern.name,
        severity: pattern.severity,
        description: pattern.desc,
        position: lowerText.indexOf(pattern.pattern.toLowerCase()),
        recommendation: getRemediation(pattern.name),
      });
    }
  });

  // Additional regex-based detection
  const advancedPatterns = [
    { regex: /['"];\s*(?:DROP|DELETE|TRUNCATE|ALTER)\s/i, name: 'Destructive Query', severity: 'critical', desc: 'Attempted database destruction' },
    { regex: /UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL|[\d])/i, name: 'UNION NULL Probe', severity: 'critical', desc: 'Column count enumeration via UNION SELECT NULL' },
    { regex: /(?:OR|AND)\s+\d+\s*=\s*\d+/i, name: 'Numeric Tautology', severity: 'high', desc: 'Boolean-based injection using numeric comparison' },
    { regex: /(?:SLEEP|BENCHMARK|WAITFOR|DELAY)\s*\(/i, name: 'Time-Based Attack', severity: 'high', desc: 'Time delay function used for blind injection' },
    { regex: /(?:INFORMATION_SCHEMA|sys\.tables|sysobjects)/i, name: 'Schema Enumeration', severity: 'critical', desc: 'Attempting to enumerate database structure' },
    { regex: /(?:LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)/i, name: 'File System Access', severity: 'critical', desc: 'Attempting to read/write files through SQL' },
    { regex: /(?:xp_cmdshell|sp_executesql|EXEC\s*\()/i, name: 'Stored Procedure Abuse', severity: 'critical', desc: 'Attempting to execute stored procedures' },
    { regex: /(?:CONCAT|GROUP_CONCAT|STRING_AGG)\s*\(.*(?:0x|CHAR\s*\()/i, name: 'String Concatenation Attack', severity: 'medium', desc: 'Using string functions to build malicious queries' },
    { regex: /(?:\/\*.*\*\/){2,}/i, name: 'Comment Obfuscation', severity: 'medium', desc: 'Multiple SQL comments used to evade detection' },
    { regex: /(?:%27|%22|%3B|%2D%2D)/i, name: 'URL Encoded Injection', severity: 'high', desc: 'URL-encoded SQL injection characters detected' },
    { regex: /(?:0x[0-9a-f]{6,})/i, name: 'Hex Encoded Payload', severity: 'medium', desc: 'Hexadecimal encoded payload to bypass WAF' },
    { regex: /(?:CASE\s+WHEN\s+.*THEN\s+.*(?:ELSE|END))/i, name: 'Conditional Injection', severity: 'high', desc: 'CASE/WHEN conditional logic for data extraction' },
  ];

  advancedPatterns.forEach((ap) => {
    const match = text.match(ap.regex);
    if (match) {
      // Avoid duplicates
      if (!results.some(r => r.name === ap.name)) {
        results.push({
          type: 'regex_match',
          pattern: match[0],
          name: ap.name,
          severity: ap.severity,
          description: ap.desc,
          position: match.index,
          recommendation: getRemediation(ap.name),
        });
      }
    }
  });

  // Check for common SQL keywords in suspicious context
  const suspiciousKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE', 'EXEC'];
  const hasSQLKeywords = suspiciousKeywords.some(kw => lowerText.includes(kw.toLowerCase()));
  const hasQuotes = text.includes("'") || text.includes('"');
  const hasSemicolon = text.includes(';');
  const hasComment = text.includes('--') || text.includes('/*');

  if (hasSQLKeywords && (hasQuotes || hasSemicolon || hasComment) && results.length === 0) {
    results.push({
      type: 'heuristic',
      pattern: 'SQL keywords + special characters',
      name: 'Suspicious SQL Pattern',
      severity: 'medium',
      description: 'Input contains SQL keywords combined with special characters — potential injection attempt',
      recommendation: 'Validate and sanitize all user inputs. Use parameterized queries.',
    });
  }

  return results;
}

// Scan a URL for SQL injection indicators
export function scanURL(url) {
  const results = [];
  try {
    const parsed = new URL(url);
    const params = parsed.searchParams;

    params.forEach((value, key) => {
      const paramResults = scanForSQLInjection(value);
      paramResults.forEach((r) => {
        results.push({
          ...r,
          location: `URL parameter: ${key}`,
        });
      });

      // Check for numeric parameter manipulation
      if (/^\d+$/.test(value)) {
        results.push({
          type: 'info',
          pattern: `${key}=${value}`,
          name: 'Numeric Parameter',
          severity: 'low',
          description: `Parameter "${key}" accepts numeric input — test with: ${key}=${value} OR 1=1`,
          location: `URL parameter: ${key}`,
          recommendation: 'Ensure parameter type is validated server-side.',
        });
      }
    });
  } catch {
    results.push({
      type: 'error',
      name: 'Invalid URL',
      severity: 'info',
      description: 'The provided URL could not be parsed. Please enter a valid URL.',
    });
  }
  return results;
}

function getRemediation(attackType) {
  const remediations = {
    'Boolean Bypass': 'Use parameterized queries (prepared statements) instead of string concatenation.',
    'String Boolean Bypass': 'Implement input validation and use parameterized queries.',
    'Drop Table Attack': 'Use database accounts with minimum required privileges. Never allow DROP permissions from web app accounts.',
    'Union-Based Extraction': 'Use parameterized queries and implement column-level access control.',
    'Time-Based Blind': 'Set query timeouts and use parameterized queries.',
    'Error-Based': 'Disable verbose error messages in production. Use custom error pages.',
    'OS Command Injection': 'Disable xp_cmdshell. Use least-privilege database accounts.',
    'Data Modification': 'Use read-only database connections where writes are not needed.',
    'Substring Extraction': 'Implement query parameterization and rate limiting.',
    'Comment Bypass': 'Use parameterized queries — comments in input become harmless.',
    default: 'Use parameterized queries, input validation, and a Web Application Firewall (WAF).',
  };
  return remediations[attackType] || remediations.default;
}
