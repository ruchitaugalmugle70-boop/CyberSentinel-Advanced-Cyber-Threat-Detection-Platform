/**
 * YARA Rule Sandbox & Entropy Calculator Client Engine for CyberSentinel.
 */

export const DEFAULT_CLIENT_YARA_RULES = [
  {
    name: "Pegasus_C2_Domain_Injector",
    pattern: /(?:https?:\/\/)?(?:[a-z0-9-]+\.)*(?:pegasus-c2|apple-cloud-check|nsogroup-telemetry|icloud-verify)\.[a-z]{2,}/gi,
    severity: "CRITICAL",
    desc: "Obfuscated Pegasus C2 communication domain pattern."
  },
  {
    name: "SQLi_Boolean_Bypass_Probe",
    pattern: /(?:'|")?\s*(?:or|and)\s+(?:'|")?[\w\d]+(?:'|")?\s*=\s*(?:'|")?[\w\d]+(?:'|")?/gi,
    severity: "HIGH",
    desc: "Classic OR 1=1 boolean bypass probe."
  },
  {
    name: "AWS_Secret_Access_Key_Leak",
    pattern: /aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    severity: "CRITICAL",
    desc: "Hardcoded AWS Secret Access Key pattern."
  }
];

export function computeShannonEntropy(str = "") {
  if (!str) return 0;
  const freq = {};
  for (let char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (let count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

export function evaluateYaraPayload(payload = "") {
  const entropy = computeShannonEntropy(payload);
  const matches = [];

  DEFAULT_CLIENT_YARA_RULES.forEach(rule => {
    const found = payload.match(rule.pattern);
    if (found) {
      matches.push({
        ruleName: rule.name,
        severity: rule.severity,
        desc: rule.desc,
        count: found.length,
        snippets: found.slice(0, 3)
      });
    }
  });

  const threatScore = Math.min(100, matches.length * 30 + (entropy > 5.8 ? 25 : 0));

  return {
    payloadLength: payload.length,
    entropy,
    isObfuscated: entropy > 5.8,
    matchedCount: matches.length,
    matches,
    threatScore
  };
}
