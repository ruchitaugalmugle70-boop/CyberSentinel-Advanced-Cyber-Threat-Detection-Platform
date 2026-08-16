// Spyware & IOC Detection Engine
import { KNOWN_IOCS } from '../utils/threatData';

export function scanForIOCs(input) {
  const results = [];
  const text = input.toLowerCase();

  // Scan for known malicious domains
  KNOWN_IOCS.domains.forEach((ioc) => {
    if (text.includes(ioc.pattern.toLowerCase())) {
      results.push({
        type: 'domain',
        match: ioc.pattern,
        category: ioc.type,
        severity: ioc.severity,
        description: `Known ${ioc.type} domain detected: ${ioc.pattern}`,
        recommendation: 'Immediately isolate the device and perform a full forensic analysis.',
      });
    }
  });

  // Scan for known malicious process names
  KNOWN_IOCS.processes.forEach((proc) => {
    if (text.includes(proc.name.toLowerCase())) {
      results.push({
        type: 'process',
        match: proc.name,
        category: proc.desc,
        severity: proc.severity,
        description: `Malicious process "${proc.name}" detected — ${proc.desc}`,
        recommendation: 'This process is associated with advanced spyware. Terminate immediately and preserve logs for forensic investigation.',
      });
    }
  });

  // Scan for known file hashes
  KNOWN_IOCS.fileHashes.forEach((hash) => {
    if (text.includes(hash.toLowerCase())) {
      results.push({
        type: 'hash',
        match: hash.substring(0, 16) + '...',
        category: 'Known Malware Hash',
        severity: 'critical',
        description: `File hash matches known spyware binary: ${hash.substring(0, 32)}...`,
        recommendation: 'The matched file is confirmed malware. Quarantine immediately.',
      });
    }
  });

  // Heuristic checks
  const heuristicPatterns = [
    { regex: /\/var\/containers\/Bundle\/Application\/[a-f0-9-]+\/(?!com\.apple)/i, name: 'Suspicious App Bundle Path', severity: 'medium', desc: 'Unusual application bundle path detected — may indicate sideloaded malware' },
    { regex: /shutdown\.log.*(?:libtouchregd|bh|roleaborede)/i, name: 'Pegasus in Shutdown Log', severity: 'critical', desc: 'Pegasus indicator found in iOS shutdown log — device likely compromised' },
    { regex: /datausage\.sqlite.*(?:unknown|untitled).*network/i, name: 'Hidden Network Process', severity: 'high', desc: 'Unknown process with network activity detected in usage database' },
    { regex: /(?:microphone|camera).*(?:background|inactive|locked)/i, name: 'Background Sensor Access', severity: 'critical', desc: 'Camera or microphone accessed while device is locked — surveillance indicator' },
    { regex: /root.*certificate.*install/i, name: 'Root Certificate Installation', severity: 'high', desc: 'Root certificate installed — potential man-in-the-middle attack setup' },
    { regex: /(?:jailbreak|cydia|substrate|sileo)/i, name: 'Jailbreak Detected', severity: 'high', desc: 'Jailbreak indicators found — device security compromised' },
  ];

  heuristicPatterns.forEach((hp) => {
    if (hp.regex.test(text)) {
      results.push({
        type: 'heuristic',
        match: hp.name,
        category: 'Behavioral Analysis',
        severity: hp.severity,
        description: hp.desc,
        recommendation: 'Investigate further. This pattern may indicate active surveillance.',
      });
    }
  });

  return results;
}

// Analyze device behavior metrics for anomalies
export function analyzeDeviceBehavior(metrics) {
  const findings = [];

  if (metrics.batteryDrain > 30) {
    findings.push({
      type: 'behavior',
      match: 'High Battery Drain',
      severity: metrics.batteryDrain > 50 ? 'critical' : 'high',
      description: `Battery drain rate of ${metrics.batteryDrain}%/day is ${metrics.batteryDrain > 50 ? 'critically' : 'abnormally'} high — possible background spyware activity`,
      recommendation: 'Check background processes and recently installed apps.',
    });
  }

  if (metrics.dataUsage > 500) {
    findings.push({
      type: 'behavior',
      match: 'Excessive Data Usage',
      severity: metrics.dataUsage > 1000 ? 'critical' : 'high',
      description: `Data usage of ${metrics.dataUsage}MB/day is abnormal — possible data exfiltration`,
      recommendation: 'Review network connections and data transfer logs.',
    });
  }

  if (metrics.cpuSpikes > 5) {
    findings.push({
      type: 'behavior',
      match: 'CPU Spike Anomaly',
      severity: 'medium',
      description: `${metrics.cpuSpikes} unexplained CPU spikes detected — may indicate encryption operations by spyware`,
      recommendation: 'Monitor which processes consume CPU during spikes.',
    });
  }

  if (metrics.unexpectedReboots > 2) {
    findings.push({
      type: 'behavior',
      match: 'Unexpected Reboots',
      severity: 'high',
      description: `${metrics.unexpectedReboots} unexpected device reboots — possible exploit-triggered crashes`,
      recommendation: 'Preserve crash logs and analyze for exploit signatures.',
    });
  }

  return findings;
}
