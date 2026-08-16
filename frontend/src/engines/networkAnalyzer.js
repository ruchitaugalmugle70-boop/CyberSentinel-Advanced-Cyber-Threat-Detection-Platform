// Network Anomaly Detection Engine

// Analyze network traffic data for anomalies
export function analyzeNetworkTraffic(trafficData) {
  const findings = [];

  // Check for C2 beaconing (periodic connections)
  const connectionIntervals = [];
  for (let i = 1; i < trafficData.connections.length; i++) {
    const interval = trafficData.connections[i].timestamp - trafficData.connections[i - 1].timestamp;
    connectionIntervals.push(interval);
  }

  const avgInterval = connectionIntervals.reduce((a, b) => a + b, 0) / connectionIntervals.length;
  const variance = connectionIntervals.reduce((sum, interval) => sum + Math.pow(interval - avgInterval, 2), 0) / connectionIntervals.length;
  const stdDev = Math.sqrt(variance);

  if (stdDev < avgInterval * 0.1 && connectionIntervals.length > 5) {
    findings.push({
      type: 'beaconing',
      name: 'C2 Beaconing Detected',
      severity: 'critical',
      description: `Regular periodic connections detected every ~${Math.round(avgInterval / 1000)}s with very low variance — classic C2 beacon pattern`,
      recommendation: 'Block the destination IP immediately. Investigate the source device for compromise.',
    });
  }

  // Check for data exfiltration (large outbound transfers)
  const largeUploads = trafficData.connections.filter((c) => c.bytesOut > 1000000);
  if (largeUploads.length > 0) {
    const totalExfil = largeUploads.reduce((sum, c) => sum + c.bytesOut, 0);
    findings.push({
      type: 'exfiltration',
      name: 'Data Exfiltration Suspected',
      severity: totalExfil > 10000000 ? 'critical' : 'high',
      description: `${largeUploads.length} large outbound transfers detected totaling ${formatBytes(totalExfil)}`,
      recommendation: 'Review what data was transmitted. Check if transfers were authorized.',
    });
  }

  // Check for DNS tunneling
  const dnsQueries = trafficData.connections.filter((c) => c.port === 53);
  const longDNS = dnsQueries.filter((c) => c.query && c.query.length > 50);
  if (longDNS.length > 3) {
    findings.push({
      type: 'dns_tunnel',
      name: 'DNS Tunneling Suspected',
      severity: 'critical',
      description: `${longDNS.length} unusually long DNS queries detected — possible DNS tunneling for data exfiltration`,
      recommendation: 'Monitor DNS traffic. Implement DNS query length limits. Block suspicious DNS resolvers.',
    });
  }

  // Check for port scanning
  const uniquePorts = new Set(trafficData.connections.map((c) => c.port));
  if (uniquePorts.size > 20) {
    findings.push({
      type: 'port_scan',
      name: 'Port Scan Detected',
      severity: 'high',
      description: `Connections to ${uniquePorts.size} different ports detected — possible port scanning activity`,
      recommendation: 'Block the scanning IP. Review firewall rules. Enable port scan detection.',
    });
  }

  // Check for connections to suspicious ports
  const suspiciousPorts = [4444, 5555, 1337, 31337, 6667, 6666, 8888, 9999, 12345, 54321];
  const suspConn = trafficData.connections.filter((c) => suspiciousPorts.includes(c.port));
  if (suspConn.length > 0) {
    findings.push({
      type: 'suspicious_port',
      name: 'Suspicious Port Activity',
      severity: 'high',
      description: `Connections on known malicious ports: ${[...new Set(suspConn.map((c) => c.port))].join(', ')}`,
      recommendation: 'Block these ports. Investigate which processes are making these connections.',
    });
  }

  return findings;
}

// Check IP addresses against threat intelligence
export function checkIPReputation(ip) {
  // Simulated bad IP ranges (in a real system, this would query threat intel APIs)
  const badRanges = [
    { prefix: '185.220.', desc: 'Tor exit node / known attack source', severity: 'high' },
    { prefix: '45.33.', desc: 'Hosting provider frequently used for C2', severity: 'medium' },
    { prefix: '91.134.', desc: 'Known malware distribution network', severity: 'high' },
    { prefix: '103.24.', desc: 'Botnet command infrastructure', severity: 'critical' },
    { prefix: '5.188.', desc: 'Brute force attack origin', severity: 'high' },
    { prefix: '141.98.', desc: 'Scanning / exploitation network', severity: 'medium' },
  ];

  const match = badRanges.find((range) => ip.startsWith(range.prefix));
  if (match) {
    return {
      ip,
      status: 'malicious',
      severity: match.severity,
      description: match.desc,
      recommendation: `Block IP ${ip} at firewall level. Add to blocklist.`,
    };
  }

  // Check for private IPs
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.')) {
    return {
      ip,
      status: 'internal',
      severity: 'info',
      description: 'Internal/private IP address',
    };
  }

  return {
    ip,
    status: 'clean',
    severity: 'info',
    description: 'No threats found for this IP address',
  };
}

// Generate simulated network traffic for demo
export function generateNetworkTraffic() {
  const now = Date.now();
  return {
    connections: [
      { timestamp: now - 60000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 1024, bytesOut: 5242880, protocol: 'HTTPS', query: null },
      { timestamp: now - 55000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 50000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 45000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 40000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 35000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 30000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 25000, srcIp: '192.168.1.45', dstIp: '185.220.101.42', port: 443, bytesIn: 512, bytesOut: 256, protocol: 'HTTPS', query: null },
      { timestamp: now - 20000, srcIp: '10.0.0.15', dstIp: '103.24.77.12', port: 53, bytesIn: 64, bytesOut: 2048, protocol: 'DNS', query: 'aW1wb3J0YW50LXNlY3JldC1kYXRhLWV4ZmlsdHJhdGlvbi5leGFtcGxl.evil-dns.com' },
      { timestamp: now - 15000, srcIp: '10.0.0.15', dstIp: '103.24.77.12', port: 53, bytesIn: 64, bytesOut: 2048, protocol: 'DNS', query: 'c2Vuc2l0aXZlLWRhdGEtcGF5bG9hZC1jaHVuay0yLmV2aWwtZG5z.evil-dns.com' },
      { timestamp: now - 10000, srcIp: '10.0.0.15', dstIp: '103.24.77.12', port: 53, bytesIn: 64, bytesOut: 2048, protocol: 'DNS', query: 'ZXhmaWx0cmF0ZS11c2VyLWNyZWRlbnRpYWxzLWNoYW5rLTMuZXZpbA.evil-dns.com' },
      { timestamp: now - 5000, srcIp: '10.0.0.15', dstIp: '103.24.77.12', port: 53, bytesIn: 64, bytesOut: 2048, protocol: 'DNS', query: 'ZmluYWwtcGF5bG9hZC1jaHVuay00LWNvbXBsZXRlLmV2aWwtZG5z.evil-dns.com' },
      { timestamp: now - 70000, srcIp: '192.168.1.12', dstIp: '91.134.200.5', port: 4444, bytesIn: 8192, bytesOut: 1024, protocol: 'TCP', query: null },
      { timestamp: now - 80000, srcIp: '192.168.1.12', dstIp: '91.134.200.5', port: 5555, bytesIn: 4096, bytesOut: 512, protocol: 'TCP', query: null },
      { timestamp: now - 90000, srcIp: '192.168.1.12', dstIp: '91.134.200.5', port: 1337, bytesIn: 2048, bytesOut: 256, protocol: 'TCP', query: null },
    ],
  };
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
