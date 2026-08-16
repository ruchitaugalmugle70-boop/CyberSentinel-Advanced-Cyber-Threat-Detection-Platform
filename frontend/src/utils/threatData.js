// Simulated threat intelligence data for CyberSentinel

export const KNOWN_IOCS = {
  domains: [
    { pattern: 'arfrfrfrfrfr.com', type: 'Pegasus C2', severity: 'critical' },
    { pattern: 'bafrfrfrfrfr.com', type: 'Pegasus C2', severity: 'critical' },
    { pattern: 'drfrfrfrfrfr.com', type: 'Pegasus C2', severity: 'critical' },
    { pattern: 'free247downloads.com', type: 'Pegasus Exploit Delivery', severity: 'critical' },
    { pattern: 'urlpush.net', type: 'Pegasus Exploit Delivery', severity: 'critical' },
    { pattern: 'maborightede.com', type: 'Pegasus Infrastructure', severity: 'high' },
    { pattern: 'opposedarede.com', type: 'Pegasus Infrastructure', severity: 'high' },
    { pattern: 'pclogin-service.net', type: 'Predator Spyware', severity: 'critical' },
    { pattern: 'taaborightede.net', type: 'Pegasus Infrastructure', severity: 'high' },
    { pattern: 'revolution-ede.com', type: 'Pegasus C2', severity: 'critical' },
  ],
  processes: [
    { name: 'libtouchregd', desc: 'Pegasus fake touch daemon', severity: 'critical' },
    { name: 'roleaborede', desc: 'Pegasus disguised process', severity: 'critical' },
    { name: 'ABSCarrier', desc: 'Pegasus carrier module', severity: 'critical' },
    { name: 'brstaged', desc: 'Pegasus bridge stage', severity: 'high' },
    { name: 'caborightede', desc: 'Pegasus cab module', severity: 'high' },
    { name: 'RollingStorage', desc: 'Pegasus data collection', severity: 'critical' },
    { name: 'natgd', desc: 'Predator spyware NAT daemon', severity: 'critical' },
    { name: 'paborightede', desc: 'Pegasus pab module', severity: 'high' },
    { name: 'cfaborightede', desc: 'Pegasus CF module', severity: 'high' },
    { name: 'msgacntd', desc: 'Disguised message account daemon', severity: 'high' },
  ],
  fileHashes: [
    'e1a83e87a4b6e5f2c8d9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0',
    'a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    'f3e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3',
  ],
};

export const SQL_INJECTION_PATTERNS = [
  { pattern: "' OR 1=1", name: 'Boolean Bypass', severity: 'critical', desc: 'Classic authentication bypass using always-true condition' },
  { pattern: "' OR '1'='1", name: 'String Boolean Bypass', severity: 'critical', desc: 'String-based authentication bypass' },
  { pattern: "'; DROP TABLE", name: 'Drop Table Attack', severity: 'critical', desc: 'Attempts to destroy database tables' },
  { pattern: "' UNION SELECT", name: 'Union-Based Extraction', severity: 'critical', desc: 'Extracts data from other tables using UNION' },
  { pattern: "'; WAITFOR DELAY", name: 'Time-Based Blind', severity: 'high', desc: 'Time delay injection to confirm vulnerability' },
  { pattern: "' AND 1=CONVERT", name: 'Error-Based', severity: 'high', desc: 'Forces database error to reveal information' },
  { pattern: "'; EXEC xp_cmdshell", name: 'OS Command Injection', severity: 'critical', desc: 'Attempts to execute operating system commands' },
  { pattern: "1; UPDATE users SET", name: 'Data Modification', severity: 'critical', desc: 'Modifies database records directly' },
  { pattern: "' AND SUBSTRING(", name: 'Substring Extraction', severity: 'high', desc: 'Character-by-character data extraction' },
  { pattern: "admin'--", name: 'Comment Bypass', severity: 'high', desc: 'Bypasses password check using SQL comment' },
  { pattern: "' OR EXISTS(SELECT", name: 'Subquery Injection', severity: 'high', desc: 'Uses subqueries to probe database structure' },
  { pattern: "'; INSERT INTO", name: 'Data Injection', severity: 'critical', desc: 'Inserts unauthorized records into database' },
  { pattern: "\\x27", name: 'Hex Encoded Quote', severity: 'medium', desc: 'Uses hex encoding to bypass input filters' },
  { pattern: "CHAR(39)", name: 'CHAR Function Bypass', severity: 'medium', desc: 'Uses CHAR() to generate quotes and bypass filters' },
  { pattern: "/**/OR/**/", name: 'Comment Obfuscation', severity: 'medium', desc: 'Uses SQL comments to evade WAF detection' },
  { pattern: "' HAVING 1=1", name: 'HAVING Clause Injection', severity: 'medium', desc: 'Exploits GROUP BY/HAVING for error-based extraction' },
  { pattern: "'; DECLARE @", name: 'Variable Declaration', severity: 'high', desc: 'Declares variables for complex multi-stage attacks' },
  { pattern: "BENCHMARK(", name: 'MySQL Time-Based', severity: 'high', desc: 'MySQL-specific time delay for blind injection' },
  { pattern: "LOAD_FILE(", name: 'File Read Attack', severity: 'critical', desc: 'Reads server files through SQL injection' },
  { pattern: "INTO OUTFILE", name: 'File Write Attack', severity: 'critical', desc: 'Writes files to the server filesystem' },
];

export const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical', desc: 'Amazon Web Services access key exposed' },
  { name: 'AWS Secret Key', regex: /[A-Za-z0-9/+=]{40}/, severity: 'critical', desc: 'AWS secret access key found' },
  { name: 'GitHub Token', regex: /gh[ps]_[A-Za-z0-9_]{36}/, severity: 'critical', desc: 'GitHub personal access token leaked' },
  { name: 'Slack Webhook', regex: /hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[A-Za-z0-9]{24}/, severity: 'high', desc: 'Slack incoming webhook URL exposed' },
  { name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', desc: 'Private cryptographic key found in code' },
  { name: 'Generic API Key', regex: /api[_-]?key[\s]*[=:]\s*['"][A-Za-z0-9]{20,}['"]/, severity: 'high', desc: 'Generic API key pattern detected' },
  { name: 'Database URL', regex: /(postgres|mysql|mongodb):\/\/[^\s'"]+/, severity: 'critical', desc: 'Database connection string with credentials' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+/, severity: 'high', desc: 'JSON Web Token found in source code' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z-_]{35}/, severity: 'high', desc: 'Google Cloud API key exposed' },
  { name: 'Stripe Key', regex: /sk_live_[0-9a-zA-Z]{24}/, severity: 'critical', desc: 'Stripe live secret key detected' },
  { name: 'Password in Code', regex: /password[\s]*[=:]\s*['"][^'"]{8,}['"]/, severity: 'high', desc: 'Hardcoded password found in source code' },
  { name: 'Bearer Token', regex: /Bearer\s+[A-Za-z0-9\-._~+\/]+=*/, severity: 'high', desc: 'Bearer authentication token in code' },
];

export const THREAT_CATEGORIES = [
  { name: 'Spyware/IOC', icon: '🔍', color: '#ff3366' },
  { name: 'SQL Injection', icon: '💉', color: '#ffaa00' },
  { name: 'Repo Security', icon: '📦', color: '#a855f7' },
  { name: 'Network', icon: '🌐', color: '#00f0ff' },
];

export const SEVERITY_LEVELS = {
  critical: { label: 'Critical', color: '#ff3366', bg: 'rgba(255,51,102,0.15)' },
  high: { label: 'High', color: '#ffaa00', bg: 'rgba(255,170,0,0.15)' },
  medium: { label: 'Medium', color: '#a855f7', bg: 'rgba(168,85,247,0.15)' },
  low: { label: 'Low', color: '#00f0ff', bg: 'rgba(0,240,255,0.15)' },
  info: { label: 'Info', color: '#4a5568', bg: 'rgba(74,85,104,0.15)' },
};

// Generate simulated real-time alerts
export function generateAlert() {
  const alerts = [
    { message: 'Suspicious outbound connection to unknown C2 server detected', severity: 'critical', category: 'network', source: '192.168.1.45' },
    { message: 'SQL injection attempt blocked on /api/login endpoint', severity: 'high', category: 'sqli', source: '103.24.77.12' },
    { message: 'Known Pegasus IOC domain resolved in DNS query', severity: 'critical', category: 'spyware', source: 'dns-resolver' },
    { message: 'Unusual bulk clone activity detected on main repository', severity: 'high', category: 'repo', source: 'github-monitor' },
    { message: 'Port scan detected from external IP address', severity: 'medium', category: 'network', source: '45.33.128.91' },
    { message: 'Hardcoded API key found in recent commit', severity: 'high', category: 'repo', source: 'secret-scanner' },
    { message: 'Anomalous data exfiltration pattern detected (3.2GB upload)', severity: 'critical', category: 'network', source: '10.0.0.15' },
    { message: 'Process "libtouchregd" detected — matches Pegasus signature', severity: 'critical', category: 'spyware', source: 'ioc-scanner' },
    { message: 'UNION-based SQL injection payload detected in search parameter', severity: 'high', category: 'sqli', source: '185.220.101.8' },
    { message: 'Abnormal battery drain pattern detected on monitored device', severity: 'medium', category: 'spyware', source: 'behavior-monitor' },
    { message: 'Repository visibility changed from private to public', severity: 'high', category: 'repo', source: 'github-audit' },
    { message: 'DNS tunneling activity suspected on port 53', severity: 'high', category: 'network', source: 'dns-monitor' },
    { message: 'Time-based blind SQL injection attempt on /api/users', severity: 'medium', category: 'sqli', source: '91.134.200.5' },
    { message: 'Unauthorized SSH key added to organization', severity: 'critical', category: 'repo', source: 'github-audit' },
    { message: 'Zero-click exploit pattern detected in iMessage traffic', severity: 'critical', category: 'spyware', source: 'exploit-detector' },
    { message: 'Encrypted C2 beacon detected every 30 seconds', severity: 'critical', category: 'network', source: 'beacon-detector' },
    { message: 'Database connection string leaked in error log', severity: 'high', category: 'repo', source: 'log-scanner' },
    { message: 'XSS payload detected in form submission', severity: 'medium', category: 'sqli', source: 'waf-module' },
    { message: 'Device microphone activated without user interaction', severity: 'critical', category: 'spyware', source: 'permission-monitor' },
    { message: 'Brute force login attempt — 150 failed logins in 2 minutes', severity: 'high', category: 'network', source: 'auth-monitor' },
  ];
  const alert = alerts[Math.floor(Math.random() * alerts.length)];
  return {
    ...alert,
    id: Date.now() + Math.random(),
    timestamp: new Date(),
  };
}

// Attack origin coordinates for threat map
export const ATTACK_ORIGINS = [
  { lat: 55.75, lng: 37.62, city: 'Moscow', country: 'Russia', attacks: 2847 },
  { lat: 39.90, lng: 116.40, city: 'Beijing', country: 'China', attacks: 3421 },
  { lat: 28.61, lng: 77.21, city: 'New Delhi', country: 'India', attacks: 1534 },
  { lat: 37.57, lng: 126.98, city: 'Seoul', country: 'South Korea', attacks: 892 },
  { lat: 35.68, lng: 139.69, city: 'Tokyo', country: 'Japan', attacks: 567 },
  { lat: 51.51, lng: -0.13, city: 'London', country: 'UK', attacks: 1203 },
  { lat: 48.86, lng: 2.35, city: 'Paris', country: 'France', attacks: 734 },
  { lat: -23.55, lng: -46.63, city: 'São Paulo', country: 'Brazil', attacks: 1876 },
  { lat: 40.71, lng: -74.01, city: 'New York', country: 'USA', attacks: 945 },
  { lat: 1.35, lng: 103.82, city: 'Singapore', country: 'Singapore', attacks: 432 },
  { lat: 25.28, lng: 55.30, city: 'Dubai', country: 'UAE', attacks: 678 },
  { lat: 52.52, lng: 13.40, city: 'Berlin', country: 'Germany', attacks: 543 },
  { lat: 33.87, lng: 35.51, city: 'Beirut', country: 'Lebanon', attacks: 321 },
  { lat: -33.87, lng: 151.21, city: 'Sydney', country: 'Australia', attacks: 289 },
  { lat: 6.52, lng: 3.38, city: 'Lagos', country: 'Nigeria', attacks: 1123 },
];

// Simulated dashboard stats
export function getDashboardStats() {
  return {
    threatsDetected: { value: 1247, trend: '+12%', direction: 'up' },
    activeScans: { value: 8, trend: '3 pending', direction: 'neutral' },
    securityScore: { value: 73, trend: '+5pts', direction: 'down' },
    vulnerabilities: { value: 23, trend: '-8%', direction: 'down' },
  };
}

// Threat trend data for charts
export function getThreatTrendData() {
  const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  return {
    labels,
    datasets: [
      { label: 'Spyware', data: [12, 19, 8, 25, 14, 7, 16], color: '#ff3366' },
      { label: 'SQL Injection', data: [8, 14, 22, 11, 18, 9, 13], color: '#ffaa00' },
      { label: 'Repo Threats', data: [5, 7, 3, 9, 6, 4, 8], color: '#a855f7' },
      { label: 'Network', data: [15, 23, 17, 31, 22, 12, 19], color: '#00f0ff' },
    ],
  };
}

export function getAttackTypeDistribution() {
  return [
    { label: 'Zero-Click Exploit', value: 18, color: '#ff3366' },
    { label: 'SQL Injection', value: 28, color: '#ffaa00' },
    { label: 'Code Theft', value: 12, color: '#a855f7' },
    { label: 'Network Intrusion', value: 25, color: '#00f0ff' },
    { label: 'Phishing', value: 10, color: '#00ff88' },
    { label: 'Brute Force', value: 7, color: '#3b82f6' },
  ];
}
