/**
 * Incident Response Playbook Client Engine for CyberSentinel.
 */

export function buildContainmentPlaybook(category = "spyware", params = {}) {
  const targetIp = params.targetIp || "192.168.1.105";
  const processName = params.processName || "netd_agent";
  const c2Domain = params.c2Domain || "pegasus-telemetry.org";
  const secretId = params.secretId || "AKIAIOSFODNN7EXAMPLE";

  if (category.toLowerCase().includes("spyware")) {
    return {
      title: "Pegasus / Surveillance Isolation Playbook",
      steps: [
        { step: 1, action: "Network Isolation", command: `sudo iptables -A OUTPUT -d ${targetIp} -j DROP`, purpose: "Terminate active C2 socket connections immediately." },
        { step: 2, action: "Process Termination", command: `sudo pkill -9 -f ${processName}`, purpose: "Kill suspect spyware child processes." },
        { step: 3, action: "Forensic Dump", command: "sudo sysdiagnose -f /var/log/cybersentinel_evidence/", purpose: "Capture full system state for MVT verification." }
      ]
    };
  }

  if (category.toLowerCase().includes("sqli")) {
    return {
      title: "SQL Injection & WAF Defense Playbook",
      steps: [
        { step: 1, action: "WAF Rule Deployment", command: `aws wafv2 update-ip-set --name BlockedSQLiIPs --addresses ${targetIp}/32`, purpose: "Block malicious IP at AWS WAF layer." },
        { step: 2, action: "Kill DB Sessions", command: `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE client_addr = '${targetIp}';`, purpose: "Kill active database queries." }
      ]
    };
  }

  if (category.toLowerCase().includes("repo")) {
    return {
      title: "Leaked Credential Revocation Playbook",
      steps: [
        { step: 1, action: "Deactivate AWS Token", command: `aws iam update-access-key --access-key-id ${secretId} --status Inactive`, purpose: "Deactivate compromised IAM credentials." },
        { step: 2, action: "Purge Git History", command: "git filter-repo --invert-paths --path .env", purpose: "Purge secret file from all commits." }
      ]
    };
  }

  return {
    title: "C2 Network Beaconing Containment Playbook",
    steps: [
      { step: 1, action: "DNS Sinkhole", command: `echo '127.0.0.1 ${c2Domain}' | sudo tee -a /etc/hosts`, purpose: "Reroute outbound C2 DNS requests to loopback." },
      { step: 2, action: "BGP Null Route", command: `sudo ip route add blackhole ${targetIp}`, purpose: "Drop all outbound traffic to C2 IP." }
    ]
  };
}
