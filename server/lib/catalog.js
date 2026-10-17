'use strict';

/**
 * Static reference data shared by the seeder and the live alert engine:
 * MITRE ATT&CK technique mappings, detection rules, asset inventory and
 * threat-actor profiles. Keeping it in one place means a generated alert
 * always maps to a rule that actually exists in the catalog.
 */

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

/** Detection rules — each maps to a real ATT&CK technique id. */
const RULES = [
  {
    id: 'VGIL-1001',
    name: 'Impossible Travel — Concurrent Geo Sessions',
    technique: 'T1078',
    techniqueName: 'Valid Accounts',
    tactic: 'Initial Access',
    severity: 'high',
    source: 'Identity Provider',
    description:
      'A single identity authenticated from two geographies faster than physical travel allows.',
    response: 'Force re-authentication, revoke active sessions, verify with the account owner.'
  },
  {
    id: 'VGIL-1002',
    name: 'Credential Stuffing Burst',
    technique: 'T1110.004',
    techniqueName: 'Credential Stuffing',
    tactic: 'Credential Access',
    severity: 'high',
    source: 'WAF',
    description:
      'High-volume authentication failures across many accounts from a small set of source IPs.',
    response: 'Block source ranges at the edge, enable step-up MFA, check for successful logins.'
  },
  {
    id: 'VGIL-1003',
    name: 'Ransomware Canary File Modified',
    technique: 'T1486',
    techniqueName: 'Data Encrypted for Impact',
    tactic: 'Impact',
    severity: 'critical',
    source: 'EDR',
    description:
      'Decoy canary files were renamed or encrypted — a strong pre-encryption ransomware signal.',
    response: 'Isolate host immediately, snapshot volumes, hunt for the parent process tree.'
  },
  {
    id: 'VGIL-1004',
    name: 'Suspicious PowerShell — Encoded Command',
    technique: 'T1059.001',
    techniqueName: 'PowerShell',
    tactic: 'Execution',
    severity: 'high',
    source: 'EDR',
    description:
      'PowerShell launched with -EncodedCommand and hidden window from a non-admin parent.',
    response: 'Decode the payload, quarantine the binary, check outbound connections from the host.'
  },
  {
    id: 'VGIL-1005',
    name: 'Beaconing to Rare External Destination',
    technique: 'T1071.001',
    techniqueName: 'Web Protocols',
    tactic: 'Command and Control',
    severity: 'critical',
    source: 'Network Sensor',
    description:
      'Low-jitter periodic callbacks to a domain seen nowhere else in the estate.',
    response: 'Sinkhole the domain, capture full PCAP, image the beaconing host.'
  },
  {
    id: 'VGIL-1006',
    name: 'Cloud IAM Privilege Escalation',
    technique: 'T1098',
    techniqueName: 'Account Manipulation',
    tactic: 'Privilege Escalation',
    severity: 'critical',
    source: 'Cloud Audit Log',
    description:
      'A non-admin principal attached an administrator policy to itself.',
    response: 'Detach the policy, rotate the access key, review CloudTrail for the full session.'
  },
  {
    id: 'VGIL-1007',
    name: 'Mass Data Egress to Personal Storage',
    technique: 'T1567.002',
    techniqueName: 'Exfiltration to Cloud Storage',
    tactic: 'Exfiltration',
    severity: 'high',
    source: 'DLP',
    description:
      'Volume of uploads to an unmanaged cloud storage provider exceeded baseline by 40x.',
    response: 'Block the destination, preserve the file list, engage HR and Legal if intentional.'
  },
  {
    id: 'VGIL-1008',
    name: 'Kerberoasting — Bulk SPN Ticket Requests',
    technique: 'T1558.003',
    techniqueName: 'Kerberoasting',
    tactic: 'Credential Access',
    severity: 'high',
    source: 'Domain Controller',
    description:
      'A single account requested service tickets for an unusual number of SPNs (RC4 encryption).',
    response: 'Reset affected service account passwords, enforce AES, hunt for offline cracking.'
  },
  {
    id: 'VGIL-1009',
    name: 'Public S3 Bucket Exposure',
    technique: 'T1530',
    techniqueName: 'Data from Cloud Storage',
    tactic: 'Collection',
    severity: 'medium',
    source: 'CSPM',
    description:
      'A storage bucket containing classified objects was made publicly readable.',
    response: 'Revoke the public ACL, review access logs for anonymous reads, notify the data owner.'
  },
  {
    id: 'VGIL-1010',
    name: 'Web Shell Dropped in Web Root',
    technique: 'T1505.003',
    techniqueName: 'Web Shell',
    tactic: 'Persistence',
    severity: 'critical',
    source: 'FIM',
    description:
      'A new executable script appeared in a public web directory outside the deploy pipeline.',
    response: 'Take the node out of the load balancer, preserve the file, review access logs.'
  },
  {
    id: 'VGIL-1011',
    name: 'Phishing Link Clicked — Credential Harvest Page',
    technique: 'T1566.002',
    techniqueName: 'Spearphishing Link',
    tactic: 'Initial Access',
    severity: 'medium',
    source: 'Email Gateway',
    description:
      'A user followed a link to a newly registered domain impersonating the corporate SSO page.',
    response: 'Reset the user password, purge the message tenant-wide, block the domain.'
  },
  {
    id: 'VGIL-1012',
    name: 'Lateral Movement — SMB Admin Share Access',
    technique: 'T1021.002',
    techniqueName: 'SMB/Windows Admin Shares',
    tactic: 'Lateral Movement',
    severity: 'high',
    source: 'Network Sensor',
    description:
      'A workstation account authenticated to ADMIN$ on multiple servers in under a minute.',
    response: 'Isolate the source host, disable the account, hunt for the credential source.'
  },
  {
    id: 'VGIL-1013',
    name: 'Security Tooling Disabled on Endpoint',
    technique: 'T1562.001',
    techniqueName: 'Impair Defenses',
    tactic: 'Defense Evasion',
    severity: 'high',
    source: 'EDR',
    description:
      'Real-time protection was turned off by a process that is not the management agent.',
    response: 'Re-enable protection, treat the host as compromised, collect a memory image.'
  },
  {
    id: 'VGIL-1014',
    name: 'Anomalous Database Query Volume',
    technique: 'T1213',
    techniqueName: 'Data from Information Repositories',
    tactic: 'Collection',
    severity: 'medium',
    source: 'Database Audit',
    description:
      'A service account executed full-table SELECTs far outside its normal query profile.',
    response: 'Review the query text, confirm with the owning team, check for a compromised secret.'
  },
  {
    id: 'VGIL-1015',
    name: 'New Domain Admin Account Created',
    technique: 'T1136.002',
    techniqueName: 'Create Account: Domain Account',
    tactic: 'Persistence',
    severity: 'critical',
    source: 'Domain Controller',
    description:
      'A privileged account was created outside the change window and the IAM workflow.',
    response: 'Disable the account, identify the creating session, run a full AD integrity check.'
  },
  {
    id: 'VGIL-1016',
    name: 'Outdated TLS / Weak Cipher Negotiated',
    technique: 'T1040',
    techniqueName: 'Network Sniffing',
    tactic: 'Credential Access',
    severity: 'low',
    source: 'Network Sensor',
    description:
      'An internal service accepted a TLS 1.0 handshake with an export-grade cipher suite.',
    response: 'Update the TLS policy on the listener, rescan, add to the hardening backlog.'
  },
  {
    id: 'VGIL-1017',
    name: 'Container Escape Attempt Detected',
    technique: 'T1611',
    techniqueName: 'Escape to Host',
    tactic: 'Privilege Escalation',
    severity: 'critical',
    source: 'Runtime Sensor',
    description:
      'A container process attempted to mount the host filesystem via a privileged syscall.',
    response: 'Kill the pod, cordon the node, review the admission policy that allowed privilege.'
  },
  {
    id: 'VGIL-1018',
    name: 'DNS Tunnelling Pattern',
    technique: 'T1071.004',
    techniqueName: 'DNS',
    tactic: 'Command and Control',
    severity: 'high',
    source: 'DNS Resolver',
    description:
      'High-entropy subdomain queries to a single authoritative name server at a fixed cadence.',
    response: 'Block the parent domain, decode sample queries, isolate the querying host.'
  },
  {
    id: 'VGIL-1019',
    name: 'Brute Force — SSH Public Endpoint',
    technique: 'T1110.001',
    techniqueName: 'Password Guessing',
    tactic: 'Credential Access',
    severity: 'medium',
    source: 'Host Log',
    description:
      'Sustained failed SSH authentications against an internet-facing bastion host.',
    response: 'Confirm key-only auth, rate-limit the source, verify no successful login followed.'
  },
  {
    id: 'VGIL-1020',
    name: 'Scheduled Task Persistence Created',
    technique: 'T1053.005',
    techniqueName: 'Scheduled Task',
    tactic: 'Persistence',
    severity: 'medium',
    source: 'EDR',
    description:
      'A task was registered to run a binary from a user-writable temp directory at logon.',
    response: 'Remove the task, hash the binary, check the estate for the same artefact.'
  }
];

/**
 * Which asset classes each rule can plausibly fire on, and whether the source
 * address is internal. Without this a Kerberoasting alert could land on an S3
 * bucket, which no analyst would believe.
 */
const RULE_CONTEXT = {
  'VGIL-1001': { assets: ['Workstation', 'VPN Gateway', 'Bastion', 'Cloud IAM'], internal: false },
  'VGIL-1002': { assets: ['Web Server'], internal: false },
  'VGIL-1003': { assets: ['Workstation', 'Database', 'Web Server', 'Backup Appliance'], internal: true },
  'VGIL-1004': { assets: ['Workstation', 'Domain Controller', 'Database'], internal: true },
  'VGIL-1005': { assets: ['Workstation', 'Web Server', 'Container Host', 'Database'], internal: false },
  'VGIL-1006': { assets: ['Cloud IAM'], internal: false },
  'VGIL-1007': { assets: ['Workstation', 'Database', 'Cloud Storage'], internal: true },
  'VGIL-1008': { assets: ['Domain Controller'], internal: true },
  'VGIL-1009': { assets: ['Cloud Storage'], internal: true },
  'VGIL-1010': { assets: ['Web Server'], internal: false },
  'VGIL-1011': { assets: ['Email Gateway', 'Workstation'], internal: false },
  'VGIL-1012': { assets: ['Domain Controller', 'Database', 'Web Server', 'Workstation'], internal: true },
  'VGIL-1013': { assets: ['Workstation', 'Database', 'Web Server', 'Domain Controller'], internal: true },
  'VGIL-1014': { assets: ['Database'], internal: true },
  'VGIL-1015': { assets: ['Domain Controller'], internal: true },
  'VGIL-1016': { assets: ['Web Server', 'VPN Gateway', 'Email Gateway', 'Bastion'], internal: true },
  'VGIL-1017': { assets: ['Container Host'], internal: true },
  'VGIL-1018': { assets: ['Workstation', 'Container Host', 'Web Server', 'Database'], internal: false },
  'VGIL-1019': { assets: ['Bastion', 'VPN Gateway', 'Web Server', 'Container Host'], internal: false },
  'VGIL-1020': { assets: ['Workstation', 'Web Server', 'Database'], internal: true }
};

for (const rule of RULES) {
  const ctx = RULE_CONTEXT[rule.id];
  rule.assetTypes = ctx ? ctx.assets : null;
  rule.internalSource = ctx ? ctx.internal : false;
}

/** Monitored asset inventory used to anchor alerts to something concrete. */
const ASSETS = [
  { id: 'AST-001', host: 'dc-core-01', ip: '10.20.0.11', type: 'Domain Controller', os: 'Windows Server 2022', zone: 'Core', criticality: 'critical', owner: 'Platform' },
  { id: 'AST-002', host: 'dc-core-02', ip: '10.20.0.12', type: 'Domain Controller', os: 'Windows Server 2022', zone: 'Core', criticality: 'critical', owner: 'Platform' },
  { id: 'AST-003', host: 'sql-fin-prod', ip: '10.30.4.20', type: 'Database', os: 'Windows Server 2019', zone: 'Finance', criticality: 'critical', owner: 'Finance IT' },
  { id: 'AST-004', host: 'web-edge-01', ip: '10.40.1.5', type: 'Web Server', os: 'Ubuntu 22.04', zone: 'DMZ', criticality: 'high', owner: 'Web Platform' },
  { id: 'AST-005', host: 'web-edge-02', ip: '10.40.1.6', type: 'Web Server', os: 'Ubuntu 22.04', zone: 'DMZ', criticality: 'high', owner: 'Web Platform' },
  { id: 'AST-006', host: 'k8s-node-07', ip: '10.50.2.37', type: 'Container Host', os: 'Flatcar 3815', zone: 'Platform', criticality: 'high', owner: 'SRE' },
  { id: 'AST-007', host: 'vpn-gw-01', ip: '10.10.0.2', type: 'VPN Gateway', os: 'Appliance', zone: 'Perimeter', criticality: 'critical', owner: 'Network' },
  { id: 'AST-008', host: 'ws-eng-4412', ip: '10.60.11.44', type: 'Workstation', os: 'Windows 11', zone: 'Corporate', criticality: 'medium', owner: 'Engineering' },
  { id: 'AST-009', host: 'ws-fin-2109', ip: '10.60.9.21', type: 'Workstation', os: 'Windows 11', zone: 'Corporate', criticality: 'medium', owner: 'Finance' },
  { id: 'AST-010', host: 'mac-des-0187', ip: '10.60.14.87', type: 'Workstation', os: 'macOS 15', zone: 'Corporate', criticality: 'low', owner: 'Design' },
  { id: 'AST-011', host: 'backup-vault-01', ip: '10.70.0.9', type: 'Backup Appliance', os: 'Appliance', zone: 'Core', criticality: 'critical', owner: 'Platform' },
  { id: 'AST-012', host: 'jump-admin-01', ip: '10.10.5.3', type: 'Bastion', os: 'Ubuntu 24.04', zone: 'Perimeter', criticality: 'critical', owner: 'Network' },
  { id: 'AST-013', host: 's3-customer-exports', ip: 'aws:eu-west-1', type: 'Cloud Storage', os: 'AWS S3', zone: 'Cloud', criticality: 'high', owner: 'Data' },
  { id: 'AST-014', host: 'iam-prod-account', ip: 'aws:global', type: 'Cloud IAM', os: 'AWS IAM', zone: 'Cloud', criticality: 'critical', owner: 'Cloud Security' },
  { id: 'AST-015', host: 'mail-gw-01', ip: '10.40.3.8', type: 'Email Gateway', os: 'Appliance', zone: 'DMZ', criticality: 'high', owner: 'Messaging' }
];

/** Tracked threat-actor profiles for the intel pages. */
const ACTORS = [
  {
    id: 'TA-0417',
    name: 'SILENT LYNX',
    aliases: ['UNC2891', 'Cobalt Drift'],
    motivation: 'Financial',
    origin: 'Eastern Europe',
    firstSeen: '2021-03',
    sophistication: 'High',
    targets: ['Banking', 'Payments', 'Fintech'],
    techniques: ['T1566.002', 'T1486', 'T1071.001', 'T1078'],
    summary:
      'Ransomware-as-a-service affiliate. Enters through phishing and edge appliance CVEs, dwells 6–11 days, exfiltrates before encrypting.',
    trend: 'rising'
  },
  {
    id: 'TA-0233',
    name: 'GLASS HERON',
    aliases: ['APT-C-61', 'Nightjar'],
    motivation: 'Espionage',
    origin: 'East Asia',
    firstSeen: '2018-09',
    sophistication: 'Very High',
    targets: ['Government', 'Defence', 'Semiconductors'],
    techniques: ['T1195.002', 'T1071.004', 'T1505.003', 'T1558.003'],
    summary:
      'State-aligned espionage group. Prefers supply-chain implants and long-dwell DNS tunnelling. Extremely low-noise tradecraft.',
    trend: 'steady'
  },
  {
    id: 'TA-0902',
    name: 'RUST MAGPIE',
    aliases: ['Scattered Crow'],
    motivation: 'Financial / Extortion',
    origin: 'Distributed',
    firstSeen: '2023-01',
    sophistication: 'Medium',
    targets: ['Retail', 'Hospitality', 'Telecom'],
    techniques: ['T1598', 'T1621', 'T1078.004', 'T1567.002'],
    summary:
      'Social-engineering specialists. Voice-phishes service desks for MFA resets, then pivots straight into cloud identity.',
    trend: 'rising'
  },
  {
    id: 'TA-0588',
    name: 'PALE FERRET',
    aliases: ['Storm-1174'],
    motivation: 'Hacktivism',
    origin: 'Middle East',
    firstSeen: '2022-06',
    sophistication: 'Low',
    targets: ['Media', 'Energy', 'Public Sector'],
    techniques: ['T1498', 'T1491.002', 'T1190'],
    summary:
      'Opportunistic defacement and DDoS aligned to geopolitical events. High volume, low technical depth, heavy publicity seeking.',
    trend: 'falling'
  },
  {
    id: 'TA-0741',
    name: 'HOLLOW BADGER',
    aliases: ['Vice Ibis', 'TEMP.Kestrel'],
    motivation: 'Financial',
    origin: 'South America',
    firstSeen: '2020-11',
    sophistication: 'Medium',
    targets: ['Healthcare', 'Logistics', 'Manufacturing'],
    techniques: ['T1059.001', 'T1053.005', 'T1562.001', 'T1021.002'],
    summary:
      'Commodity loader operator selling access to ransomware crews. Noisy on endpoint, reliable to catch with EDR tuning.',
    trend: 'steady'
  },
  {
    id: 'TA-0126',
    name: 'IRON CICADA',
    aliases: ['Grey Locust'],
    motivation: 'Espionage',
    origin: 'Unattributed',
    firstSeen: '2019-04',
    sophistication: 'High',
    targets: ['Legal', 'Research', 'Pharmaceutical'],
    techniques: ['T1611', 'T1098', 'T1530', 'T1213'],
    summary:
      'Cloud-native intrusion set. Lives entirely in IAM and container control planes; almost never touches an endpoint.',
    trend: 'rising'
  }
];

/** Indicator-of-compromise feed backing the intel search + lookup API. */
const IOCS = [
  { indicator: '185.220.101.47', type: 'ipv4', confidence: 94, severity: 'critical', actor: 'SILENT LYNX', tags: ['c2', 'ransomware'], firstSeen: '2026-07-28', description: 'Cobalt Strike team server, port 443 malleable profile.' },
  { indicator: 'cdn-sync-update.net', type: 'domain', confidence: 91, severity: 'critical', actor: 'SILENT LYNX', tags: ['c2', 'beacon'], firstSeen: '2026-08-02', description: 'Beacon callback domain, 60s jitter, TLS with self-signed cert.' },
  { indicator: 'a7f3c92e1b84d05f6a2c9e7b3d1f8a04c5e6b7d8f9a0b1c2d3e4f5a6b7c8d9e0', type: 'sha256', confidence: 88, severity: 'critical', actor: 'HOLLOW BADGER', tags: ['loader', 'malware'], firstSeen: '2026-08-05', description: 'Second-stage loader delivered via ISO attachment.' },
  { indicator: 'sso-verify-portal.com', type: 'domain', confidence: 86, severity: 'high', actor: 'RUST MAGPIE', tags: ['phishing', 'credential-harvest'], firstSeen: '2026-08-09', description: 'Okta clone harvesting credentials plus TOTP in real time.' },
  { indicator: '45.133.216.90', type: 'ipv4', confidence: 79, severity: 'high', actor: 'PALE FERRET', tags: ['scanning', 'exploit'], firstSeen: '2026-08-11', description: 'Mass scanning for CVE-2026-2183 on edge VPN appliances.' },
  { indicator: 'dns.telemetry-node.io', type: 'domain', confidence: 83, severity: 'high', actor: 'GLASS HERON', tags: ['dns-tunnel', 'exfil'], firstSeen: '2026-07-19', description: 'Authoritative NS used for DNS-tunnelled exfiltration.' },
  { indicator: 'b91d0e4a7c25f8360d9b1a3e6f4c8d2b', type: 'md5', confidence: 72, severity: 'medium', actor: 'HOLLOW BADGER', tags: ['dropper'], firstSeen: '2026-08-01', description: 'Macro-enabled dropper, low AV coverage at time of sighting.' },
  { indicator: 'payroll-review-2026.zip', type: 'filename', confidence: 68, severity: 'medium', actor: 'RUST MAGPIE', tags: ['phishing', 'lure'], firstSeen: '2026-08-12', description: 'HR-themed lure archive containing an LNK shortcut.' },
  { indicator: '104.21.55.192', type: 'ipv4', confidence: 61, severity: 'medium', actor: 'Unattributed', tags: ['proxy', 'anonymiser'], firstSeen: '2026-08-07', description: 'Residential proxy exit node used in credential stuffing.' },
  { indicator: 'update-agent-svc.exe', type: 'filename', confidence: 77, severity: 'high', actor: 'IRON CICADA', tags: ['masquerading', 'persistence'], firstSeen: '2026-07-30', description: 'Legitimate-looking binary name dropped in %TEMP%.' },
  { indicator: 'f2e8b1c4d7a9058e3b6c1d4f7a0b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b', type: 'sha256', confidence: 90, severity: 'critical', actor: 'GLASS HERON', tags: ['implant', 'supply-chain'], firstSeen: '2026-06-22', description: 'Trojanised build-tool plugin, signed with a stolen certificate.' },
  { indicator: 'auth-gateway-secure.app', type: 'domain', confidence: 74, severity: 'high', actor: 'RUST MAGPIE', tags: ['phishing', 'mfa-bypass'], firstSeen: '2026-08-13', description: 'Adversary-in-the-middle proxy relaying live session cookies.' },
  { indicator: '91.202.233.14', type: 'ipv4', confidence: 85, severity: 'high', actor: 'SILENT LYNX', tags: ['exfil', 'staging'], firstSeen: '2026-08-04', description: 'Exfiltration staging server, rclone over SFTP.' },
  { indicator: 'svc-backup-adm', type: 'account', confidence: 66, severity: 'medium', actor: 'Unattributed', tags: ['kerberoast', 'spn'], firstSeen: '2026-08-10', description: 'Service account name repeatedly targeted for SPN roasting.' }
];

/** Named CVEs surfaced on the vulnerability panel. */
const VULNS = [
  { cve: 'CVE-2026-2183', cvss: 9.8, epss: 0.87, product: 'EdgeConnect VPN 9.x', status: 'Exploited in the wild', affected: 3, kev: true, summary: 'Pre-auth remote code execution in the SSL-VPN web interface.' },
  { cve: 'CVE-2026-1774', cvss: 9.1, epss: 0.64, product: 'Apache Tomcat 11.0.x', status: 'PoC public', affected: 12, kev: false, summary: 'Deserialisation flaw in session persistence allows RCE.' },
  { cve: 'CVE-2026-0912', cvss: 8.8, epss: 0.41, product: 'Windows Print Spooler', status: 'Patch available', affected: 47, kev: true, summary: 'Local privilege escalation to SYSTEM via driver install.' },
  { cve: 'CVE-2026-3305', cvss: 8.2, epss: 0.29, product: 'OpenSSL 3.5.x', status: 'Patch available', affected: 88, kev: false, summary: 'Buffer overflow in certificate chain validation.' },
  { cve: 'CVE-2026-2940', cvss: 7.5, epss: 0.18, product: 'Kubernetes API Server 1.34', status: 'Patch available', affected: 6, kev: false, summary: 'Improper RBAC evaluation on aggregated API resources.' },
  { cve: 'CVE-2026-1102', cvss: 7.2, epss: 0.12, product: 'PostgreSQL 18', status: 'Patch available', affected: 9, kev: false, summary: 'Privilege escalation through a mutable search_path in extensions.' }
];

/** Global attack-origin volumes powering the geo panel. */
const GEO_SOURCES = [
  { country: 'Russian Federation', code: 'RU', share: 21.4, events: 48210, lat: 61, lon: 105 },
  { country: 'China', code: 'CN', share: 18.7, events: 42130, lat: 35, lon: 104 },
  { country: 'United States', code: 'US', share: 12.9, events: 29060, lat: 38, lon: -97 },
  { country: 'Netherlands', code: 'NL', share: 8.3, events: 18700, lat: 52, lon: 5 },
  { country: 'Brazil', code: 'BR', share: 7.1, events: 15990, lat: -14, lon: -51 },
  { country: 'Viet Nam', code: 'VN', share: 6.4, events: 14420, lat: 14, lon: 108 },
  { country: 'India', code: 'IN', share: 5.8, events: 13060, lat: 21, lon: 78 },
  { country: 'Iran', code: 'IR', share: 5.2, events: 11710, lat: 32, lon: 53 },
  { country: 'Nigeria', code: 'NG', share: 3.9, events: 8780, lat: 9, lon: 8 },
  { country: 'Other', code: 'XX', share: 10.3, events: 23200, lat: 0, lon: 0 }
];

const USERNAMES = [
  'a.morrow', 'j.okafor', 'l.tanaka', 's.delgado', 'r.whitfield',
  'm.chaudhry', 'k.ivanova', 'p.nakamura', 'd.oyelaran', 'n.bergstrom',
  'svc-backup-adm', 'svc-deploy-ci', 'svc-report-etl', 'admin.break-glass'
];

const EXTERNAL_IPS = [
  '185.220.101.47', '45.133.216.90', '91.202.233.14', '104.21.55.192',
  '193.32.127.201', '212.102.46.88', '5.188.206.130', '80.94.92.60',
  '141.98.11.75', '23.106.223.14'
];

module.exports = {
  SEVERITIES,
  TACTICS,
  RULES,
  ASSETS,
  ACTORS,
  IOCS,
  VULNS,
  GEO_SOURCES,
  USERNAMES,
  EXTERNAL_IPS
};
