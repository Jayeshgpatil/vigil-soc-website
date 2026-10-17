'use strict';

/**
 * Seeds the datastore with a believable 24-hour history: demo accounts,
 * back-dated alerts and a set of incidents in different lifecycle states.
 * Idempotent — running it twice does nothing unless --force is passed.
 */

const config = require('./config');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('./auth');
const engine = require('./engine');
const { ASSETS, RULES } = require('./catalog');

const DEMO_USERS = [
  {
    name: 'Demo Analyst',
    email: 'analyst@vgil.io',
    password: 'Vgil#Demo2026',
    role: 'analyst',
    org: 'VGIL Demo Tenant',
    title: 'Tier 2 SOC Analyst'
  },
  {
    name: 'Demo Admin',
    email: 'admin@vgil.io',
    password: 'Vgil#Admin2026',
    role: 'admin',
    org: 'VGIL Demo Tenant',
    title: 'SOC Manager'
  }
];

const INCIDENT_TEMPLATES = [
  {
    title: 'Ransomware staging detected on finance database host',
    severity: 'critical',
    status: 'contained',
    ruleId: 'VGIL-1003',
    assetId: 'AST-003',
    ageHours: 19,
    ackAfterMin: 3,
    closeAfterMin: 214,
    summary:
      'Canary files on sql-fin-prod were renamed by a process spawned from a scheduled task. Host isolated within 4 minutes of detection; no encryption of production volumes occurred.',
    timeline: [
      'Canary file modification detected by EDR sensor.',
      'Automated containment isolated the host from the network.',
      'Analyst confirmed the parent process chain originated from a Kerberoasted service account.',
      'Service account credentials rotated across the estate.',
      'Memory image captured and shipped to forensics.',
      'Host rebuilt from a known-good gold image and returned to service.'
    ]
  },
  {
    title: 'Adversary-in-the-middle phishing campaign against finance team',
    severity: 'high',
    status: 'investigating',
    ruleId: 'VGIL-1011',
    assetId: 'AST-015',
    ageHours: 7,
    ackAfterMin: 6,
    summary:
      'Fourteen users received a link to auth-gateway-secure.app, an AiTM proxy relaying live session cookies. Three users clicked; one submitted credentials plus a TOTP code.',
    timeline: [
      'Email gateway flagged a newly registered lookalike domain.',
      'Click telemetry identified three users who followed the link.',
      'Affected sessions revoked and passwords reset.',
      'Tenant-wide purge removed the message from all mailboxes.',
      'Hunting for post-authentication activity on the affected identity is ongoing.'
    ]
  },
  {
    title: 'Cloud IAM privilege escalation by CI service principal',
    severity: 'critical',
    status: 'triaged',
    ruleId: 'VGIL-1006',
    assetId: 'AST-014',
    ageHours: 3,
    ackAfterMin: 2,
    summary:
      'The svc-deploy-ci principal attached AdministratorAccess to itself outside a change window. Suspected leaked access key in a public repository.',
    timeline: [
      'CloudTrail alert on AttachUserPolicy for an administrator policy.',
      'Policy detached and the access key disabled within 9 minutes.',
      'Secret scanning confirmed the key was committed to a public repository 40 hours earlier.',
      'Full session replay from CloudTrail is under review.'
    ]
  },
  {
    title: 'DNS tunnelling from research subnet workstation',
    severity: 'high',
    status: 'closed',
    ruleId: 'VGIL-1018',
    assetId: 'AST-008',
    ageHours: 40,
    ackAfterMin: 11,
    closeAfterMin: 385,
    summary:
      'High-entropy subdomain queries to dns.telemetry-node.io at a fixed 30-second cadence. Traced to an unapproved developer tool, not adversary activity.',
    timeline: [
      'Resolver logs flagged an anomalous query-entropy pattern.',
      'Host isolated as a precaution and PCAP captured.',
      'Decoded queries resolved to a vendor telemetry beacon in an unsanctioned SDK.',
      'Closed as a true-positive detection with benign root cause; SDK added to the software blocklist.'
    ]
  },
  {
    title: 'Web shell dropped on DMZ web node',
    severity: 'critical',
    status: 'closed',
    ruleId: 'VGIL-1010',
    assetId: 'AST-004',
    ageHours: 62,
    ackAfterMin: 4,
    closeAfterMin: 168,
    summary:
      'A PHP script appeared in the web root of web-edge-01 outside the deployment pipeline, following exploitation of CVE-2026-1774.',
    timeline: [
      'File integrity monitoring detected an unsigned script in the web root.',
      'Node removed from the load balancer pool.',
      'Access logs confirmed exploitation of the Tomcat deserialisation flaw.',
      'Patch deployed fleet-wide and the node rebuilt.',
      'Post-incident review completed; WAF virtual patch added.'
    ]
  },
  {
    title: 'Credential stuffing against the customer portal',
    severity: 'medium',
    status: 'contained',
    ruleId: 'VGIL-1002',
    assetId: 'AST-005',
    ageHours: 12,
    ackAfterMin: 8,
    closeAfterMin: 96,
    summary:
      '61,400 authentication attempts from 340 residential proxy IPs over 22 minutes. Nine accounts matched breached credentials; all were force-reset before use.',
    timeline: [
      'WAF rate anomaly triggered on the login endpoint.',
      'Source ranges blocked at the edge and step-up MFA enforced.',
      'Nine at-risk accounts identified and force-reset.',
      'No successful unauthorised session was established.'
    ]
  },
  {
    title: 'Impossible travel on privileged administrator account',
    severity: 'high',
    status: 'closed',
    ruleId: 'VGIL-1001',
    assetId: 'AST-012',
    ageHours: 30,
    ackAfterMin: 5,
    closeAfterMin: 47,
    summary:
      'admin.break-glass authenticated from two continents 11 minutes apart. Confirmed as a corporate VPN egress change, not a compromise.',
    timeline: [
      'Identity provider correlation raised an impossible-travel alert.',
      'Sessions revoked pending verification.',
      'Account owner confirmed activity by an out-of-band channel.',
      'Geo-baseline updated for the new VPN egress range; closed as a false positive.'
    ]
  },
  {
    title: 'Public exposure of customer export storage bucket',
    severity: 'medium',
    status: 'investigating',
    ruleId: 'VGIL-1009',
    assetId: 'AST-013',
    ageHours: 5,
    ackAfterMin: 14,
    summary:
      's3-customer-exports was made publicly readable by a Terraform change. Access logs are being reviewed for anonymous reads during the exposure window.',
    timeline: [
      'CSPM detected a public-read ACL on a bucket holding classified objects.',
      'Public access revoked and account-level block enabled.',
      'Exposure window measured at 71 minutes.',
      'Access log review for anonymous reads is in progress.'
    ]
  }
];

function seedUsers() {
  // On a public deployment these are a published admin password, so they are
  // only created when demo mode is explicitly on.
  if (!config.demoMode) return;

  for (const u of DEMO_USERS) {
    if (repo.users.byEmail(u.email)) continue;
    repo.users.insert({
      id: engine.id('USR'),
      name: u.name,
      email: u.email,
      passwordHash: auth.hashPassword(u.password),
      role: u.role,
      org: u.org,
      title: u.title,
      createdAt: new Date().toISOString(),
      lastLogin: null,
      disabled: false,
      mfaEnabled: true,
      demo: true
    });
  }
}

/** Back-fills ~26 hours of alerts so the charts have real history at boot. */
function seedAlerts(count = 320) {
  const now = Date.now();
  const span = 26 * 3600_000;
  const rows = [];

  for (let i = 0; i < count; i += 1) {
    // Bias timestamps toward the recent past — the feed looks "warm".
    const skew = Math.pow(Math.random(), 1.6);
    const when = new Date(now - skew * span);
    const alert = engine.buildAlert(when);

    const age = (now - when.getTime()) / 3600_000;
    if (age > 8) {
      alert.status = engine.pick(['closed', 'closed', 'contained', 'triaged']);
      alert.assignee = engine.pick(['a.morrow', 'j.okafor', 'l.tanaka', null]);
    } else if (age > 2) {
      alert.status = engine.pick(['triaged', 'investigating', 'new', 'contained']);
    }
    rows.push(alert);
  }

  rows.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  repo.alerts.insertMany(rows);
}

function seedIncidents() {
  const now = Date.now();

  INCIDENT_TEMPLATES.forEach((tpl, idx) => {
    const opened = new Date(now - tpl.ageHours * 3600_000);
    const rule = RULES.find((r) => r.id === tpl.ruleId);
    const asset = ASSETS.find((a) => a.id === tpl.assetId);

    const incident = {
      id: `INC-${String(2041 + idx).padStart(4, '0')}`,
      title: tpl.title,
      severity: tpl.severity,
      status: tpl.status,
      priority: tpl.severity === 'critical' ? 'P1' : tpl.severity === 'high' ? 'P2' : 'P3',
      summary: tpl.summary,
      ruleId: tpl.ruleId,
      rule: rule ? rule.name : 'Correlated detection',
      technique: rule ? rule.technique : 'T1078',
      tactic: rule ? rule.tactic : 'Initial Access',
      assetId: tpl.assetId,
      host: asset ? asset.host : 'unknown',
      zone: asset ? asset.zone : 'unknown',
      owner: asset ? asset.owner : 'Unassigned',
      analyst: engine.pick(['a.morrow', 'j.okafor', 'l.tanaka', 's.delgado']),
      openedAt: opened.toISOString(),
      acknowledgedAt: new Date(
        opened.getTime() + tpl.ackAfterMin * 60_000
      ).toISOString(),
      closedAt:
        tpl.closeAfterMin !== undefined
          ? new Date(opened.getTime() + tpl.closeAfterMin * 60_000).toISOString()
          : null,
      updatedAt: new Date(
        opened.getTime() + (tpl.closeAfterMin || tpl.ackAfterMin) * 60_000
      ).toISOString(),
      timeline: tpl.timeline.map((entry, i) => ({
        ts: new Date(opened.getTime() + i * 18 * 60_000).toISOString(),
        actor: i === 0 ? 'VGIL Detection Engine' : engine.pick(['a.morrow', 'j.okafor', 'Automation']),
        entry
      })),
      seeded: true
    };

    repo.incidents.insert(incident);
  });
}

function seedAssets() {
  const rows = ASSETS.map((a) => ({
    ...a,
    status: Math.random() < 0.92 ? 'healthy' : 'degraded',
    agentVersion: '4.8.' + engine.randInt(10, 24),
    lastSeen: new Date(Date.now() - engine.randInt(0, 400) * 1000).toISOString(),
    openFindings: engine.randInt(0, 7)
  }));
  repo.assets.upsertMany(rows);
}

/** Drops all tenant data. Used by `npm run seed -- --force` and the tests. */
function reset() {
  const conn = database.handle();
  database.transaction(() => {
    // Order matters: children before parents, since foreign keys are enforced.
    for (const table of [
      'alert_notes',
      'incident_timeline',
      'alerts',
      'incidents',
      'sessions',
      'contacts',
      'audit_log',
      'assets',
      'users'
    ]) {
      conn.exec(`DELETE FROM ${table}`);
    }
  });
}


/**
 * A working follow-the-sun rota.
 *
 * Three eight-hour windows that between them cover every UTC hour, so the
 * coverage check has something true to verify rather than an empty table that
 * would report a 24-hour gap on a fresh install.
 */
function seedRota() {
  if (repo.socShifts.count() > 0) return;

  const now = new Date().toISOString();

  const podSpecs = [
    { region: 'APAC', name: 'Pod Kestrel', description: 'Singapore and Sydney console.' },
    { region: 'EMEA', name: 'Pod Harrier', description: 'London and Dublin console.' },
    { region: 'AMER', name: 'Pod Merlin', description: 'Toronto and Austin console.' }
  ];

  const shiftSpecs = [
    { region: 'APAC', label: 'APAC day', startHour: 22, endHour: 6 },
    { region: 'EMEA', label: 'EMEA day', startHour: 6, endHour: 14 },
    { region: 'AMER', label: 'AMER day', startHour: 14, endHour: 22 }
  ];

  database.transaction(() => {
    const pods = {};
    for (const spec of podSpecs) {
      const pod = repo.pods.insert({
        id: engine.id('POD'),
        name: spec.name,
        region: spec.region,
        description: spec.description,
        createdAt: now
      });
      pods[spec.region] = pod.id;
    }

    for (const spec of shiftSpecs) {
      repo.socShifts.insert({
        id: engine.id('SHF'),
        region: spec.region,
        label: spec.label,
        podId: pods[spec.region],
        startHour: spec.startHour,
        endHour: spec.endHour,
        createdAt: now
      });
    }
  });
}


/**
 * Vulnerability catalogue.
 *
 * Deliberately includes pairs where CVSS and real exploitability disagree,
 * because that disagreement is the entire claim on the services page. If every
 * high-CVSS entry also had high EPSS, the ranking would be indistinguishable
 * from sorting by CVSS and there would be nothing to demonstrate.
 *
 * `appliesTo` uses the asset-type labels from the inventory, so discovery
 * cannot report a Tomcat flaw against a storage bucket.
 */
const VULN_CATALOGUE = [
  {
    cve: 'CVE-2026-2183',
    title: 'Pre-auth RCE in SSL-VPN web interface',
    vendor: 'EdgeConnect',
    product: 'EdgeConnect VPN 9.x',
    cvss: 9.8,
    cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    epss: 0.87,
    epssPercentile: 0.999,
    kev: true,
    kevAdded: '2026-07-14',
    published: '2026-06-28',
    summary: 'Unauthenticated remote code execution in the SSL-VPN web interface.',
    fixVersion: '9.4.7',
    appliesTo: ['VPN Gateway']
  },
  {
    // The instructive one: CVSS 6.5 but actively exploited and internet-facing.
    // Sorting by CVSS buries this beneath half a dozen 9s nobody is using.
    cve: 'CVE-2026-4410',
    title: 'Authentication bypass via crafted session cookie',
    vendor: 'Atlas',
    product: 'Atlas Web Gateway 4.2',
    cvss: 6.5,
    cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N',
    epss: 0.91,
    epssPercentile: 0.999,
    kev: true,
    kevAdded: '2026-08-02',
    published: '2026-07-19',
    summary: 'A crafted cookie skips session validation, granting authenticated access.',
    fixVersion: '4.2.9',
    appliesTo: ['Web Server', 'Email Gateway']
  },
  {
    // The opposite: a 9.9 with almost no exploitation. High CVSS, low urgency.
    cve: 'CVE-2026-5521',
    title: 'Command injection in backup restore routine',
    vendor: 'Vaultis',
    product: 'Vaultis Backup 7',
    cvss: 9.9,
    cvssVector: 'AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H',
    epss: 0.03,
    epssPercentile: 0.61,
    kev: false,
    published: '2026-08-11',
    summary: 'Authenticated administrators can inject commands through a restore path.',
    fixVersion: '7.1.2',
    appliesTo: ['Backup Appliance']
  },
  {
    cve: 'CVE-2026-1774',
    title: 'Deserialisation RCE in session persistence',
    vendor: 'Apache',
    product: 'Apache Tomcat 11.0.x',
    cvss: 9.1,
    epss: 0.64,
    epssPercentile: 0.988,
    kev: false,
    published: '2026-05-02',
    summary: 'Deserialisation flaw in session persistence allows remote code execution.',
    fixVersion: '11.0.14',
    appliesTo: ['Web Server', 'Container Host']
  },
  {
    cve: 'CVE-2026-0912',
    title: 'Print Spooler privilege escalation',
    vendor: 'Microsoft',
    product: 'Windows Print Spooler',
    cvss: 8.8,
    epss: 0.41,
    epssPercentile: 0.962,
    kev: true,
    kevAdded: '2026-04-30',
    published: '2026-03-14',
    summary: 'Local privilege escalation to SYSTEM through driver installation.',
    fixVersion: 'KB5041882',
    appliesTo: ['Workstation', 'Domain Controller']
  },
  {
    cve: 'CVE-2026-3305',
    title: 'Buffer overflow in certificate chain validation',
    vendor: 'OpenSSL',
    product: 'OpenSSL 3.5.x',
    cvss: 8.2,
    epss: 0.29,
    epssPercentile: 0.934,
    kev: false,
    published: '2026-06-09',
    summary: 'Overflow while validating a crafted certificate chain.',
    fixVersion: '3.5.4',
    appliesTo: ['Web Server', 'VPN Gateway', 'Email Gateway', 'Bastion']
  },
  {
    cve: 'CVE-2026-2940',
    title: 'Improper RBAC on aggregated API resources',
    vendor: 'Kubernetes',
    product: 'Kubernetes API Server 1.34',
    cvss: 7.5,
    epss: 0.18,
    epssPercentile: 0.887,
    kev: false,
    published: '2026-05-21',
    summary: 'RBAC is evaluated incorrectly for aggregated API resources.',
    fixVersion: '1.34.3',
    appliesTo: ['Container Host', 'Cloud IAM']
  },
  {
    cve: 'CVE-2026-1102',
    title: 'Privilege escalation via mutable search_path',
    vendor: 'PostgreSQL',
    product: 'PostgreSQL 18',
    cvss: 7.2,
    epss: 0.12,
    epssPercentile: 0.842,
    kev: false,
    published: '2026-02-27',
    summary: 'Extensions with a mutable search_path allow privilege escalation.',
    fixVersion: '18.2',
    appliesTo: ['Database']
  },
  {
    cve: 'CVE-2026-6087',
    title: 'Public bucket enumeration through misconfigured policy',
    vendor: 'Cloud',
    product: 'Object Storage policy engine',
    cvss: 5.3,
    epss: 0.55,
    epssPercentile: 0.981,
    kev: false,
    published: '2026-07-30',
    summary: 'A permissive default policy allows anonymous enumeration of bucket contents.',
    fixVersion: 'policy-2026-08',
    appliesTo: ['Cloud Storage']
  },
  {
    cve: 'CVE-2026-3388',
    title: 'Stored XSS in administrative console',
    vendor: 'Atlas',
    product: 'Atlas Admin Console 4.2',
    cvss: 4.8,
    epss: 0.02,
    epssPercentile: 0.44,
    kev: false,
    published: '2026-04-04',
    summary: 'An administrator can store script that executes for other administrators.',
    fixVersion: '4.2.9',
    appliesTo: ['Web Server']
  }
];

/**
 * Loads the catalogue and runs one discovery pass, so a fresh install has a
 * populated, correctly-ranked queue rather than an empty page.
 */
function seedExposure() {
  if (repo.vulnFindings.count() > 0) return;

  const exposure = require('./exposure');

  database.transaction(() => {
    for (const vuln of VULN_CATALOGUE) repo.vulnerabilities.insert(vuln);
  });

  exposure.runDiscovery({ triggeredBy: 'seed' });
}

function run({ force = false, quiet = false } = {}) {
  database.open({ quiet });

  if (force) reset();

  const fresh = repo.alerts.count() === 0;

  seedUsers();
  seedAssets();
  seedRota();
  seedExposure();

  if (fresh) {
    database.transaction(() => {
      seedAlerts();
      if (repo.incidents.count() === 0) seedIncidents();
    });

    if (!quiet) {
      console.log(
        `[seed] ${repo.alerts.count()} alerts, ${repo.incidents.count()} incidents, ` +
          `${repo.users.count()} users, ${repo.assets.count()} assets`
      );
    }
  }

  return { seeded: fresh };
}

module.exports = { run, reset, DEMO_USERS };

// Allow `npm run seed`
if (require.main === module) {
  run({ force: process.argv.includes('--force') });
  console.log('[seed] done →', database.path);
  database.close();
}
