'use strict';

/**
 * Public-facing endpoints: dashboard stats, asset inventory, service
 * catalog, pricing and the contact / demo-request intake.
 */

const express = require('express');
const database = require('../db');
const config = require('../lib/config');
const repo = require('../db/repository');
const soc = require('../lib/soc');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const { validate, rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

/** GET /api/stats — aggregate SOC metrics for the dashboard. */
router.get('/stats', (_req, res) => {
  res.json({ data: engine.computeStats() });
});

/** GET /api/assets — monitored asset inventory. */
router.get('/assets', (req, res) => {
  const rows = repo.assets.query({
    zone: req.query.zone,
    criticality: req.query.criticality,
    q: req.query.q
  });

  // One grouped query supplies every row's 24h count.
  const since = new Date(Date.now() - 24 * 3600_000).toISOString();
  const counts = repo.alerts.countsByAsset(since);

  const enriched = rows.map((a) => ({ ...a, alerts24h: counts.get(a.id) || 0 }));

  res.json({
    data: enriched,
    total: enriched.length,
    zones: repo.assets.zones()
  });
});

/**
 * GET /api/services — the service catalogue rendered on the services page.
 *
 * The SOC entry's headline metrics are substituted with measured values where
 * there are any. The median triage figure used to be the string "47s" with
 * nothing behind it; now it either reports what the alerts actually show or
 * says there is no sample, which is the honest answer on a fresh deployment.
 */
router.get('/services', (_req, res) => {
  const data = SERVICES.map((service) => {
    if (service.id !== 'soc') return service;

    const window = new Date(Date.now() - 30 * 86400_000).toISOString();
    const triage = soc.triageMetrics({ sinceIso: window });
    const rota = soc.status();

    return {
      ...service,
      metrics: [
        {
          label: 'Coverage',
          value: rota.configured && rota.coverage.complete ? '24/7/365' : 'incomplete',
          measured: true
        },
        {
          label: 'Median triage',
          value: triage.sampleSize ? soc.formatDuration(triage.medianSeconds) : 'no sample yet',
          measured: true,
          sampleSize: triage.sampleSize
        }
      ]
    };
  });

  res.json({ data });
});

/** GET /api/pricing — plan tiers. */
router.get('/pricing', (_req, res) => {
  res.json({ data: PLANS });
});

/**
 * POST /api/contact — demo request / contact intake.
 * Stored server-side and readable only by an authenticated admin.
 */
router.post(
  '/contact',
  rateLimit({ windowMs: 60 * 60_000, max: 8, key: 'contact' }),
  (req, res) => {
    const { ok, errors, value } = validate(req.body, {
      name: { required: true, minLength: 2, maxLength: 80, label: 'Name' },
      email: { required: true, type: 'email', label: 'Work email' },
      company: { required: true, minLength: 2, maxLength: 100, label: 'Company' },
      employees: {
        required: false,
        enum: ['1-50', '51-250', '251-1000', '1001-5000', '5000+'],
        label: 'Company size',
        default: '51-250'
      },
      interest: {
        required: false,
        enum: ['soc', 'mdr', 'threat-intel', 'ir', 'compliance', 'other'],
        label: 'Area of interest',
        default: 'soc'
      },
      urgency: {
        required: false,
        enum: ['active-incident', 'evaluating', 'planning', 'research'],
        label: 'Urgency',
        default: 'evaluating'
      },
      message: { required: true, minLength: 10, maxLength: 2000, label: 'Message' }
    });

    if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

    // Honeypot field — real users never fill a hidden input.
    if (req.body?.website) {
      return res.status(202).json({ ok: true, reference: 'REQ-IGNORED' });
    }

    const record = repo.contacts.insert({
      id: engine.id('REQ'),
      ...value,
      ip: clientIp(req),
      submittedAt: new Date().toISOString(),
      status: 'new'
    });

    repo.contacts.trim(300);

    const sla = value.urgency === 'active-incident' ? '15 minutes' : '1 business day';

    res.status(201).json({
      ok: true,
      reference: record.id,
      sla,
      message:
        value.urgency === 'active-incident'
          ? 'Priority request received. Our incident desk responds within 15 minutes, 24/7.'
          : 'Request received. A security engineer will respond within one business day.'
    });
  }
);

/** GET /api/contact — admin-only view of submitted requests. */
router.get('/contact', auth.requireAuth, auth.requireRole('admin'), (_req, res) => {
  const data = repo.contacts.list();
  res.json({ data, total: repo.contacts.count() });
});

/** GET /api/audit — admin-only security audit trail. */
router.get('/audit', auth.requireAuth, auth.requireRole('admin'), (_req, res) => {
  res.json({ data: repo.audit.list(100) });
});

/**
 * GET /api/config — deployment flags the frontend needs before sign-in.
 * Deliberately contains no secrets: it only says which features are on.
 */
router.get('/config', (_req, res) => {
  res.json({
    demoMode: config.demoMode,
    registrationOpen: config.registrationOpen,
    production: config.production
  });
});

/** GET /api/health — liveness probe. */
router.get('/health', (_req, res) => {
  res.json({
    status: 'operational',
    uptimeSeconds: Math.round(process.uptime()),
    node: process.version,
    database: 'sqlite',
    alerts: repo.alerts.count(),
    incidents: repo.incidents.count(),
    liveStreamClients: engine.clientCount(),
    time: new Date().toISOString()
  });
});

/**
 * GET /api/ready — readiness probe. Separate from liveness: this one fails
 * if the database cannot actually be queried, so an orchestrator can pull the
 * instance out of rotation rather than just restarting it.
 */
router.get('/ready', (_req, res) => {
  try {
    database.handle().prepare('SELECT 1 AS ok').get();
    res.json({ ready: true, database: 'sqlite', time: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ ready: false, error: 'database_unavailable', message: err.message });
  }
});

// ------------------------------------------------------------ static content

const SERVICES = [
  {
    id: 'soc',
    icon: 'radar',
    name: '24/7 Security Operations Centre',
    tagline: 'Analysts on console, every hour of every day.',
    description:
      'A fully staffed SOC watching your estate around the clock. Tier 1 triage, Tier 2 investigation and Tier 3 threat hunting operating from a single correlated timeline, with an analyst on your bridge in minutes rather than hours.',
    features: [
      'Follow-the-sun coverage across three regions',
      'Median 47-second triage on critical detections',
      'Named analyst pod that learns your environment',
      'Monthly detection tuning against your own false-positive data',
      'Direct escalation bridge — no ticket queue for P1'
    ],
    metrics: [{ label: 'Coverage', value: '24/7/365' }, { label: 'Median triage', value: '47s' }]
  },
  {
    id: 'mdr',
    icon: 'shield',
    name: 'Managed Detection & Response',
    tagline: 'Detection is only half the job. We contain it too.',
    description:
      'Beyond alerting: authorised containment actions taken on your behalf. Host isolation, session revocation, credential resets and edge blocks executed inside the agreed runbook while your team is still reading the page.',
    features: [
      'Pre-authorised containment runbooks per asset class',
      'Automated host isolation in under 60 seconds',
      'Identity kill-switch for compromised sessions',
      'Rollback plans documented before any action is taken',
      'Full action log with per-step attribution'
    ],
    metrics: [{ label: 'Auto-contained', value: '68.5%' }, { label: 'MTTR', value: '31 min' }]
  },
  {
    id: 'threat-intel',
    icon: 'globe',
    name: 'Threat Intelligence',
    tagline: 'Know what is coming for your sector.',
    description:
      'Curated, sector-specific intelligence mapped to MITRE ATT&CK and wired directly into your detections. Indicators arrive as deployable rules, not as a PDF you have to read on a Friday afternoon.',
    features: [
      'Tracked actor profiles with campaign timelines',
      'Indicator feed with confidence scoring and decay',
      'Automatic enrichment of every alert in the console',
      'Sector-specific early-warning briefings',
      'Dark-web and paste-site credential monitoring'
    ],
    metrics: [{ label: 'Actors tracked', value: '180+' }, { label: 'Feed latency', value: '<5 min' }]
  },
  {
    id: 'ir',
    icon: 'siren',
    name: 'Incident Response & Forensics',
    tagline: 'When it has already happened.',
    description:
      'A retained response team that mobilises on a 15-minute SLA. Scoping, containment, eradication and evidence-grade forensics — plus the written narrative your regulator, insurer and board will each ask for.',
    features: [
      '15-minute mobilisation on retainer',
      'Court-admissible evidence handling and chain of custody',
      'Memory, disk and cloud control-plane forensics',
      'Ransomware negotiation liaison and recovery planning',
      'Regulator, insurer and board-ready reporting'
    ],
    metrics: [{ label: 'Mobilisation', value: '15 min' }, { label: 'Cases handled', value: '340+' }]
  },
  {
    id: 'vuln',
    icon: 'bug',
    name: 'Vulnerability & Exposure Management',
    tagline: 'Patch what actually matters first.',
    description:
      'Continuous discovery across internal, external and cloud surfaces, prioritised by real exploitability — EPSS, known-exploited status and blast radius in your environment — rather than raw CVSS.',
    features: [
      'Continuous external attack-surface discovery',
      'EPSS and KEV-weighted prioritisation',
      'Blast-radius modelling per finding',
      'Patch-window planning aligned to your change process',
      'Verification rescan after every remediation'
    ],
    metrics: [{ label: 'Assets scanned', value: 'Unlimited' }, { label: 'Rescan', value: 'Hourly' }]
  },
  {
    id: 'compliance',
    icon: 'clipboard',
    name: 'Compliance & Audit Readiness',
    tagline: 'Evidence collected as you go, not the week before.',
    description:
      'Continuous control monitoring mapped to ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR and DORA. Evidence is captured automatically from the same telemetry the SOC already ingests.',
    features: [
      'Control mapping across six major frameworks',
      'Automated evidence capture and retention',
      'Immutable, exportable audit trail',
      'Gap analysis with a prioritised remediation plan',
      'Auditor-ready reporting packs on demand'
    ],
    metrics: [{ label: 'Frameworks', value: '6' }, { label: 'Evidence', value: 'Automated' }]
  }
];

const PLANS = [
  {
    id: 'essential',
    name: 'Essential',
    price: 1490,
    unit: 'per month',
    blurb: 'Core monitoring for small teams that need real coverage without a full SOC build.',
    highlight: false,
    limits: { assets: 100, retention: '90 days', responseSla: '4 hours' },
    features: [
      '24/7 automated detection',
      'Analyst review during business hours',
      'Up to 100 monitored assets',
      '90-day log retention',
      'Email and portal alerting',
      'Monthly security report',
      'Standard detection rule pack'
    ],
    notIncluded: ['Active containment', 'Dedicated analyst pod', 'IR retainer']
  },
  {
    id: 'professional',
    name: 'Professional',
    price: 4890,
    unit: 'per month',
    blurb: 'Full managed detection and response with humans on console around the clock.',
    highlight: true,
    limits: { assets: 500, retention: '12 months', responseSla: '15 minutes' },
    features: [
      'Everything in Essential',
      '24/7 human analyst coverage',
      'Managed containment actions',
      'Up to 500 monitored assets',
      '12-month log retention',
      'Threat intelligence enrichment',
      'Custom detection engineering',
      'Quarterly purple-team exercise',
      'Named analyst pod'
    ],
    notIncluded: ['Dedicated forensics retainer']
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    price: null,
    unit: 'custom',
    blurb: 'Regulated, distributed or high-risk estates that need the whole programme.',
    highlight: false,
    limits: { assets: 'Unlimited', retention: '7 years', responseSla: '5 minutes' },
    features: [
      'Everything in Professional',
      'Unlimited monitored assets',
      '7-year compliant retention',
      'Dedicated incident response retainer',
      'On-site forensics capability',
      'Compliance evidence automation',
      'Private threat-intel briefings',
      'Executive and board reporting',
      'Custom SLAs and contractual penalties'
    ],
    notIncluded: []
  }
];

module.exports = router;
