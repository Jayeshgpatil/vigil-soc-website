'use strict';

const express = require('express');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const webhooks = require('../lib/webhooks');
const notify = require('../lib/notify');
const soc = require('../lib/soc');
const { validate, rateLimit } = require('../lib/security');

const router = express.Router();

const STATUSES = ['new', 'triaged', 'investigating', 'contained', 'closed'];

/**
 * GET /api/alerts
 * Filter (severity, status, tactic, source, q, since), sort and paginate.
 * Public read so the marketing pages can show a live sample.
 */
router.get('/', rateLimit({ windowMs: 60_000, max: 240, key: 'alerts' }), (req, res) => {
  // Filtering, sorting and paging all happen in SQL against the indexed
  // columns rather than by loading the table and walking it in JS.
  const { rows, total, page, limit } = repo.alerts.query({
    severity: req.query.severity,
    status: req.query.status,
    tactic: req.query.tactic,
    source: req.query.source,
    zone: req.query.zone,
    assignee: req.query.assignee,
    q: req.query.q,
    since: req.query.since,
    sort: req.query.sort || 'ts',
    order: req.query.order || 'desc',
    page: req.query.page,
    limit: req.query.limit
  });

  const start = (page - 1) * limit;

  res.json({
    data: rows,
    pagination: {
      page,
      limit,
      total,
      pages: Math.max(1, Math.ceil(total / limit)),
      hasNext: start + limit < total,
      hasPrev: page > 1
    }
  });
});

/** GET /api/alerts/stream — Server-Sent Events feed of new detections. */
router.get('/stream', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();

  res.write(`event: connected\ndata: ${JSON.stringify({
    ts: new Date().toISOString(),
    message: 'VGIL detection stream established'
  })}\n\n`);

  // Prime the client with the most recent detections, oldest first so the
  // console reads in chronological order.
  for (const alert of repo.alerts.recent(8).reverse()) {
    res.write(`event: alert\ndata: ${JSON.stringify(alert)}\n\n`);
  }

  const detach = engine.addClient(res);
  req.on('close', () => {
    detach();
    res.end();
  });
});

/** GET /api/alerts/:id */
router.get('/:id', (req, res) => {
  const alert = repo.alerts.byId(req.params.id);
  if (!alert) return res.status(404).json({ error: 'not_found', message: 'Alert not found.' });
  res.json({ data: alert });
});

/** PATCH /api/alerts/:id — triage actions. Requires a session. */
router.patch('/:id', auth.requireAuthOrKey, (req, res) => {
  const alert = repo.alerts.byId(req.params.id);
  if (!alert) return res.status(404).json({ error: 'not_found', message: 'Alert not found.' });

  const { ok, errors, value } = validate(req.body, {
    status: { required: false, enum: STATUSES, label: 'Status' },
    assignee: { required: false, maxLength: 60, label: 'Assignee' },
    note: { required: false, maxLength: 500, label: 'Note' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const patch = { updatedAt: new Date().toISOString() };
  if (value.status) patch.status = value.status;
  if (value.assignee !== undefined) patch.assignee = value.assignee || req.user.email;

  // The first move out of 'new' is the triage moment. Stamped once and never
  // overwritten: updated_at moves on every later edit, so it cannot answer
  // "how long did somebody take to look at this".
  if (value.status && value.status !== 'new' && !alert.triagedAt) {
    patch.triagedAt = patch.updatedAt;
    patch.triagedBy = req.user.email;
  }

  if (value.note) {
    repo.alerts.addNote(alert.id, {
      ts: new Date().toISOString(),
      author: req.user.email,
      text: value.note
    });
  }

  const updated = repo.alerts.update(alert.id, patch);
  engine.broadcast('alert-updated', updated);

  res.json({ data: updated });
});

/**
 * POST /api/alerts/:id/escalate — promote an alert to a tracked incident.
 */
router.post('/:id/escalate', auth.requireAuthOrKey, (req, res) => {
  const alert = repo.alerts.byId(req.params.id);
  if (!alert) return res.status(404).json({ error: 'not_found', message: 'Alert not found.' });

  const existing = repo.incidents.bySourceAlert(alert.id);
  if (existing) {
    return res.status(409).json({
      error: 'already_escalated',
      message: `Alert already escalated as ${existing.id}.`,
      data: existing
    });
  }

  const now = new Date().toISOString();
  const seq = repo.incidents.nextSequence();

  const incident = repo.incidents.insert({
    id: `INC-${String(seq).padStart(4, '0')}`,
    title: `${alert.rule} on ${alert.host}`,
    severity: alert.severity,
    status: 'triaged',
    priority: alert.severity === 'critical' ? 'P1' : alert.severity === 'high' ? 'P2' : 'P3',
    summary: alert.description,
    ruleId: alert.ruleId,
    rule: alert.rule,
    technique: alert.technique,
    tactic: alert.tactic,
    assetId: alert.assetId,
    host: alert.host,
    zone: alert.zone,
    owner: alert.owner,
    analyst: req.user.email,
    sourceAlertId: alert.id,
    openedAt: now,
    acknowledgedAt: now,
    closedAt: null,
    updatedAt: now,
    timeline: [
      { ts: now, actor: 'VGIL Detection Engine', entry: `Detection ${alert.id} fired: ${alert.rule}.` },
      { ts: now, actor: req.user.email, entry: 'Escalated to incident from the alert console.' }
    ]
  });

  repo.alerts.update(alert.id, {
    status: 'investigating',
    incidentId: incident.id,
    assignee: req.user.email,
    updatedAt: now
  });

  engine.broadcast('incident', incident);
  webhooks.dispatch('incident.opened', incident);
  if (incident.severity === 'critical') {
    webhooks.dispatch('alert.critical', alert);
    notify.criticalAlert(alert);
  }
  notify.incidentOpened(incident, req.user.email);

  res.status(201).json({ data: incident });
});

/**
 * POST /api/alerts/:id/false-positive — mark a detection as wrong.
 *
 * The category matters more than the free text: it is what turns a pile of
 * dismissals into a specific tuning suggestion. "Rule too broad" and
 * "known-good process" need different fixes.
 */
router.post('/:id/false-positive', auth.requireAuth, (req, res) => {
  const alert = repo.alerts.byId(req.params.id);
  if (!alert) return res.status(404).json({ error: 'not_found', message: 'Alert not found.' });

  const categories = Object.keys(soc.FP_CATEGORIES);
  const { ok, errors, value } = validate(req.body, {
    category: { required: true, enum: categories, label: 'Category' },
    reason: { required: true, minLength: 8, maxLength: 400, label: 'Reason' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const now = new Date().toISOString();
  const patch = {
    falsePositive: true,
    fpCategory: value.category,
    fpReason: value.reason,
    fpMarkedBy: req.user.email,
    fpMarkedAt: now,
    status: 'closed',
    updatedAt: now
  };

  // Marking a false positive is itself a triage decision, so it counts.
  if (!alert.triagedAt) {
    patch.triagedAt = now;
    patch.triagedBy = req.user.email;
  }

  const updated = repo.alerts.update(alert.id, patch);

  repo.alerts.addNote(alert.id, {
    ts: now,
    author: req.user.email,
    text: `Marked false positive — ${soc.FP_CATEGORIES[value.category]}. ${value.reason}`
  });

  engine.broadcast('alert-updated', updated);

  // Feed back what this means for the rule, so the analyst sees the effect of
  // the mark rather than it disappearing into a report nobody opens.
  const report = soc.tuningReport({ minimumAlerts: 1 });
  const forRule = report.rules.find((rule) => rule.ruleId === alert.ruleId) || null;

  res.json({
    data: updated,
    rule: forRule,
    message: forRule
      ? `${forRule.falsePositives} of ${forRule.total} alerts from this rule are now marked false positive (${forRule.falsePositiveRate}%).`
      : 'Recorded.'
  });
});

/** POST /api/alerts/:id/true-positive — undo a false-positive mark. */
router.post('/:id/true-positive', auth.requireAuth, (req, res) => {
  const alert = repo.alerts.byId(req.params.id);
  if (!alert) return res.status(404).json({ error: 'not_found', message: 'Alert not found.' });
  if (!alert.falsePositive) {
    return res.status(409).json({ error: 'not_marked', message: 'That alert is not marked as a false positive.' });
  }

  const now = new Date().toISOString();
  const updated = repo.alerts.update(alert.id, {
    falsePositive: false,
    fpCategory: null,
    fpReason: null,
    fpMarkedBy: null,
    fpMarkedAt: null,
    status: 'investigating',
    updatedAt: now
  });

  repo.alerts.addNote(alert.id, {
    ts: now,
    author: req.user.email,
    text: 'False-positive mark removed; reopened for investigation.'
  });

  engine.broadcast('alert-updated', updated);
  res.json({ data: updated });
});

/** GET /api/alerts/meta/filters — filter options for the console UI. */
router.get('/meta/filters', (_req, res) => {
  const options = repo.alerts.filterOptions();
  res.json({
    severities: ['critical', 'high', 'medium', 'low', 'info'],
    statuses: STATUSES,
    tactics: options.tactics,
    sources: options.sources,
    zones: options.zones
  });
});

module.exports = router;
