'use strict';

const express = require('express');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const webhooks = require('../lib/webhooks');
const notify = require('../lib/notify');
const { validate } = require('../lib/security');

const router = express.Router();

const STATUSES = ['open', 'triaged', 'investigating', 'contained', 'closed'];
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/** GET /api/incidents — list with filters and pagination. */
router.get('/', (req, res) => {
  const { rows, total, page, limit } = repo.incidents.query({
    status: req.query.status,
    severity: req.query.severity,
    q: req.query.q,
    page: req.query.page,
    limit: req.query.limit
  });

  const start = (page - 1) * limit;

  res.json({
    data: rows,
    summary: repo.incidents.summary(),
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

/** GET /api/incidents/:id */
router.get('/:id', (req, res) => {
  const incident = repo.incidents.byId(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: 'not_found', message: 'Incident not found.' });
  }

  res.json({
    data: incident,
    relatedAlerts: repo.incidents.relatedAlerts(incident.id, incident.sourceAlertId)
  });
});

/** POST /api/incidents — open an incident manually. */
router.post('/', auth.requireAuthOrKey, (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    title: { required: true, minLength: 6, maxLength: 160, label: 'Title' },
    severity: { required: true, enum: SEVERITIES, label: 'Severity' },
    summary: { required: true, minLength: 10, maxLength: 1000, label: 'Summary' },
    host: { required: false, maxLength: 80, label: 'Affected host', default: 'unspecified' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const now = new Date().toISOString();
  const seq = repo.incidents.nextSequence();

  const incident = repo.incidents.insert({
    id: `INC-${String(seq).padStart(4, '0')}`,
    title: value.title,
    severity: value.severity,
    status: 'open',
    priority: value.severity === 'critical' ? 'P1' : value.severity === 'high' ? 'P2' : 'P3',
    summary: value.summary,
    host: value.host,
    zone: 'unspecified',
    owner: req.user.org || 'Unassigned',
    analyst: req.user.email,
    openedAt: now,
    acknowledgedAt: now,
    closedAt: null,
    updatedAt: now,
    timeline: [{ ts: now, actor: req.user.email, entry: 'Incident opened manually.' }]
  });

  engine.broadcast('incident', incident);
  // Fire-and-forget: a slow subscriber must not delay this response.
  webhooks.dispatch('incident.opened', incident);
  notify.incidentOpened(incident, req.user.email);

  res.status(201).json({ data: incident });
});

/** PATCH /api/incidents/:id — update status, assignment, or append a note. */
router.patch('/:id', auth.requireAuthOrKey, (req, res) => {
  const incident = repo.incidents.byId(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: 'not_found', message: 'Incident not found.' });
  }

  const { ok, errors, value } = validate(req.body, {
    status: { required: false, enum: STATUSES, label: 'Status' },
    severity: { required: false, enum: SEVERITIES, label: 'Severity' },
    analyst: { required: false, maxLength: 80, label: 'Analyst' },
    note: { required: false, maxLength: 600, label: 'Note' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const now = new Date().toISOString();
  const patch = { updatedAt: now };

  if (value.severity) patch.severity = value.severity;
  if (value.analyst) patch.analyst = value.analyst;

  // The status change, its timeline entry and any note are one unit of work:
  // a half-applied update would leave the history inconsistent with the row.
  const updated = database.transaction(() => {
    if (value.status && value.status !== incident.status) {
      patch.status = value.status;
      patch.closedAt = value.status === 'closed' ? now : null;
      repo.incidents.addTimelineEntry(incident.id, {
        ts: now,
        actor: req.user.email,
        entry: `Status changed from ${incident.status} to ${value.status}.`
      });
    }

    if (value.note) {
      repo.incidents.addTimelineEntry(incident.id, {
        ts: now,
        actor: req.user.email,
        entry: value.note
      });
    }

    return repo.incidents.update(incident.id, patch);
  });

  engine.broadcast('incident-updated', updated);

  if (value.status && value.status !== incident.status) {
    webhooks.dispatch(
      value.status === 'closed' ? 'incident.closed' : 'incident.escalated',
      updated
    );
    notify.incidentStatusChanged(updated, incident.status, req.user.email);
  }

  res.json({ data: updated });
});

/** DELETE /api/incidents/:id — admin only, and never for seeded records. */
router.delete('/:id', auth.requireAuth, auth.requireRole('admin'), (req, res) => {
  const incident = repo.incidents.byId(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: 'not_found', message: 'Incident not found.' });
  }
  if (incident.seeded) {
    return res.status(403).json({
      error: 'protected_record',
      message: 'Seeded demo incidents cannot be deleted.'
    });
  }

  repo.incidents.remove(incident.id);
  res.json({ ok: true, deleted: req.params.id });
});

module.exports = router;
