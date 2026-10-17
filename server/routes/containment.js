'use strict';

/**
 * Containment action records.
 *
 * This records what an analyst did. It does not do it.
 *
 * That distinction is the whole design. There are no agents connected to this
 * platform, so an endpoint that reported "host isolated" would be asserting
 * something it has no way to know — the same reason device status is derived
 * from telemetry rather than set by whoever asks. What an incident actually
 * needs afterwards is a defensible account: what was contained, who decided,
 * under whose authority, when, and when it was lifted. That is what this is.
 *
 * If real containment integrations arrive later, they slot in as an execution
 * step that writes the same row — the evidence model does not change.
 */

const express = require('express');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const webhooks = require('../lib/webhooks');
const { validate, rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

/**
 * The containment types VGIL's runbooks cover, matching the service
 * description on the services page.
 */
const ACTIONS = {
  host_isolate: {
    label: 'Host isolation',
    targetLabel: 'Hostname',
    detail: 'Network access restricted to management traffic only.'
  },
  session_revoke: {
    label: 'Session revocation',
    targetLabel: 'Account',
    detail: 'Active sessions and refresh tokens invalidated.'
  },
  credential_reset: {
    label: 'Credential reset',
    targetLabel: 'Account',
    detail: 'Password rotated and the account forced to re-enrol.'
  },
  account_disable: {
    label: 'Account disabled',
    targetLabel: 'Account',
    detail: 'Sign-in blocked pending investigation.'
  },
  edge_block: {
    label: 'Edge block',
    targetLabel: 'Address or domain',
    detail: 'Blocked at the perimeter and on egress filtering.'
  },
  process_kill: {
    label: 'Process terminated',
    targetLabel: 'Process or PID',
    detail: 'Malicious process stopped and its binary quarantined.'
  }
};

router.use(auth.requireAuth);

function audit(req, action, detail) {
  repo.audit.insert({
    id: engine.id('AUD'),
    ts: new Date().toISOString(),
    action,
    detail,
    ip: clientIp(req),
    userAgent: (req.get('user-agent') || '').slice(0, 200)
  });
  repo.audit.trim(400);
}

/** GET /api/containment/actions — the catalogue the form is built from. */
router.get('/actions', (_req, res) => {
  res.json({
    data: Object.entries(ACTIONS).map(([id, meta]) => ({ id, ...meta })),
    note: 'Recording an action documents a containment decision. It does not execute anything.'
  });
});

/** GET /api/containment — recent records across all incidents. */
router.get('/', (req, res) => {
  const rows = repo.containment.list(Math.min(Number(req.query.limit) || 100, 500));
  res.json({
    data: rows,
    total: rows.length,
    active: rows.filter((row) => row.active).length
  });
});

/** GET /api/containment/incident/:id — records for one incident. */
router.get('/incident/:id', (req, res) => {
  const incident = repo.incidents.byId(req.params.id);
  if (!incident) {
    return res.status(404).json({ error: 'not_found', message: 'No such incident.' });
  }

  const rows = repo.containment.forIncident(incident.id);
  res.json({ data: rows, total: rows.length, active: rows.filter((r) => r.active).length });
});

/**
 * POST /api/containment — record a containment decision.
 *
 * The reason is mandatory. An action without one is useless as evidence: the
 * question asked afterwards is always "why", and reconstructing it from
 * memory weeks later is exactly what this table exists to avoid.
 */
router.post('/', rateLimit({ windowMs: 60_000, max: 30, key: 'containment' }), (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    incidentId: { required: true, maxLength: 40, label: 'Incident' },
    action: { required: true, enum: Object.keys(ACTIONS), label: 'Action' },
    target: { required: true, minLength: 1, maxLength: 120, label: 'Target' },
    scope: { required: false, maxLength: 200, label: 'Scope' },
    reason: { required: true, minLength: 8, maxLength: 400, label: 'Reason' },
    authorisedBy: { required: false, maxLength: 120, label: 'Authorised by' },
    alertId: { required: false, maxLength: 40, label: 'Alert' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const incident = repo.incidents.byId(value.incidentId);
  if (!incident) {
    return res.status(404).json({ error: 'not_found', message: 'No such incident.' });
  }
  if (incident.status === 'closed') {
    return res.status(409).json({
      error: 'incident_closed',
      message: 'Reopen the incident before recording further containment.'
    });
  }

  const now = new Date().toISOString();
  const meta = ACTIONS[value.action];

  // The record and its timeline entry are one unit of work: a containment
  // that is missing from the incident history is worse than one never logged,
  // because the history then looks complete and is not.
  const record = database.transaction(() => {
    const created = repo.containment.insert({
      id: engine.id('CNT'),
      incidentId: incident.id,
      alertId: value.alertId || null,
      action: value.action,
      target: value.target,
      scope: value.scope,
      reason: value.reason,
      authorisedBy: value.authorisedBy || req.user.email,
      performedBy: req.user.email,
      performedAt: now
    });

    repo.incidents.addTimelineEntry(incident.id, {
      ts: now,
      actor: req.user.email,
      entry: `Containment recorded — ${meta.label} on ${value.target}. ${value.reason}`
    });

    return created;
  });

  audit(
    req,
    'containment.recorded',
    `${req.user.email} recorded ${meta.label} on ${value.target} for ${incident.id}`
  );

  const refreshed = repo.incidents.byId(incident.id);
  engine.broadcast('incident-updated', refreshed);
  webhooks.dispatch('incident.escalated', refreshed);

  res.status(201).json({
    data: record,
    action: { id: value.action, ...meta },
    note: 'Recorded. This documents the decision; it does not perform the action.'
  });
});

/**
 * POST /api/containment/:id/revert — record that containment was lifted.
 *
 * Kept as an update rather than a delete: how long a host stayed isolated is
 * part of the incident record, and deleting the row would erase it.
 */
router.post('/:id/revert', (req, res) => {
  const record = repo.containment.byId(req.params.id);
  if (!record) {
    return res.status(404).json({ error: 'not_found', message: 'No such containment record.' });
  }
  if (!record.active) {
    return res.status(409).json({
      error: 'already_reverted',
      message: 'That containment was already lifted.'
    });
  }

  const reason = String(req.body?.reason || '').trim().slice(0, 400);
  if (reason.length < 8) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: { reason: 'Say why the containment is being lifted (at least 8 characters).' }
    });
  }

  const now = new Date().toISOString();
  const meta = ACTIONS[record.action] || { label: record.action };

  const lifted = database.transaction(() => {
    // Guarded inside the statement, so two analysts cannot both record the
    // reversal of the same action.
    if (!repo.containment.revert(record.id, { revertedBy: req.user.email, reason, now })) {
      return false;
    }

    if (record.incidentId) {
      repo.incidents.addTimelineEntry(record.incidentId, {
        ts: now,
        actor: req.user.email,
        entry: `Containment lifted — ${meta.label} on ${record.target}. ${reason}`
      });
    }
    return true;
  });

  if (!lifted) {
    return res.status(409).json({ error: 'already_reverted', message: 'That containment was already lifted.' });
  }

  audit(req, 'containment.reverted', `${req.user.email} lifted ${meta.label} on ${record.target}`);

  if (record.incidentId) {
    engine.broadcast('incident-updated', repo.incidents.byId(record.incidentId));
  }

  res.json({ data: repo.containment.byId(record.id) });
});

module.exports = router;
