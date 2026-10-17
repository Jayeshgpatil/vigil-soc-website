'use strict';

/**
 * SOC operations: the rota, the pods, the escalation bridge, and the numbers
 * the service claims rest on.
 *
 * The staffing is people. The rota that says whether 03:00 UTC is actually
 * covered, the measurement that says whether triage really is under a minute,
 * and the tuning report that turns analyst feedback into rule changes — those
 * are software, and this is it.
 */

const express = require('express');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const soc = require('../lib/soc');
const notify = require('../lib/notify');
const webhooks = require('../lib/webhooks');
const { validate, rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

const REGIONS = ['APAC', 'EMEA', 'AMER'];
const PRIORITIES = ['P1', 'P2', 'P3'];

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

/** Window for "recent" metrics. */
function since(req, defaultDays = 30) {
  const days = Math.min(Math.max(Number(req.query.days) || defaultDays, 1), 365);
  return new Date(Date.now() - days * 86400_000).toISOString();
}

/* ------------------------------------------------------------- overview */

/**
 * GET /api/soc/status — the rota right now.
 *
 * Public, because "is anybody watching" is the one thing a prospect most
 * wants to see demonstrated rather than asserted.
 */
router.get('/status', (_req, res) => {
  const state = soc.status();
  const openEscalations = (() => {
    try {
      return repo.escalations.openCount();
    } catch {
      return 0;
    }
  })();

  res.json({
    ...state,
    openEscalations,
    // Said plainly: an unconfigured rota is not the same as a covered one.
    claim: state.configured
      ? state.coverage.complete
        ? 'Every UTC hour is covered by an active shift.'
        : `Coverage is incomplete — ${state.coverage.gapRanges.join(', ')} has no active shift.`
      : 'No shifts configured, so no coverage can be claimed.'
  });
});

/**
 * GET /api/soc/metrics — measured performance.
 *
 * Every number here is computed from the rows. Nulls are returned where there
 * is nothing to measure, because "no data" and "instant" are different
 * answers.
 */
router.get('/metrics', (req, res) => {
  const window = since(req);
  const triage = soc.triageMetrics({ sinceIso: window });

  let acknowledgement = { sampleSize: 0, medianSeconds: null };
  try {
    const durations = repo.escalations.acknowledgeDurations(window).map((row) => row.seconds);
    acknowledgement = {
      sampleSize: durations.length,
      medianSeconds: soc.median(durations)
    };
  } catch {
    /* table absent */
  }

  const tuning = soc.tuningReport({ sinceIso: window });

  res.json({
    window,
    triage: {
      ...triage,
      medianLabel: soc.formatDuration(triage.medianSeconds),
      p90Label: soc.formatDuration(triage.p90Seconds),
      criticalMedianLabel: soc.formatDuration(triage.criticalMedianSeconds)
    },
    escalation: {
      ...acknowledgement,
      medianLabel: soc.formatDuration(acknowledgement.medianSeconds),
      open: repo.escalations.openCount()
    },
    falsePositives: tuning.overall,
    note:
      triage.sampleSize === 0
        ? 'No alerts have been triaged in this window, so there is no median to report.'
        : `Median computed from ${triage.sampleSize} triaged alert(s).`
  });
});

/**
 * GET /api/soc/tuning — per-rule false-positive analysis.
 *
 * This is what "monthly tuning against your own false-positive data" has to
 * mean in software: rules ranked by how much of their output analysts marked
 * wrong, with the reason they gave and a concrete suggestion.
 */
router.get('/tuning', auth.requireAuthOrKey, (req, res) => {
  const report = soc.tuningReport({
    sinceIso: since(req),
    minimumAlerts: Math.max(Number(req.query.minimum) || 3, 1)
  });

  res.json({
    ...report,
    categories: soc.FP_CATEGORIES,
    summary: report.rules.length
      ? `${report.rules.length} rule(s) worth tuning. ${report.overall.falsePositives} of ${report.overall.alerts} alerts were marked false positive (${report.overall.rate}%).`
      : 'No rule has enough marked false positives to recommend a change yet.'
  });
});

/* ---------------------------------------------------------------- rota */

router.get('/shifts', (_req, res) => {
  const shifts = repo.socShifts.list();
  const cover = soc.coverage(shifts);
  res.json({
    data: shifts,
    total: shifts.length,
    regions: REGIONS,
    coverage: {
      complete: cover.complete,
      gaps: cover.gaps,
      gapRanges: soc.describeGaps(cover.gaps)
    }
  });
});

const adminOnly = [auth.requireAuth, auth.requireRole('admin')];

/** POST /api/soc/shifts — add a window to the rota. */
router.post('/shifts', adminOnly, (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    region: { required: true, enum: REGIONS, label: 'Region' },
    label: { required: true, minLength: 2, maxLength: 60, label: 'Shift label' },
    startHour: { required: true, type: 'number', min: 0, max: 23, label: 'Start hour' },
    endHour: { required: true, type: 'number', min: 0, max: 23, label: 'End hour' },
    podId: { required: false, maxLength: 40, label: 'Pod' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  if (value.podId && !repo.pods.byId(value.podId)) {
    return res.status(400).json({ error: 'validation_failed', fields: { podId: 'No such pod.' } });
  }

  const shift = repo.socShifts.insert({
    id: engine.id('SHF'),
    region: value.region,
    label: value.label,
    podId: value.podId || null,
    startHour: value.startHour,
    endHour: value.endHour,
    createdAt: new Date().toISOString()
  });

  audit(req, 'soc.shift.created', `${req.user.email} added ${value.label} (${value.region})`);

  const cover = soc.coverage(repo.socShifts.list());
  res.status(201).json({
    data: shift,
    coverage: { complete: cover.complete, gapRanges: soc.describeGaps(cover.gaps) }
  });
});

router.patch('/shifts/:id', adminOnly, (req, res) => {
  if (!repo.socShifts.byId(req.params.id)) {
    return res.status(404).json({ error: 'not_found', message: 'No such shift.' });
  }

  const patch = {};
  if (req.body.label !== undefined) patch.label = String(req.body.label).slice(0, 60);
  if (req.body.region !== undefined) {
    if (!REGIONS.includes(req.body.region)) {
      return res.status(400).json({ error: 'validation_failed', fields: { region: `One of: ${REGIONS.join(', ')}` } });
    }
    patch.region = req.body.region;
  }
  for (const field of ['startHour', 'endHour']) {
    if (req.body[field] === undefined) continue;
    const hour = Number(req.body[field]);
    if (!Number.isInteger(hour) || hour < 0 || hour > 23) {
      return res.status(400).json({ error: 'validation_failed', fields: { [field]: 'Use a UTC hour from 0 to 23.' } });
    }
    patch[field] = hour;
  }
  if (req.body.active !== undefined) patch.active = Boolean(req.body.active);
  if (req.body.podId !== undefined) patch.podId = req.body.podId || null;

  if (!Object.keys(patch).length) {
    return res.status(400).json({ error: 'nothing_to_update' });
  }

  const updated = repo.socShifts.update(req.params.id, patch);
  audit(req, 'soc.shift.updated', `${req.user.email} updated ${updated.label}`);

  const cover = soc.coverage(repo.socShifts.list());
  res.json({
    data: updated,
    coverage: { complete: cover.complete, gapRanges: soc.describeGaps(cover.gaps) }
  });
});

router.delete('/shifts/:id', adminOnly, (req, res) => {
  const shift = repo.socShifts.byId(req.params.id);
  if (!shift) return res.status(404).json({ error: 'not_found', message: 'No such shift.' });

  repo.socShifts.remove(req.params.id);
  audit(req, 'soc.shift.deleted', `${req.user.email} removed ${shift.label}`);

  const cover = soc.coverage(repo.socShifts.list());
  res.json({
    ok: true,
    // Removing a shift is the most likely way to open a gap, so say so now
    // rather than letting somebody discover it at 03:00.
    coverage: { complete: cover.complete, gapRanges: soc.describeGaps(cover.gaps) },
    warning: cover.complete ? null : `Coverage now has a gap: ${soc.describeGaps(cover.gaps).join(', ')}`
  });
});

/* ---------------------------------------------------------------- pods */

router.get('/pods', (_req, res) => {
  const data = repo.pods.list();
  res.json({ data, total: data.length, regions: REGIONS });
});

router.post('/pods', adminOnly, (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    name: { required: true, minLength: 2, maxLength: 60, label: 'Pod name' },
    region: { required: true, enum: REGIONS, label: 'Region' },
    description: { required: false, maxLength: 200, label: 'Description' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const pod = repo.pods.insert({
    id: engine.id('POD'),
    name: value.name,
    region: value.region,
    description: value.description,
    createdAt: new Date().toISOString()
  });

  audit(req, 'soc.pod.created', `${req.user.email} created pod ${value.name}`);
  res.status(201).json({ data: pod });
});

/** POST /api/soc/pods/:id/members — assign an analyst to a tier. */
router.post('/pods/:id/members', adminOnly, (req, res) => {
  const pod = repo.pods.byId(req.params.id);
  if (!pod) return res.status(404).json({ error: 'not_found', message: 'No such pod.' });

  const { ok, errors, value } = validate(req.body, {
    userId: { required: true, maxLength: 40, label: 'Analyst' },
    tier: { required: true, type: 'number', min: 1, max: 3, label: 'Tier' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const user = repo.users.byId(value.userId);
  if (!user) {
    return res.status(400).json({ error: 'validation_failed', fields: { userId: 'No such user.' } });
  }

  const members = repo.pods.addMember(pod.id, user.id, value.tier);
  audit(req, 'soc.pod.member_added', `${req.user.email} added ${user.email} to ${pod.name} at tier ${value.tier}`);

  res.status(201).json({ data: members });
});

router.delete('/pods/:id/members/:userId', adminOnly, (req, res) => {
  if (!repo.pods.removeMember(req.params.id, req.params.userId)) {
    return res.status(404).json({ error: 'not_found', message: 'That analyst is not in this pod.' });
  }
  audit(req, 'soc.pod.member_removed', `${req.user.email} removed ${req.params.userId}`);
  res.json({ ok: true, data: repo.pods.members(req.params.id) });
});

router.delete('/pods/:id', adminOnly, (req, res) => {
  const pod = repo.pods.byId(req.params.id);
  if (!pod) return res.status(404).json({ error: 'not_found', message: 'No such pod.' });

  repo.pods.remove(req.params.id);
  audit(req, 'soc.pod.deleted', `${req.user.email} deleted pod ${pod.name}`);
  res.json({ ok: true });
});

/* ----------------------------------------------------------- handovers */

router.get('/handovers', auth.requireAuth, (req, res) => {
  const data = repo.handovers.list(Math.min(Number(req.query.limit) || 25, 100));
  res.json({ data, total: data.length, latest: data[0] || null });
});

/**
 * POST /api/soc/handovers — hand the console to the next shift.
 *
 * The open incidents are snapshotted rather than recomputed later, because
 * the point of a handover record is what the outgoing analyst actually saw
 * and said about it.
 */
router.post('/handovers', auth.requireAuth, (req, res) => {
  const notes = String(req.body?.notes || '').trim();
  if (notes.length < 10) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: { notes: 'Write a handover note of at least 10 characters. "Nothing to report" is a valid note; an empty one is not.' }
    });
  }

  const state = soc.status();
  const open = repo.incidents.query({ status: 'open', limit: 50, page: 1 }).rows.map((incident) => ({
    id: incident.id,
    title: incident.title,
    severity: incident.severity,
    status: incident.status,
    analyst: incident.analyst
  }));

  const record = repo.handovers.insert({
    id: engine.id('HND'),
    fromShift: state.onDuty[0] ? state.onDuty[0].id : null,
    fromRegion: state.onDuty[0] ? state.onDuty[0].region : null,
    toShift: state.nextHandover && state.nextHandover.incoming[0] ? state.nextHandover.incoming[0].id : null,
    toRegion: state.nextHandover && state.nextHandover.incoming[0] ? state.nextHandover.incoming[0].region : null,
    notes: notes.slice(0, 2000),
    openIncidents: open,
    createdBy: req.user.email,
    createdAt: new Date().toISOString()
  });

  audit(req, 'soc.handover', `${req.user.email} handed over with ${open.length} open incident(s)`);
  engine.broadcast('handover', record);

  res.status(201).json({ data: record });
});

/* --------------------------------------------------------- escalations */

router.get('/escalations', auth.requireAuth, (req, res) => {
  const data = repo.escalations.list(Math.min(Number(req.query.limit) || 50, 200));
  res.json({
    data,
    total: data.length,
    open: data.filter((row) => !row.resolvedAt).length,
    unacknowledged: data.filter((row) => !row.acknowledgedAt).length
  });
});

/**
 * POST /api/soc/escalations — raise the bridge.
 *
 * This is the "no ticket queue for P1" path. It notifies subscribers
 * immediately regardless of digest settings, because a P1 that waits for the
 * daily digest is the exact failure the claim promises not to have.
 */
router.post('/escalations', auth.requireAuth, rateLimit({ windowMs: 60_000, max: 20, key: 'escalate' }), (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    incidentId: { required: true, maxLength: 40, label: 'Incident' },
    priority: { required: true, enum: PRIORITIES, label: 'Priority' },
    reason: { required: true, minLength: 10, maxLength: 400, label: 'Reason' },
    bridgeRef: { required: false, maxLength: 120, label: 'Bridge reference' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const incident = repo.incidents.byId(value.incidentId);
  if (!incident) return res.status(404).json({ error: 'not_found', message: 'No such incident.' });

  const now = new Date().toISOString();

  const record = database.transaction(() => {
    const created = repo.escalations.insert({
      id: engine.id('ESC'),
      incidentId: incident.id,
      priority: value.priority,
      reason: value.reason,
      bridgeRef: value.bridgeRef,
      raisedBy: req.user.email,
      raisedAt: now
    });

    repo.incidents.addTimelineEntry(incident.id, {
      ts: now,
      actor: req.user.email,
      entry: `Escalated ${value.priority} — ${value.reason}${value.bridgeRef ? ` (bridge: ${value.bridgeRef})` : ''}`
    });

    return created;
  });

  audit(req, 'soc.escalation.raised', `${req.user.email} raised ${value.priority} on ${incident.id}`);

  const refreshed = repo.incidents.byId(incident.id);
  engine.broadcast('escalation', record);
  webhooks.dispatch('incident.escalated', refreshed);

  // Severity is forced to critical for a P1 so it bypasses every digest and
  // quiet-hours setting on the way out.
  notify.dispatch({
    kind: 'incident',
    severity: value.priority === 'P1' ? 'critical' : incident.severity,
    actorEmail: req.user.email,
    title: `${value.priority} escalation — ${incident.id}`,
    subject: `[VGIL ${value.priority}] ${incident.id} escalated — ${incident.title}`,
    summary: value.reason,
    path: `/incidents.html?id=${encodeURIComponent(incident.id)}`,
    details: [
      ['Incident', incident.id],
      ['Priority', value.priority],
      ['Raised by', req.user.email],
      ['Bridge', value.bridgeRef || 'not yet opened'],
      ['Asset', incident.host || '—']
    ]
  });

  res.status(201).json({
    data: record,
    onDuty: soc.status().onDuty,
    note: 'Escalation recorded and subscribers notified immediately, bypassing digest and quiet-hours settings.'
  });
});

/** POST /api/soc/escalations/:id/acknowledge — somebody has the bridge. */
router.post('/escalations/:id/acknowledge', auth.requireAuth, (req, res) => {
  const record = repo.escalations.byId(req.params.id);
  if (!record) return res.status(404).json({ error: 'not_found', message: 'No such escalation.' });

  if (!repo.escalations.acknowledge(record.id, { by: req.user.email })) {
    return res.status(409).json({
      error: 'already_acknowledged',
      message: `Already acknowledged by ${record.acknowledgedBy}.`
    });
  }

  const updated = repo.escalations.byId(record.id);
  audit(req, 'soc.escalation.acknowledged', `${req.user.email} took ${record.id} in ${updated.acknowledgeSeconds}s`);

  if (record.incidentId) {
    repo.incidents.addTimelineEntry(record.incidentId, {
      ts: new Date().toISOString(),
      actor: req.user.email,
      entry: `Escalation acknowledged after ${soc.formatDuration(updated.acknowledgeSeconds)}.`
    });
  }

  res.json({ data: updated });
});

router.post('/escalations/:id/resolve', auth.requireAuth, (req, res) => {
  const record = repo.escalations.byId(req.params.id);
  if (!record) return res.status(404).json({ error: 'not_found', message: 'No such escalation.' });

  const resolution = String(req.body?.resolution || '').trim();
  if (resolution.length < 10) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: { resolution: 'Say how it was resolved, in at least 10 characters.' }
    });
  }

  if (!repo.escalations.resolve(record.id, { resolution: resolution.slice(0, 400) })) {
    return res.status(409).json({ error: 'already_resolved', message: 'That escalation is already closed.' });
  }

  audit(req, 'soc.escalation.resolved', `${req.user.email} resolved ${record.id}`);
  res.json({ data: repo.escalations.byId(record.id) });
});

module.exports = router;
