'use strict';

/**
 * Data export.
 *
 * Mounted on its own prefix rather than as `/api/incidents/export`, which
 * would have to be declared ahead of `/api/incidents/:id` to avoid being
 * swallowed by it — a footgun for whoever adds the next route.
 *
 * Unlike the public read endpoints these require a credential. A whole-table
 * pull is a different proposition from a paginated view: it is the shape of
 * request that precedes exfiltration, so it is attributable to a session or
 * an API key and lands in the audit log.
 */

const express = require('express');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const csv = require('../lib/csv');
const engine = require('../lib/engine');
const { rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

// Every route here requires a session token or an API key.
router.use(auth.requireAuthOrKey);

// Exports are heavy and rarely legitimate in bursts.
router.use(rateLimit({ windowMs: 60_000, max: 20, key: 'export' }));

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

/** Caps a pull so one request cannot drag the whole table into memory. */
const MAX_ROWS = 5000;

const INCIDENT_COLUMNS = [
  { key: 'id', label: 'Incident ID' },
  { key: 'title', label: 'Title' },
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' },
  { key: 'priority', label: 'Priority' },
  { key: 'host', label: 'Host' },
  { key: 'zone', label: 'Zone' },
  { key: 'technique', label: 'ATT&CK Technique' },
  { key: 'tactic', label: 'ATT&CK Tactic' },
  { key: 'analyst', label: 'Analyst' },
  { key: 'owner', label: 'Owner' },
  { key: 'openedAt', label: 'Opened' },
  { key: 'acknowledgedAt', label: 'Acknowledged' },
  { key: 'closedAt', label: 'Closed' },
  { key: 'summary', label: 'Summary' }
];

const ALERT_COLUMNS = [
  { key: 'id', label: 'Alert ID' },
  { key: 'ts', label: 'Timestamp' },
  { key: 'rule', label: 'Rule' },
  { key: 'severity', label: 'Severity' },
  { key: 'status', label: 'Status' },
  { key: 'tactic', label: 'ATT&CK Tactic' },
  { key: 'technique', label: 'ATT&CK Technique' },
  { key: 'host', label: 'Host' },
  { key: 'ip', label: 'Asset IP' },
  { key: 'zone', label: 'Zone' },
  { key: 'user', label: 'User' },
  { key: 'sourceIp', label: 'Source IP' },
  { key: 'destPort', label: 'Destination Port' },
  { key: 'risk', label: 'Risk' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'assignee', label: 'Assignee' },
  { key: 'incidentId', label: 'Incident' },
  { key: 'description', label: 'Description' }
];

const AUDIT_COLUMNS = [
  { key: 'id', label: 'Entry ID' },
  { key: 'ts', label: 'Timestamp' },
  { key: 'action', label: 'Action' },
  { key: 'detail', label: 'Detail' },
  { key: 'ip', label: 'IP' },
  { key: 'userAgent', label: 'User Agent' }
];

/**
 * Serves one dataset as CSV or JSON.
 * Query filters are the same ones the console's table view already accepts,
 * so "export what I am looking at" produces what the analyst expects.
 */
function serve(req, res, { kind, rows, columns }) {
  const format = String(req.query.format || 'csv').toLowerCase();

  audit(
    req,
    `export.${kind}`,
    `${req.user.email} exported ${rows.length} ${kind} row(s) as ${format}` +
      (req.apiKey ? ` via API key ${req.apiKey.prefix}…` : '')
  );

  if (format === 'json') {
    res.setHeader('Content-Disposition', `attachment; filename="${csv.filename(kind, 'json')}"`);
    res.setHeader('Cache-Control', 'no-store');
    return res.json({
      exportedAt: new Date().toISOString(),
      kind,
      count: rows.length,
      truncated: rows.length >= MAX_ROWS,
      rows
    });
  }

  if (format !== 'csv') {
    return res.status(400).json({
      error: 'unsupported_format',
      message: 'format must be csv or json.'
    });
  }

  return csv.attach(res, csv.filename(kind), csv.serialise(rows, columns));
}

/** GET /api/export/incidents — honours the same filters as the incidents table. */
router.get('/incidents', (req, res) => {
  const { rows } = repo.incidents.query({
    status: req.query.status,
    severity: req.query.severity,
    q: req.query.q,
    limit: MAX_ROWS,
    page: 1
  });
  serve(req, res, { kind: 'incidents', rows, columns: INCIDENT_COLUMNS });
});

/** GET /api/export/alerts — honours the same filters as the alert queue. */
router.get('/alerts', (req, res) => {
  const { rows } = repo.alerts.query({
    severity: req.query.severity,
    status: req.query.status,
    tactic: req.query.tactic,
    zone: req.query.zone,
    assignee: req.query.assignee,
    since: req.query.since,
    q: req.query.q,
    sort: req.query.sort,
    order: req.query.order,
    limit: MAX_ROWS,
    page: 1
  });
  serve(req, res, { kind: 'alerts', rows, columns: ALERT_COLUMNS });
});

/** GET /api/export/audit — administrators only; this is the compliance trail. */
router.get('/audit', auth.requireRole('admin'), (req, res) => {
  const rows = repo.audit.list(MAX_ROWS);
  serve(req, res, { kind: 'audit', rows, columns: AUDIT_COLUMNS });
});

/**
 * GET /api/export/all — the whole tenant as JSON.
 *
 * Administrators only, and never CSV: the payload is nested and would lose
 * its structure flattened into a single sheet.
 */
router.get('/all', auth.requireRole('admin'), (req, res) => {
  const payload = repo.admin.exportAll();
  audit(req, 'export.all', `${req.user.email} exported the full dataset`);

  res.setHeader('Content-Disposition', `attachment; filename="${csv.filename('export', 'json')}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.json(payload);
});

module.exports = router;
