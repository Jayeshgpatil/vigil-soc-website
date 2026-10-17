'use strict';

/**
 * Vulnerability and exposure management.
 *
 * Findings are ranked by exposure — EPSS, known-exploited status, blast radius
 * and reachability — with CVSS as the smallest term. The ranking-comparison
 * endpoint exists so that claim can be checked rather than believed.
 */

const express = require('express');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const exposure = require('../lib/exposure');
const webhooks = require('../lib/webhooks');
const { validate, rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

const SURFACES = ['internal', 'external', 'cloud'];
const STATUSES = ['open', 'remediating', 'resolved', 'accepted', 'false_positive'];

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

/* --------------------------------------------------------------- reading */

/** GET /api/exposure — the prioritised remediation queue. */
router.get('/', (req, res) => {
  const findings = exposure.prioritised({
    limit: Math.min(Number(req.query.limit) || 50, 200),
    status: req.query.status || 'open',
    surface: SURFACES.includes(req.query.surface) ? req.query.surface : null
  });

  res.json({
    data: findings,
    total: findings.length,
    summary: exposure.summary(),
    ranking: {
      weights: exposure.WEIGHTS,
      basis:
        'Ranked by exposure: EPSS (probability of exploitation), known-exploited status, ' +
        'blast radius across your inventory, and reachability. CVSS contributes least — it ' +
        'describes impact if exploited, not whether anyone is doing so.'
    }
  });
});

/** GET /api/exposure/summary — headline counts for a dashboard tile. */
router.get('/summary', (_req, res) => {
  res.json({ data: exposure.summary() });
});

/**
 * GET /api/exposure/ranking — exposure order beside raw CVSS order.
 *
 * The services page claims prioritisation "rather than raw CVSS". This puts
 * both lists side by side so the difference is visible.
 */
router.get('/ranking', (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 5, 1), 20);
  const comparison = exposure.rankingComparison(limit);

  res.json({
    ...comparison,
    explanation:
      comparison.differing > 0
        ? `${comparison.differing} of the top ${limit} findings differ between the two orderings. ` +
          'Sorting by CVSS promotes severe vulnerabilities nobody is exploiting over ones under active attack.'
        : 'Both orderings agree on the top findings for the current inventory.'
  });
});

/** GET /api/exposure/catalogue — the CVE catalogue behind the findings. */
router.get('/catalogue', (_req, res) => {
  const data = repo.vulnerabilities.list().map((vuln) => ({
    ...vuln,
    // Blast radius counted from findings rather than stored on the CVE: the
    // same vulnerability affects different estates differently.
    affectedAssets: repo.vulnFindings.countForCve(vuln.cve)
  }));

  res.json({
    data,
    total: data.length,
    kev: data.filter((vuln) => vuln.kev).length
  });
});

/** GET /api/exposure/scans — discovery and verification history. */
router.get('/scans', (req, res) => {
  const data = repo.vulnScans.list(Math.min(Number(req.query.limit) || 20, 100));
  res.json({ data, total: data.length, latest: data[0] || null });
});

/** GET /api/exposure/:id — one finding with its full score breakdown. */
router.get('/:id', (req, res) => {
  const finding = repo.vulnFindings.byId(req.params.id);
  if (!finding) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });

  const detailed = exposure
    .prioritised({ limit: 1000, status: 'all' })
    .find((entry) => entry.id === finding.id);

  res.json({ data: detailed || finding });
});

/* --------------------------------------------------------------- writing */

const writeGuard = [auth.requireAuth, rateLimit({ windowMs: 60_000, max: 60, key: 'exposure' })];

/**
 * POST /api/exposure/scan — run discovery.
 *
 * Deterministic: an asset either matches a vulnerability's applicability or it
 * does not. A scanner returning different findings each run would make the
 * trend meaningless.
 */
router.post('/scan', writeGuard, (req, res) => {
  const surface = SURFACES.includes(req.body?.surface) ? req.body.surface : null;

  const result = exposure.runDiscovery({ surface, triggeredBy: req.user.email });

  audit(
    req,
    'exposure.scan',
    `${req.user.email} ran discovery on ${surface || 'all surfaces'} — ${result.created} new, ${result.seen} re-seen`
  );

  res.json({
    scan: result.scan,
    created: result.created,
    seen: result.seen,
    summary: exposure.summary(),
    message: result.created
      ? `${result.created} new finding(s) across ${result.scan.assetsScanned} asset(s).`
      : `No new findings. ${result.seen} existing finding(s) confirmed still present.`
  });
});

/** PATCH /api/exposure/:id — assign, change status, or reschedule. */
router.patch('/:id', writeGuard, (req, res) => {
  const finding = repo.vulnFindings.byId(req.params.id);
  if (!finding) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });

  const { ok, errors, value } = validate(req.body, {
    status: { required: false, enum: STATUSES, label: 'Status' },
    assignedTo: { required: false, maxLength: 80, label: 'Assignee' },
    dueAt: { required: false, maxLength: 40, label: 'Due date' },
    notes: { required: false, maxLength: 400, label: 'Notes' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const patch = {};
  if (value.assignedTo !== undefined) patch.assignedTo = value.assignedTo || req.user.email;
  if (value.notes !== undefined) patch.notes = value.notes;

  if (value.dueAt) {
    const parsed = new Date(value.dueAt);
    if (Number.isNaN(parsed.getTime())) {
      return res.status(400).json({ error: 'validation_failed', fields: { dueAt: 'Not a valid date.' } });
    }
    patch.dueAt = parsed.toISOString();
  }

  if (value.status) {
    // "resolved" is reserved for verification. Claiming a fix without a rescan
    // is how a vulnerability survives an audit trail that says it was patched.
    if (value.status === 'resolved') {
      return res.status(400).json({
        error: 'verification_required',
        message:
          'Mark it remediating, then run a verification rescan. A finding is only resolved once a scan confirms it is gone.'
      });
    }
    if (value.status === 'accepted') {
      return res.status(400).json({
        error: 'use_accept_endpoint',
        message: 'Accepting risk needs a justification and an expiry — use POST /api/exposure/:id/accept.'
      });
    }
    patch.status = value.status;
  }

  if (!Object.keys(patch).length) {
    return res.status(400).json({ error: 'nothing_to_update' });
  }

  const updated = repo.vulnFindings.update(finding.id, patch);
  repo.assets.refreshOpenFindings();
  audit(req, 'exposure.updated', `${req.user.email} updated ${finding.id}: ${Object.keys(patch).join(', ')}`);

  res.json({ data: updated });
});

/**
 * POST /api/exposure/:id/verify — verification rescan.
 *
 * `stillPresent` lets an operator record that the patch did not take, which
 * reopens the finding. That is the honest outcome, and the reason verification
 * exists as a separate step rather than a checkbox.
 */
router.post('/:id/verify', writeGuard, (req, res) => {
  const finding = repo.vulnFindings.byId(req.params.id);
  if (!finding) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });

  if (finding.status === 'accepted') {
    return res.status(409).json({
      error: 'risk_accepted',
      message: 'This finding has an accepted risk. Withdraw the acceptance before verifying.'
    });
  }

  const result = exposure.verifyRemediation(finding.id, {
    triggeredBy: req.user.email,
    stillPresent: Boolean(req.body?.stillPresent)
  });

  audit(
    req,
    result.verified ? 'exposure.verified' : 'exposure.verification_failed',
    `${req.user.email} verified ${finding.id} — ${result.verified ? 'resolved' : 'still present'}`
  );

  res.json({
    ...result,
    message: result.verified
      ? 'Verification rescan confirmed the vulnerability is gone. Finding resolved.'
      : 'Verification rescan still found it. The finding has been reopened.'
  });
});

/**
 * POST /api/exposure/:id/accept — accept the risk.
 *
 * An expiry is mandatory. An acceptance without one is a permanent exception
 * nobody revisits, which is how a known vulnerability quietly becomes part of
 * the furniture.
 */
router.post('/:id/accept', writeGuard, (req, res) => {
  const finding = repo.vulnFindings.byId(req.params.id);
  if (!finding) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });

  const reason = String(req.body?.reason || '').trim();
  if (reason.length < 20) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: {
        reason: 'Give a justification of at least 20 characters. This is the record an auditor will read.'
      }
    });
  }

  const days = Number(req.body?.days);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: { days: 'Set an expiry between 1 and 365 days. Acceptances must be revisited.' }
    });
  }

  const until = new Date(Date.now() + days * 86400_000).toISOString();

  const updated = repo.vulnFindings.update(finding.id, {
    status: 'accepted',
    acceptedBy: req.user.email,
    acceptedReason: reason.slice(0, 400),
    acceptedUntil: until
  });

  repo.assets.refreshOpenFindings();
  audit(req, 'exposure.accepted', `${req.user.email} accepted risk on ${finding.id} until ${until}`);

  res.json({
    data: updated,
    message: `Risk accepted until ${until.slice(0, 10)}. The finding returns to the queue when the acceptance lapses.`
  });
});

/** POST /api/exposure/:id/withdraw-acceptance — put it back in the queue. */
router.post('/:id/withdraw-acceptance', writeGuard, (req, res) => {
  const finding = repo.vulnFindings.byId(req.params.id);
  if (!finding) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });
  if (finding.status !== 'accepted') {
    return res.status(409).json({ error: 'not_accepted', message: 'That finding does not have an accepted risk.' });
  }

  const updated = repo.vulnFindings.update(finding.id, {
    status: 'open',
    acceptedBy: null,
    acceptedReason: null,
    acceptedUntil: null
  });

  repo.assets.refreshOpenFindings();
  audit(req, 'exposure.acceptance_withdrawn', `${req.user.email} withdrew acceptance on ${finding.id}`);

  res.json({ data: updated });
});

/**
 * POST /api/exposure/:id/escalate — open an incident for a finding.
 *
 * The bridge between exposure management and the incident queue: an
 * internet-facing, actively-exploited finding is not a patch ticket.
 */
router.post('/:id/escalate', writeGuard, (req, res) => {
  const detailed = exposure
    .prioritised({ limit: 1000, status: 'all' })
    .find((entry) => entry.id === req.params.id);

  if (!detailed) return res.status(404).json({ error: 'not_found', message: 'No such finding.' });

  const now = new Date().toISOString();
  const seq = repo.incidents.nextSequence();

  const incident = database.transaction(() =>
    repo.incidents.insert({
      id: `INC-${String(seq).padStart(4, '0')}`,
      title: `${detailed.cve} exposed on ${detailed.asset.host}`,
      severity: detailed.band === 'critical' ? 'critical' : detailed.band === 'high' ? 'high' : 'medium',
      status: 'open',
      priority: detailed.band === 'critical' ? 'P1' : detailed.band === 'high' ? 'P2' : 'P3',
      summary:
        `${detailed.vulnerability.title}. Exposure ${detailed.exposureScore}/100 — ` +
        `EPSS ${(detailed.vulnerability.epss * 100).toFixed(0)}%` +
        `${detailed.vulnerability.kev ? ', on the KEV list' : ''}, ` +
        `${detailed.blastRadius} asset(s) affected, ${detailed.surface} surface.`,
      host: detailed.asset.host,
      zone: detailed.asset.zone,
      assetId: detailed.asset.id,
      owner: req.user.org || 'Unassigned',
      analyst: req.user.email,
      openedAt: now,
      acknowledgedAt: now,
      closedAt: null,
      updatedAt: now,
      timeline: [
        {
          ts: now,
          actor: req.user.email,
          entry: `Escalated from exposure management. ${detailed.factors.map((f) => `${f.factor} +${f.points}`).join(', ')}.`
        }
      ]
    })
  );

  repo.vulnFindings.update(detailed.id, {
    status: 'remediating',
    assignedTo: detailed.assignedTo || req.user.email,
    notes: `Escalated to ${incident.id}.`
  });

  audit(req, 'exposure.escalated', `${req.user.email} escalated ${detailed.id} to ${incident.id}`);
  engine.broadcast('incident', incident);
  webhooks.dispatch('incident.opened', incident);

  res.status(201).json({ incident, finding: repo.vulnFindings.byId(detailed.id) });
});

module.exports = router;
