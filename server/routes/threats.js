'use strict';

const express = require('express');
const crypto = require('crypto');
const repo = require('../db/repository');
const engine = require('../lib/engine');
const {
  ACTORS,
  IOCS,
  VULNS,
  GEO_SOURCES,
  RULES,
  ASSETS
} = require('../lib/catalog');
const { rateLimit, cleanString } = require('../lib/security');

const router = express.Router();

/** GET /api/threats/actors — tracked threat-actor profiles. */
router.get('/actors', (req, res) => {
  const { motivation, trend, q } = req.query;
  let rows = ACTORS.slice();

  if (motivation) rows = rows.filter((a) => a.motivation.toLowerCase().includes(String(motivation).toLowerCase()));
  if (trend) rows = rows.filter((a) => a.trend === trend);
  if (q) {
    const needle = String(q).toLowerCase();
    rows = rows.filter((a) =>
      [a.name, a.id, a.summary, ...a.aliases, ...a.targets]
        .some((f) => String(f).toLowerCase().includes(needle))
    );
  }

  res.json({ data: rows, total: rows.length });
});

/** GET /api/threats/actors/:id */
router.get('/actors/:id', (req, res) => {
  const key = String(req.params.id).toLowerCase();
  const actor = ACTORS.find(
    (a) => a.id.toLowerCase() === key || a.name.toLowerCase() === key.replace(/-/g, ' ')
  );
  if (!actor) return res.status(404).json({ error: 'not_found', message: 'Actor not tracked.' });

  const indicators = IOCS.filter((i) => i.actor === actor.name);
  const detections = RULES.filter((r) => actor.techniques.includes(r.technique));

  res.json({ data: actor, indicators, detections });
});

/** GET /api/threats/iocs — searchable indicator feed. */
router.get('/iocs', (req, res) => {
  const { type, severity, actor, q } = req.query;
  const limit = Math.min(Number(req.query.limit) || 50, 200);

  let rows = IOCS.slice();
  if (type) rows = rows.filter((i) => i.type === type);
  if (severity) rows = rows.filter((i) => i.severity === severity);
  if (actor) rows = rows.filter((i) => i.actor.toLowerCase().includes(String(actor).toLowerCase()));
  if (q) {
    const needle = String(q).toLowerCase();
    rows = rows.filter((i) =>
      [i.indicator, i.description, i.actor, ...i.tags]
        .some((f) => String(f).toLowerCase().includes(needle))
    );
  }

  rows.sort((a, b) => b.confidence - a.confidence);
  res.json({ data: rows.slice(0, limit), total: rows.length });
});

/**
 * POST /api/threats/lookup — indicator reputation check.
 * Known indicators come from the curated feed. Unknown ones get a
 * deterministic heuristic verdict (same input always yields the same
 * result) rather than a random one, so the tool behaves consistently.
 */
router.post(
  '/lookup',
  rateLimit({ windowMs: 60_000, max: 30, key: 'lookup' }),
  (req, res) => {
    const raw = String(req.body?.indicator || '').trim();
    if (!raw) {
      return res.status(400).json({
        error: 'validation_failed',
        fields: { indicator: 'Enter an IP address, domain, hash or filename.' }
      });
    }
    if (raw.length > 200) {
      return res.status(400).json({
        error: 'validation_failed',
        fields: { indicator: 'Indicator is too long (max 200 characters).' }
      });
    }

    const indicator = cleanString(raw, 200);
    const type = classify(raw);

    const known = IOCS.find((i) => i.indicator.toLowerCase() === raw.toLowerCase());

    if (known) {
      return res.json({
        data: {
          indicator,
          type: known.type,
          verdict: 'malicious',
          confidence: known.confidence,
          severity: known.severity,
          actor: known.actor,
          tags: known.tags,
          firstSeen: known.firstSeen,
          description: known.description,
          sources: ['VGIL Threat Graph', 'Partner Feed', 'Honeypot Network'],
          relatedDetections: RULES.filter((r) =>
            known.tags.some((t) => r.tactic.toLowerCase().includes(t.split('-')[0]))
          )
            .slice(0, 3)
            .map((r) => ({ id: r.id, name: r.name, technique: r.technique }))
        },
        checkedAt: new Date().toISOString()
      });
    }

    // Deterministic pseudo-score derived from the indicator itself.
    const digest = crypto.createHash('sha256').update(raw.toLowerCase()).digest();
    const score = digest[0] % 100;

    let verdict = 'clean';
    let severity = 'info';
    if (score > 96) {
      verdict = 'malicious';
      severity = 'high';
    } else if (score > 88) {
      verdict = 'suspicious';
      severity = 'medium';
    }

    res.json({
      data: {
        indicator,
        type,
        verdict,
        confidence: verdict === 'clean' ? Math.max(60, 100 - score) : score,
        severity,
        actor: null,
        tags: verdict === 'clean' ? ['no-known-association'] : ['unclassified', 'low-prevalence'],
        firstSeen: null,
        description:
          verdict === 'clean'
            ? 'No association with tracked infrastructure, campaigns or malware families in the VGIL threat graph.'
            : 'Low-prevalence indicator with weak signals. Not confirmed malicious — corroborate before blocking.',
        sources: ['VGIL Threat Graph'],
        relatedDetections: []
      },
      checkedAt: new Date().toISOString()
    });
  }
);

function classify(value) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ipv4';
  if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
  if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
  if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return 'domain';
  if (/^https?:\/\//i.test(value)) return 'url';
  if (/\.[a-z0-9]{2,4}$/i.test(value)) return 'filename';
  return 'unknown';
}

/** GET /api/threats/vulnerabilities — CVE exposure across the estate. */
router.get('/vulnerabilities', (_req, res) => {
  // Was six hard-coded rows sorted by raw CVSS, with an "affected" count that
  // was a literal rather than anything counted. Now the real catalogue, with
  // blast radius counted from findings against the actual inventory, ordered
  // the way exposure management orders it.
  const catalogue = repo.vulnerabilities.list().map((vuln) => ({
    cve: vuln.cve,
    cvss: vuln.cvss,
    epss: vuln.epss,
    product: vuln.product,
    kev: vuln.kev,
    summary: vuln.summary,
    fixVersion: vuln.fixVersion,
    status: vuln.kev
      ? 'Exploited in the wild'
      : vuln.epss >= 0.5
        ? 'Exploitation likely'
        : 'Patch available',
    affected: repo.vulnFindings.countForCve(vuln.cve)
  }));

  res.json({
    data: catalogue,
    summary: {
      total: catalogue.length,
      kev: catalogue.filter((v) => v.kev).length,
      criticalCvss: catalogue.filter((v) => v.cvss >= 9).length,
      affectedAssets: catalogue.reduce((sum, v) => sum + v.affected, 0)
    }
  });
});

/** GET /api/threats/geo — attack-origin distribution. */
router.get('/geo', (_req, res) => {
  res.json({
    data: GEO_SOURCES,
    totalEvents: GEO_SOURCES.reduce((s, g) => s + g.events, 0),
    window: 'last 24 hours'
  });
});

/** GET /api/threats/rules — the published detection-rule catalog. */
router.get('/rules', (req, res) => {
  const { tactic, severity, q } = req.query;
  let rows = RULES.slice();

  if (tactic) rows = rows.filter((r) => r.tactic === tactic);
  if (severity) rows = rows.filter((r) => r.severity === severity);
  if (q) {
    const needle = String(q).toLowerCase();
    rows = rows.filter((r) =>
      [r.name, r.id, r.technique, r.techniqueName, r.description]
        .some((f) => String(f).toLowerCase().includes(needle))
    );
  }

  res.json({ data: rows, total: rows.length });
});

/**
 * GET /api/threats/attack-matrix — alert counts per ATT&CK tactic,
 * built from live detections rather than static numbers.
 */
router.get('/attack-matrix', (_req, res) => {
  // One grouped query instead of a full scan per rule.
  const hits = repo.alerts.countsByTechnique();
  const matrix = {};

  for (const rule of RULES) {
    if (!matrix[rule.tactic]) matrix[rule.tactic] = [];
    matrix[rule.tactic].push({
      technique: rule.technique,
      name: rule.techniqueName,
      ruleId: rule.id,
      severity: rule.severity,
      hits: hits.get(rule.technique) || 0
    });
  }

  res.json({ data: matrix, coverage: RULES.length, assets: ASSETS.length });
});

/**
 * POST /api/threats/posture-scan — lightweight external posture assessment
 * of a hostname. Checks are heuristic and deterministic; this is an
 * educational demo, not a substitute for a real external scan.
 */
router.post(
  '/posture-scan',
  rateLimit({ windowMs: 60_000, max: 10, key: 'scan' }),
  (req, res) => {
    const raw = String(req.body?.domain || '').trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');

    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(raw)) {
      return res.status(400).json({
        error: 'validation_failed',
        fields: { domain: 'Enter a valid domain, e.g. example.com' }
      });
    }

    const digest = crypto.createHash('sha256').update(raw).digest();
    const bit = (n) => (digest[n] % 100) > 30;

    const checks = [
      { id: 'tls', name: 'TLS configuration', detail: 'TLS 1.3 offered, weak ciphers disabled', weight: 15 },
      { id: 'hsts', name: 'HSTS enforced', detail: 'Strict-Transport-Security with a long max-age', weight: 10 },
      { id: 'csp', name: 'Content Security Policy', detail: 'CSP present and restrictive', weight: 12 },
      { id: 'spf', name: 'SPF record', detail: 'Sender policy published with a hard fail', weight: 10 },
      { id: 'dmarc', name: 'DMARC policy', detail: 'DMARC set to quarantine or reject', weight: 13 },
      { id: 'dnssec', name: 'DNSSEC', detail: 'Zone signed and validating', weight: 8 },
      { id: 'headers', name: 'Security headers', detail: 'X-Frame-Options and nosniff present', weight: 10 },
      { id: 'exposure', name: 'Exposed services', detail: 'No unexpected admin ports reachable', weight: 12 },
      { id: 'leaks', name: 'Credential exposure', detail: 'No corporate credentials in known breach sets', weight: 10 }
    ].map((c, i) => ({ ...c, pass: bit(i + 1) }));

    const earned = checks.reduce((s, c) => s + (c.pass ? c.weight : 0), 0);
    const possible = checks.reduce((s, c) => s + c.weight, 0);
    const score = Math.round((earned / possible) * 100);

    const grade =
      score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F';

    res.json({
      data: {
        domain: raw,
        score,
        grade,
        scannedAt: new Date().toISOString(),
        checks,
        passed: checks.filter((c) => c.pass).length,
        failed: checks.filter((c) => !c.pass).length,
        recommendations: checks
          .filter((c) => !c.pass)
          .map((c) => `Remediate: ${c.name} — ${c.detail}.`),
        disclaimer:
          'Heuristic demonstration assessment based on the supplied hostname. It does not send traffic to the target and is not a substitute for an authorised external assessment.'
      }
    });
  }
);

/** GET /api/threats/feed — condensed intel summary for the homepage ticker. */
router.get('/feed', (_req, res) => {
  const alerts = repo.alerts.recent(6);
  res.json({
    data: {
      headlines: [
        `${IOCS.filter((i) => i.severity === 'critical').length} critical indicators added in the last 24h`,
        `${VULNS.filter((v) => v.kev).length} CVEs on the known-exploited list affect monitored assets`,
        `${ACTORS.filter((a) => a.trend === 'rising').length} tracked actors showing rising activity`,
        `${engine.clientCount()} analysts connected to the live stream`
      ],
      latestAlerts: alerts.map((a) => ({
        id: a.id,
        ts: a.ts,
        severity: a.severity,
        rule: a.rule,
        host: a.host
      })),
      topActor: ACTORS.find((a) => a.trend === 'rising')?.name || null
    }
  });
});

module.exports = router;
