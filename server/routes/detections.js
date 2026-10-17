'use strict';

/**
 * Custom detection engineering.
 *
 * A rule written here joins the same pool the built-in catalogue draws from,
 * so a customer detection is a first-class rule rather than a second tier —
 * it fires with the same weighting, produces the same alert shape, and its
 * response playbook shows on the alerts it generates.
 *
 * The built-in catalogue stays read-only. Editing shipped rules in place
 * makes it impossible to tell an upstream detection from a local change, and
 * there is no way back to the original once someone has overwritten it.
 */

const express = require('express');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const { RULES, ASSETS } = require('../lib/catalog');
const { validate, rateLimit, clientIp } = require('../lib/security');

const router = express.Router();

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const TACTICS = [
  'Reconnaissance',
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

/** Asset types a rule can be scoped to, taken from the live inventory. */
function assetTypes() {
  return Array.from(new Set(ASSETS.map((asset) => asset.type))).sort();
}

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

/* -------------------------------------------------------------- reading */

/**
 * GET /api/detections — built-in and custom rules together.
 *
 * `custom` marks which is which, so the console can show what is editable
 * without a second request.
 */
router.get('/', auth.optionalAuth, (req, res) => {
  const builtIn = RULES.map((rule) => ({ ...rule, enabled: true, custom: false }));
  const custom = repo.detectionRules.list();

  let rows = custom.concat(builtIn);

  if (req.query.custom === 'true') rows = rows.filter((r) => r.custom);
  if (req.query.severity) rows = rows.filter((r) => r.severity === req.query.severity);
  if (req.query.tactic) rows = rows.filter((r) => r.tactic === req.query.tactic);

  if (req.query.q) {
    const needle = String(req.query.q).toLowerCase();
    rows = rows.filter((rule) =>
      [rule.name, rule.id, rule.technique, rule.techniqueName, rule.description]
        .some((field) => String(field || '').toLowerCase().includes(needle))
    );
  }

  res.json({
    data: rows,
    total: rows.length,
    customCount: custom.length,
    builtInCount: builtIn.length,
    activeInPool: engine.weightedRules().length
  });
});

/** GET /api/detections/meta — the option lists the rule editor needs. */
router.get('/meta', (_req, res) => {
  res.json({
    severities: SEVERITIES,
    tactics: TACTICS,
    assetTypes: assetTypes(),
    sources: Array.from(new Set(RULES.map((rule) => rule.source))).sort()
  });
});

router.get('/:id', auth.optionalAuth, (req, res) => {
  const custom = repo.detectionRules.byId(req.params.id);
  if (custom) return res.json({ data: custom });

  const builtIn = RULES.find((rule) => rule.id === req.params.id);
  if (builtIn) return res.json({ data: { ...builtIn, enabled: true, custom: false } });

  res.status(404).json({ error: 'not_found', message: 'No such detection rule.' });
});

/* -------------------------------------------------------------- writing */

// Every write below needs a session.
const writeGuard = [auth.requireAuth, rateLimit({ windowMs: 60_000, max: 40, key: 'detections' })];

/** Shared validation for create and update. */
function validateRule(body, { partial = false } = {}) {
  const { ok, errors, value } = validate(body, {
    name: { required: !partial, minLength: 4, maxLength: 120, label: 'Rule name' },
    severity: { required: !partial, enum: SEVERITIES, label: 'Severity' },
    tactic: { required: false, enum: TACTICS, label: 'Tactic' },
    technique: { required: false, maxLength: 16, label: 'Technique' },
    techniqueName: { required: false, maxLength: 80, label: 'Technique name' },
    source: { required: false, maxLength: 60, label: 'Telemetry source' },
    description: { required: !partial, minLength: 10, maxLength: 400, label: 'Description' },
    response: { required: false, maxLength: 400, label: 'Response playbook' }
  });

  if (!ok) return { ok, errors, value };

  // ATT&CK identifiers are Txxxx, optionally with a .00x sub-technique.
  if (value.technique && !/^T\d{4}(\.\d{3})?$/.test(value.technique)) {
    return {
      ok: false,
      errors: { technique: 'Use an ATT&CK identifier such as T1110 or T1078.004.' },
      value
    };
  }

  const allowed = assetTypes();
  const requested = Array.isArray(body.assetTypes) ? body.assetTypes : [];
  const scoped = requested.filter((type) => allowed.includes(type));

  if (requested.length && !scoped.length) {
    return {
      ok: false,
      errors: { assetTypes: `Asset types must be from: ${allowed.join(', ')}` },
      value
    };
  }

  return { ok: true, errors: {}, value: { ...value, assetTypes: scoped } };
}

/** POST /api/detections — author a rule. */
router.post('/', writeGuard, (req, res) => {
  const { ok, errors, value } = validateRule(req.body);
  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  if (repo.detectionRules.list().length >= 100) {
    return res.status(409).json({
      error: 'too_many_rules',
      message: 'This tenant already has 100 custom rules. Remove one before adding another.'
    });
  }

  const rule = repo.detectionRules.insert({
    id: engine.id('CUS'),
    name: value.name,
    technique: value.technique,
    techniqueName: value.techniqueName,
    tactic: value.tactic,
    severity: value.severity,
    source: value.source || 'Custom',
    description: value.description,
    response: value.response,
    assetTypes: value.assetTypes,
    internalSource: Boolean(req.body.internalSource),
    enabled: req.body.enabled !== false,
    createdBy: req.user.email,
    createdAt: new Date().toISOString()
  });

  // The engine caches its weighted pool; without this the new rule would not
  // fire until the process restarted.
  const poolSize = engine.refreshRules();
  audit(req, 'detection.created', `${req.user.email} created "${rule.name}" (${rule.id})`);

  res.status(201).json({ data: rule, activeInPool: poolSize });
});

/** PATCH /api/detections/:id — edit, enable or disable a custom rule. */
router.patch('/:id', writeGuard, (req, res) => {
  const existing = repo.detectionRules.byId(req.params.id);
  if (!existing) {
    // Distinguish "does not exist" from "exists but is not yours to edit".
    if (RULES.some((rule) => rule.id === req.params.id)) {
      return res.status(403).json({
        error: 'built_in_rule',
        message:
          'Built-in rules cannot be edited. Disable it and author a custom rule if you need different logic.'
      });
    }
    return res.status(404).json({ error: 'not_found', message: 'No such detection rule.' });
  }

  const { ok, errors, value } = validateRule(req.body, { partial: true });
  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const patch = { ...value };
  if (!Array.isArray(req.body.assetTypes)) delete patch.assetTypes;
  if (req.body.enabled !== undefined) patch.enabled = Boolean(req.body.enabled);
  if (req.body.internalSource !== undefined) patch.internalSource = Boolean(req.body.internalSource);

  if (!Object.keys(patch).length) {
    return res.status(400).json({ error: 'nothing_to_update' });
  }

  const updated = repo.detectionRules.update(req.params.id, patch);
  const poolSize = engine.refreshRules();
  audit(req, 'detection.updated', `${req.user.email} updated ${updated.id}: ${Object.keys(patch).join(', ')}`);

  res.json({ data: updated, activeInPool: poolSize });
});

/** DELETE /api/detections/:id — remove a custom rule. */
router.delete('/:id', writeGuard, (req, res) => {
  const existing = repo.detectionRules.byId(req.params.id);
  if (!existing) {
    if (RULES.some((rule) => rule.id === req.params.id)) {
      return res.status(403).json({
        error: 'built_in_rule',
        message: 'Built-in rules cannot be deleted.'
      });
    }
    return res.status(404).json({ error: 'not_found', message: 'No such detection rule.' });
  }

  repo.detectionRules.remove(req.params.id);
  const poolSize = engine.refreshRules();
  audit(req, 'detection.deleted', `${req.user.email} deleted "${existing.name}" (${existing.id})`);

  res.json({ ok: true, removed: existing.id, activeInPool: poolSize });
});

/**
 * POST /api/detections/:id/preview — show what this rule would produce.
 *
 * Builds a sample alert without writing it, so an author can see the shape of
 * the detection before arming it.
 */
router.post('/:id/preview', auth.requireAuth, (req, res) => {
  const rule =
    repo.detectionRules.byId(req.params.id) || RULES.find((r) => r.id === req.params.id);

  if (!rule) return res.status(404).json({ error: 'not_found', message: 'No such detection rule.' });

  const sample = engine.buildAlert();

  res.json({
    data: {
      ...sample,
      id: 'ALT-PREVIEW',
      ruleId: rule.id,
      rule: rule.name,
      severity: rule.severity,
      tactic: rule.tactic,
      technique: rule.technique,
      techniqueName: rule.techniqueName,
      source: rule.source,
      description: rule.description,
      recommendation: rule.response
    },
    note: 'Preview only — this alert was not saved and does not appear in the queue.'
  });
});

module.exports = router;
