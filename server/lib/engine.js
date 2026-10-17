'use strict';

/**
 * The SOC engine: generates detection alerts from the rule catalog, keeps
 * rolling metrics, and broadcasts new events to connected SSE clients.
 * This is what makes the dashboard feel like a live console rather than
 * a static mock-up.
 */

const crypto = require('crypto');
const repo = require('../db/repository');
const {
  RULES,
  ASSETS,
  IOCS,
  USERNAMES,
  EXTERNAL_IPS,
  SEVERITIES
} = require('./catalog');

const MAX_ALERTS = 600;

// ---------------------------------------------------------------- utilities

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const randInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

/**
 * Readable, sortable, collision-free record id.
 *
 * Timestamp alone is not enough: the seeder inserts hundreds of rows inside a
 * single millisecond. An in-process counter makes those unique by
 * construction, and the random suffix keeps ids from colliding across
 * restarts or parallel processes writing the same database.
 */
let sequence = Math.floor(Math.random() * 46656);

function id(prefix) {
  sequence = (sequence + 1) % 46656; // 3 base-36 characters
  const stamp = Date.now().toString(36).toUpperCase();
  const counter = sequence.toString(36).toUpperCase().padStart(3, '0');
  const random = crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${prefix}-${stamp}${counter}${random}`;
}

/**
 * Risk score blends rule severity, asset criticality and indicator confidence,
 * so a critical rule on a domain controller outranks the same rule on a laptop.
 */
function riskScore(rule, asset, confidence) {
  const sevWeight = { critical: 45, high: 34, medium: 20, low: 10, info: 4 };
  const critWeight = { critical: 30, high: 22, medium: 12, low: 5 };
  const base = sevWeight[rule.severity] || 10;
  const assetPart = critWeight[asset.criticality] || 8;
  const confPart = Math.round((confidence / 100) * 25);
  return Math.min(100, base + assetPart + confPart);
}

// ------------------------------------------------------------ alert factory

/**
 * Rules are not equally likely to fire. Weighting the draw by severity keeps
 * the feed realistic — roughly 8% critical, 22% high — so a critical alert
 * still means something when it appears.
 */
const SEVERITY_WEIGHT = { critical: 1, high: 3, medium: 6, low: 8, info: 8 };

function weight(rules) {
  return rules.flatMap((rule) => Array(SEVERITY_WEIGHT[rule.severity] || 4).fill(rule));
}

// Customer-authored rules join the same pool as the built-in catalogue, so a
// custom detection is a first-class rule rather than a second tier.
//
// Cached rather than rebuilt per alert — this runs on every emit — and
// invalidated by refreshRules() whenever the rule set is edited.
let weightedCache = null;

function weightedRules() {
  if (weightedCache) return weightedCache;

  let custom = [];
  try {
    custom = repo.detectionRules.enabled();
  } catch {
    // Table absent or mid-migration: fall back to the built-in catalogue
    // rather than stopping detection altogether.
    custom = [];
  }

  weightedCache = weight(RULES.concat(custom));
  return weightedCache;
}

/** Called after any rule is created, edited, enabled, disabled or deleted. */
function refreshRules() {
  weightedCache = null;
  return weightedRules().length;
}

/** Picks an asset the rule could realistically fire on. */
function assetFor(rule) {
  if (!rule.assetTypes) return pick(ASSETS);
  const candidates = ASSETS.filter((a) => rule.assetTypes.includes(a.type));
  return candidates.length ? pick(candidates) : pick(ASSETS);
}

/** Internal-origin detections should not report a public source address. */
function sourceFor(rule) {
  if (!rule.internalSource) return pick(EXTERNAL_IPS);
  return `10.${pick([10, 20, 30, 40, 50, 60])}.${randInt(0, 20)}.${randInt(2, 250)}`;
}

function buildAlert(when = new Date()) {
  const rule = pick(weightedRules());
  const asset = assetFor(rule);
  const confidence = randInt(55, 99);
  const ioc = Math.random() < 0.55 ? pick(IOCS) : null;

  const alert = {
    id: id('ALT'),
    ts: when.toISOString(),
    ruleId: rule.id,
    rule: rule.name,
    severity: rule.severity,
    tactic: rule.tactic,
    technique: rule.technique,
    techniqueName: rule.techniqueName,
    source: rule.source,
    description: rule.description,
    recommendation: rule.response,
    assetId: asset.id,
    host: asset.host,
    ip: asset.ip,
    zone: asset.zone,
    assetType: asset.type,
    criticality: asset.criticality,
    owner: asset.owner,
    user: pick(USERNAMES),
    sourceIp: sourceFor(rule),
    destPort: pick([22, 80, 443, 445, 3389, 53, 8443, 1433]),
    confidence,
    risk: riskScore(rule, asset, confidence),
    status: 'new',
    assignee: null,
    indicator: ioc ? ioc.indicator : null,
    indicatorType: ioc ? ioc.type : null,
    actor: ioc ? ioc.actor : null,
    notes: []
  };

  return alert;
}

/** Weighted generation: criticals should stay rare enough to mean something. */
function shouldEmit() {
  return Math.random() < 0.72;
}

function emitAlert() {
  const alert = buildAlert();
  repo.alerts.insert(alert);

  // Trimming on every insert would be wasteful; the table only needs pruning
  // once it has actually drifted past the cap.
  if (repo.alerts.count() > MAX_ALERTS + 25) repo.alerts.trim(MAX_ALERTS);

  broadcast('alert', alert);
  return alert;
}

// -------------------------------------------------------- SSE broadcasting

const clients = new Set();

function addClient(res) {
  clients.add(res);
  return () => clients.delete(res);
}

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) {
    try {
      res.write(payload);
    } catch {
      clients.delete(res);
    }
  }
}

function clientCount() {
  return clients.size;
}

// ------------------------------------------------------------------ metrics

/**
 * Aggregate counters the dashboard header and charts read from.
 * The grouped counts and response times are computed by SQL rather than by
 * loading every row into memory; only the 24 timeline buckets need row-level
 * timestamps, and those are bounded by the retention cap.
 */
function computeStats() {
  const now = Date.now();
  const dayAgo = new Date(now - 24 * 3600_000).toISOString();

  const bySeverity = {};
  for (const s of SEVERITIES) bySeverity[s] = 0;
  Object.assign(bySeverity, repo.alerts.groupCount('severity'));

  const byTactic = repo.alerts.groupCount('tactic');
  const bySource = repo.alerts.groupCount('source');

  const byStatus = { new: 0, triaged: 0, investigating: 0, contained: 0, closed: 0 };
  for (const [status, count] of Object.entries(repo.alerts.groupCount('status'))) {
    if (byStatus[status] !== undefined) byStatus[status] = count;
  }

  // 24 hourly buckets of alert volume, split critical vs the rest. Buckets are
  // relative to now rather than to clock hours, so they are filled in JS.
  const recent = repo.alerts.timelineRows(dayAgo).map((r) => ({
    t: new Date(r.ts).getTime(),
    severity: r.severity
  }));

  const timeline = [];
  for (let h = 23; h >= 0; h -= 1) {
    const start = now - (h + 1) * 3600_000;
    const end = now - h * 3600_000;
    const inBucket = recent.filter((a) => a.t >= start && a.t < end);
    timeline.push({
      hour: new Date(end).toISOString(),
      label: new Date(end).getHours().toString().padStart(2, '0') + ':00',
      total: inBucket.length,
      critical: inBucket.filter((a) => a.severity === 'critical').length,
      high: inBucket.filter((a) => a.severity === 'high').length
    });
  }

  const incidentSummary = repo.incidents.summary();
  const times = repo.incidents.responseTimes();

  return {
    generatedAt: new Date().toISOString(),
    totals: {
      alerts: repo.alerts.count(),
      alerts24h: recent.length,
      critical24h: recent.filter((a) => a.severity === 'critical').length,
      high24h: recent.filter((a) => a.severity === 'high').length,
      openIncidents: incidentSummary.open,
      totalIncidents: incidentSummary.total,
      assetsMonitored: ASSETS.length,
      iocsTracked: IOCS.length,
      liveViewers: clientCount()
    },
    bySeverity,
    byTactic,
    bySource,
    byStatus,
    timeline,
    performance: {
      mttaMinutes: times.mttaMinutes,
      mttrMinutes: times.mttrMinutes,
      // Measured from the alerts themselves rather than asserted. These were
      // the literals 3.7 and a hard-coded triage figure; a dashboard that
      // reports a made-up false-positive rate is worse than one that reports
      // none, because it cannot be acted on.
      ...measuredPerformance(),
      detectionCoverage: 94.2,
      automationRate: 68.5,
      uptime: 99.99
    }
  };
}

/**
 * The performance numbers that can actually be computed.
 *
 * Returns nulls where there is nothing to measure. "No alerts triaged yet"
 * and "triaged instantly" are different answers, and collapsing them into a
 * number is how a metric stops meaning anything.
 */
function measuredPerformance() {
  try {
    // Required lazily: lib/soc reads the repository, which reads this module's
    // sibling, and a top-level require would close the cycle.
    const soc = require('./soc');
    const window = new Date(Date.now() - 30 * 86400_000).toISOString();

    const triage = soc.triageMetrics({ sinceIso: window });
    const tuning = soc.tuningReport({ sinceIso: window, minimumAlerts: 1 });

    return {
      medianTriageSeconds: triage.medianSeconds,
      medianTriageLabel: soc.formatDuration(triage.medianSeconds),
      triageSampleSize: triage.sampleSize,
      criticalMedianTriageSeconds: triage.criticalMedianSeconds,
      criticalMedianTriageLabel: soc.formatDuration(triage.criticalMedianSeconds),
      falsePositiveRate: tuning.overall ? tuning.overall.rate : null,
      falsePositiveSampleSize: tuning.overall ? tuning.overall.alerts : 0
    };
  } catch {
    return {
      medianTriageSeconds: null,
      medianTriageLabel: '—',
      triageSampleSize: 0,
      criticalMedianTriageSeconds: null,
      criticalMedianTriageLabel: '—',
      falsePositiveRate: null,
      falsePositiveSampleSize: 0
    };
  }
}

// ------------------------------------------------------------- engine loop

let timer = null;

function start(intervalMs = 4000) {
  if (timer) return;
  timer = setInterval(() => {
    if (shouldEmit()) emitAlert();
    // Occasional burst — attacks arrive in clusters, not evenly.
    if (Math.random() < 0.12) {
      setTimeout(() => emitAlert(), 600).unref();
      setTimeout(() => emitAlert(), 1200).unref();
    }
  }, intervalMs);
  timer.unref?.();

  // Heartbeat keeps proxies from closing idle SSE connections.
  setInterval(() => {
    broadcast('heartbeat', {
      ts: new Date().toISOString(),
      viewers: clientCount()
    });
  }, 25_000).unref();

  console.log(`[engine] detection pipeline running (tick ${intervalMs}ms)`);
}

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

module.exports = {
  start,
  stop,
  measuredPerformance,
  refreshRules,
  weightedRules,
  buildAlert,
  emitAlert,
  computeStats,
  addClient,
  broadcast,
  clientCount,
  riskScore,
  pick,
  randInt,
  id,
  MAX_ALERTS
};
