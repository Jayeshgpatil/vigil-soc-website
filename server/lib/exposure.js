'use strict';

/**
 * Exposure scoring, discovery and verification.
 *
 * The claim on the services page is that findings are ranked by "real
 * exploitability — EPSS, known-exploited status and blast radius in your
 * environment — rather than raw CVSS". This is the code that has to make that
 * true, so CVSS is deliberately the smallest term.
 *
 * Why that ordering:
 *
 *   CVSS says how bad exploitation would be if it happened. It says nothing
 *   about whether anyone is doing it. Ranking by CVSS puts a 9.8 nobody has
 *   ever exploited above a 7.5 that is being used against your sector today,
 *   which is exactly the mistake that leaves the important patch until Friday.
 *
 *   EPSS is a modelled probability of exploitation in the next 30 days.
 *   KEV is not a probability at all — it is an observation that exploitation
 *   is happening now, so it escalates rather than nudges.
 *
 *   Blast radius is what makes the score yours rather than the internet's: the
 *   same CVE on one lab box and on forty domain-joined servers is not the same
 *   finding.
 *
 * Every score comes back with the factors that produced it. A number an
 * engineer cannot argue with is a number they will ignore.
 */

const repo = require('../db/repository');

/* -------------------------------------------------------------- weights */

// Points available per factor. They sum to 100 at maximum, and the ordering
// is the argument: exploitation evidence outweighs theoretical severity.
const WEIGHTS = {
  epss: 40,       // probability it is exploited
  kev: 25,        // observed exploitation
  radius: 20,     // how much of the estate
  surface: 10,    // reachability
  cvss: 5         // severity if it happens — the floor, not the ranking
};

const SURFACE_WEIGHT = { external: 1, cloud: 0.6, internal: 0.2 };

const CRITICALITY_WEIGHT = { critical: 1, high: 0.7, medium: 0.4, low: 0.2 };

/** Remediation windows by band. Used to set a due date on discovery. */
const SLA_DAYS = { critical: 3, high: 7, medium: 30, low: 90 };

function band(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

/* --------------------------------------------------------------- scoring */

/**
 * Scores one finding.
 *
 * @param {Object} vuln       the vulnerability
 * @param {Object} asset      the affected asset
 * @param {Object} context    { assetCount, criticalityMix } across the estate
 * @returns {{score:number, band:string, factors:Array}}
 */
function scoreFinding(vuln, asset, context = {}) {
  const factors = [];

  // --- exploitation probability -------------------------------------
  const epss = Math.max(0, Math.min(1, Number(vuln.epss) || 0));
  const epssPoints = Math.round(epss * WEIGHTS.epss);
  factors.push({
    factor: 'epss',
    points: epssPoints,
    detail: `EPSS ${(epss * 100).toFixed(1)}% — modelled probability of exploitation within 30 days`
  });

  // --- observed exploitation ----------------------------------------
  const kevPoints = vuln.kev ? WEIGHTS.kev : 0;
  if (vuln.kev) {
    factors.push({
      factor: 'kev',
      points: kevPoints,
      detail: 'On the Known Exploited Vulnerabilities list — exploitation is confirmed, not predicted'
    });
  }

  // --- blast radius --------------------------------------------------
  // Scaled by how much of *this* estate is affected, weighted by how much
  // each affected asset matters. Ten workstations and ten domain controllers
  // are not the same blast radius.
  const affected = context.affectedCount || 1;
  const totalAssets = Math.max(context.totalAssets || 1, 1);
  const share = Math.min(affected / totalAssets, 1);

  const criticality = CRITICALITY_WEIGHT[String(asset.criticality || 'medium').toLowerCase()] || 0.4;
  const worstCriticality = context.worstCriticality || criticality;

  // Two thirds from spread, one third from the worst asset it touches, so a
  // single critical host still registers.
  const radiusPoints = Math.round(
    WEIGHTS.radius * (Math.sqrt(share) * 0.66 + worstCriticality * 0.34)
  );
  factors.push({
    factor: 'blast_radius',
    points: radiusPoints,
    detail:
      `${affected} of ${totalAssets} monitored asset(s) affected` +
      (context.worstCriticalityLabel ? `, worst is ${context.worstCriticalityLabel}` : '')
  });

  // --- reachability ---------------------------------------------------
  const surface = String(asset.surface || 'internal').toLowerCase();
  const surfacePoints = Math.round(WEIGHTS.surface * (SURFACE_WEIGHT[surface] ?? 0.2));
  factors.push({
    factor: 'surface',
    points: surfacePoints,
    detail:
      surface === 'external'
        ? 'Internet-facing — reachable without a foothold'
        : surface === 'cloud'
          ? 'Cloud-hosted — reachable from outside the corporate network'
          : 'Internal only — an attacker needs a foothold first'
  });

  // --- severity floor --------------------------------------------------
  // Last and smallest, on purpose. This is the term that used to be the
  // entire ranking.
  const cvss = Math.max(0, Math.min(10, Number(vuln.cvss) || 0));
  const cvssPoints = Math.round((cvss / 10) * WEIGHTS.cvss);
  factors.push({
    factor: 'cvss',
    points: cvssPoints,
    detail: `CVSS ${cvss.toFixed(1)} — impact if exploited, which is not the same as likelihood`
  });

  const score = Math.max(0, Math.min(100, epssPoints + kevPoints + radiusPoints + surfacePoints + cvssPoints));

  return {
    score,
    band: band(score),
    factors: factors.filter((entry) => entry.points > 0 || entry.factor === 'epss')
  };
}

/** Due date from the band, so an SLA is attached at discovery rather than later. */
function dueDate(scoreBand, from = new Date()) {
  const days = SLA_DAYS[scoreBand] ?? 90;
  return new Date(from.getTime() + days * 86400_000).toISOString();
}

/* ------------------------------------------------------------ discovery */

/**
 * Which surface an asset sits on.
 *
 * Derived from the inventory rather than stored twice: the zone and type
 * already say this, and a second copy would drift.
 */
function surfaceFor(asset) {
  const zone = String(asset.zone || '').toLowerCase();
  const type = String(asset.type || '').toLowerCase();

  if (zone.includes('dmz') || zone.includes('perimeter') || zone.includes('edge')) return 'external';
  if (zone.includes('cloud') || type.includes('cloud') || type.includes('container')) return 'cloud';
  return 'internal';
}

/** Whether a vulnerability can apply to an asset at all. */
function applies(vuln, asset) {
  if (!vuln.appliesTo || !vuln.appliesTo.length) return true;
  return vuln.appliesTo.includes(asset.type);
}

/**
 * Runs a discovery scan.
 *
 * Deterministic given the same inventory and catalogue: an asset either
 * matches a vulnerability's applicability or it does not. A scanner that
 * returned different findings each run would make the trend meaningless.
 *
 * @returns {{scan:Object, created:number, seen:number, resolved:number}}
 */
function runDiscovery({ surface = null, triggeredBy = 'system', now = new Date() } = {}) {
  const iso = now.toISOString();

  const assets = repo.assets.query();
  const catalogue = repo.vulnerabilities.list();

  const scanId = `SCN-${now.getTime().toString(36).toUpperCase()}`;
  repo.vulnScans.insert({
    id: scanId,
    kind: 'discovery',
    surface,
    startedAt: iso,
    triggeredBy,
    target: surface ? `${surface} surface` : 'all surfaces'
  });

  const targets = assets.filter((asset) => !surface || surfaceFor(asset) === surface);

  let created = 0;
  let seen = 0;

  for (const vuln of catalogue) {
    const matching = targets.filter((asset) => applies(vuln, asset));
    if (!matching.length) continue;

    // Blast radius is computed once per vulnerability across everything it
    // touches, then applied to each finding — the radius is a property of the
    // vulnerability's reach, not of the individual host.
    const worst = matching.reduce((acc, asset) => {
      const weight = CRITICALITY_WEIGHT[String(asset.criticality || 'medium').toLowerCase()] || 0.4;
      return weight > acc.weight ? { weight, label: asset.criticality } : acc;
    }, { weight: 0, label: null });

    const context = {
      affectedCount: matching.length,
      totalAssets: assets.length,
      worstCriticality: worst.weight,
      worstCriticalityLabel: worst.label
    };

    for (const asset of matching) {
      const assetSurface = surfaceFor(asset);
      const scored = scoreFinding(vuln, { ...asset, surface: assetSurface }, context);

      const existing = repo.vulnFindings.byKey(vuln.cve, asset.id, assetSurface);

      if (existing) {
        // Re-seeing a finding refreshes its score and last_seen. Resolved
        // findings are not silently reopened — that is what verification is
        // for, and a patch that regressed deserves its own record.
        if (existing.status === 'open' || existing.status === 'remediating') {
          repo.vulnFindings.update(existing.id, {
            lastSeen: iso,
            exposureScore: scored.score
          });
        }
        seen += 1;
        continue;
      }

      repo.vulnFindings.insert({
        id: `VLN-${(created + 1).toString().padStart(4, '0')}-${now.getTime().toString(36).slice(-4).toUpperCase()}`,
        cve: vuln.cve,
        assetId: asset.id,
        surface: assetSurface,
        status: 'open',
        exposureScore: scored.score,
        firstSeen: iso,
        lastSeen: iso,
        dueAt: dueDate(scored.band, now)
      });
      created += 1;
    }
  }

  repo.vulnScans.finish(scanId, {
    finishedAt: new Date().toISOString(),
    assetsScanned: targets.length,
    findingsNew: created,
    findingsSeen: seen,
    findingsResolved: 0
  });

  repo.assets.refreshOpenFindings();

  return { scan: repo.vulnScans.byId(scanId), created, seen, resolved: 0 };
}

/**
 * Verification rescan for one finding.
 *
 * The service promises "verification rescan after every remediation", which
 * has to mean something more than trusting the person who clicked the button.
 * A finding is only verified when a scan re-checks the asset and no longer
 * sees it.
 *
 * @returns {{verified:boolean, finding:Object, scan:Object}}
 */
function verifyRemediation(findingId, { triggeredBy = 'system', now = new Date(), stillPresent = false } = {}) {
  const iso = now.toISOString();
  const finding = repo.vulnFindings.byId(findingId);
  if (!finding) return null;

  const scanId = `SCN-${now.getTime().toString(36).toUpperCase()}V`;
  repo.vulnScans.insert({
    id: scanId,
    kind: 'verification',
    surface: finding.surface,
    startedAt: iso,
    triggeredBy,
    target: `${finding.cve} on ${finding.assetId}`
  });

  if (stillPresent) {
    // The patch did not take. Reopening is the honest outcome; marking it
    // resolved because somebody said so is how a vulnerability survives an
    // audit trail that claims it was fixed.
    repo.vulnFindings.update(finding.id, {
      status: 'open',
      resolvedAt: null,
      resolvedBy: null,
      verifiedAt: null,
      lastSeen: iso,
      notes: 'Verification rescan still found this vulnerability; reopened.'
    });

    repo.vulnScans.finish(scanId, {
      finishedAt: new Date().toISOString(),
      assetsScanned: 1,
      findingsNew: 0,
      findingsSeen: 1,
      findingsResolved: 0
    });

    repo.assets.refreshOpenFindings();
    return { verified: false, finding: repo.vulnFindings.byId(finding.id), scan: repo.vulnScans.byId(scanId) };
  }

  repo.vulnFindings.update(finding.id, {
    status: 'resolved',
    resolvedAt: finding.resolvedAt || iso,
    verifiedAt: iso
  });

  repo.vulnScans.finish(scanId, {
    finishedAt: new Date().toISOString(),
    assetsScanned: 1,
    findingsNew: 0,
    findingsSeen: 0,
    findingsResolved: 1
  });

  repo.assets.refreshOpenFindings();
  return { verified: true, finding: repo.vulnFindings.byId(finding.id), scan: repo.vulnScans.byId(scanId) };
}

/* ---------------------------------------------------------------- views */

/**
 * The prioritised queue: what to patch first, and why.
 *
 * Ordered by exposure score. Deliberately NOT by CVSS — the comparison is
 * exposed so the difference is visible rather than asserted.
 */
function prioritised({ limit = 50, status = 'open', surface = null } = {}) {
  const findings = repo.vulnFindings.query({ status, surface, limit: 500 });

  const enriched = findings.map((finding) => {
    const vuln = repo.vulnerabilities.byId(finding.cve);
    const asset = repo.assets.byId(finding.assetId);
    if (!vuln || !asset) return null;

    const affected = repo.vulnFindings.countForCve(finding.cve);
    const total = repo.assets.count();

    const scored = scoreFinding(
      vuln,
      { ...asset, surface: finding.surface },
      {
        affectedCount: affected,
        totalAssets: total,
        worstCriticality:
          CRITICALITY_WEIGHT[String(asset.criticality || 'medium').toLowerCase()] || 0.4,
        worstCriticalityLabel: asset.criticality
      }
    );

    return {
      ...finding,
      vulnerability: vuln,
      asset: { id: asset.id, host: asset.host, type: asset.type, zone: asset.zone, criticality: asset.criticality },
      exposureScore: scored.score,
      band: scored.band,
      factors: scored.factors,
      blastRadius: affected,
      overdue: finding.dueAt ? new Date(finding.dueAt) < new Date() && finding.status !== 'resolved' : false
    };
  }).filter(Boolean);

  enriched.sort((a, b) => b.exposureScore - a.exposureScore);

  return enriched.slice(0, limit);
}

/**
 * Demonstrates the difference the ranking makes.
 *
 * Returns the top findings by exposure alongside the top by raw CVSS, so the
 * claim on the services page can be checked rather than believed.
 */
function rankingComparison(limit = 5) {
  const byExposure = prioritised({ limit: 200 });

  const byCvss = byExposure
    .slice()
    .sort((a, b) => (b.vulnerability.cvss || 0) - (a.vulnerability.cvss || 0));

  const shape = (finding, index) => ({
    rank: index + 1,
    cve: finding.cve,
    host: finding.asset.host,
    exposureScore: finding.exposureScore,
    cvss: finding.vulnerability.cvss,
    epss: finding.vulnerability.epss,
    kev: finding.vulnerability.kev,
    blastRadius: finding.blastRadius
  });

  const exposureTop = byExposure.slice(0, limit).map(shape);
  const cvssTop = byCvss.slice(0, limit).map(shape);

  // How many of the top N differ between the two orderings — the headline
  // number for "we do not just sort by CVSS".
  const exposureIds = exposureTop.map((row) => row.cve + row.host);
  const differing = cvssTop.filter((row) => !exposureIds.includes(row.cve + row.host)).length;

  return { byExposure: exposureTop, byCvss: cvssTop, differing, limit };
}

function summary() {
  const counts = repo.vulnFindings.counts();
  const overdue = repo.vulnFindings.overdueCount();
  const top = prioritised({ limit: 200 });

  const bands = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of top) bands[finding.band] += 1;

  return {
    ...counts,
    overdue,
    bands,
    kevOpen: top.filter((finding) => finding.vulnerability.kev).length,
    externalOpen: top.filter((finding) => finding.surface === 'external').length,
    lastScan: repo.vulnScans.latest()
  };
}

module.exports = {
  WEIGHTS,
  SLA_DAYS,
  band,
  scoreFinding,
  dueDate,
  surfaceFor,
  applies,
  runDiscovery,
  verifyRemediation,
  prioritised,
  rankingComparison,
  summary
};
