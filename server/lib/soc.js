'use strict';

/**
 * Follow-the-sun rota: who is on console now, and whether the day is actually
 * covered.
 *
 * A rota is a set of recurring daily UTC windows, one per region, which may
 * wrap midnight. The useful part is not "display the schedule" — it is
 * answering, from the schedule itself, whether the 24/7 claim holds. A gap at
 * 03:00 UTC is exactly the thing nobody notices until an alert lands in it.
 */

const repo = require('../db/repository');
const config = require('./config');

const HOURS_IN_DAY = 24;

/**
 * Expands a shift into the set of UTC hours it covers.
 * A window that wraps (22 → 06) covers 22, 23, 0, 1, … 5.
 *
 * end_hour is exclusive: 09→17 is a nine-hour shift covering 09:00–16:59.
 */
function hoursCovered(shift) {
  const hours = [];
  const start = ((shift.startHour % HOURS_IN_DAY) + HOURS_IN_DAY) % HOURS_IN_DAY;
  const end = ((shift.endHour % HOURS_IN_DAY) + HOURS_IN_DAY) % HOURS_IN_DAY;

  // A shift whose start and end are equal covers the whole day rather than
  // nothing — that is what somebody means by entering 00 to 00.
  if (start === end) {
    for (let hour = 0; hour < HOURS_IN_DAY; hour += 1) hours.push(hour);
    return hours;
  }

  let hour = start;
  while (hour !== end) {
    hours.push(hour);
    hour = (hour + 1) % HOURS_IN_DAY;
  }
  return hours;
}

function covers(shift, hour) {
  return hoursCovered(shift).includes(hour);
}

/**
 * Coverage across the whole UTC day.
 *
 * @returns {{covered:number[], gaps:number[], byHour:Object, complete:boolean}}
 */
function coverage(shifts) {
  const active = shifts.filter((shift) => shift.active);
  const byHour = {};

  for (let hour = 0; hour < HOURS_IN_DAY; hour += 1) byHour[hour] = [];

  for (const shift of active) {
    for (const hour of hoursCovered(shift)) byHour[hour].push(shift);
  }

  const gaps = [];
  const covered = [];
  for (let hour = 0; hour < HOURS_IN_DAY; hour += 1) {
    (byHour[hour].length ? covered : gaps).push(hour);
  }

  return { covered, gaps, byHour, complete: gaps.length === 0 };
}

/** Collapses [2,3,4,9] into "02:00–05:00, 09:00–10:00" for a readable warning. */
function describeGaps(gaps) {
  if (!gaps.length) return [];

  const ranges = [];
  let start = gaps[0];
  let previous = gaps[0];

  for (const hour of gaps.slice(1)) {
    if (hour === previous + 1) {
      previous = hour;
      continue;
    }
    ranges.push([start, previous]);
    start = hour;
    previous = hour;
  }
  ranges.push([start, previous]);

  const pad = (hour) => String(hour).padStart(2, '0') + ':00';
  return ranges.map(([from, to]) => `${pad(from)}–${pad((to + 1) % HOURS_IN_DAY)}`);
}

/** Which shifts are on console at a given moment. */
function onDuty(shifts, at = new Date()) {
  const hour = at.getUTCHours();
  return shifts.filter((shift) => shift.active && covers(shift, hour));
}

/**
 * The next shift to take over, and how long until it does.
 *
 * Walks forward hour by hour rather than sorting by start time, because a
 * wrapping window makes "which starts next" ambiguous by comparison alone.
 */
function nextHandover(shifts, at = new Date()) {
  const current = onDuty(shifts, at).map((shift) => shift.id);
  const hour = at.getUTCHours();

  for (let ahead = 1; ahead <= HOURS_IN_DAY; ahead += 1) {
    const future = (hour + ahead) % HOURS_IN_DAY;
    const then = shifts.filter((shift) => shift.active && covers(shift, future));
    const changed =
      then.length !== current.length ||
      then.some((shift) => !current.includes(shift.id));

    if (changed) {
      const at2 = new Date(at);
      at2.setUTCHours(hour + ahead, 0, 0, 0);
      return { inHours: ahead, at: at2.toISOString(), incoming: then };
    }
  }

  return null;
}

/**
 * Full rota state for the console.
 */
function status(at = new Date()) {
  let shifts = [];
  try {
    shifts = repo.socShifts.list();
  } catch {
    // Table absent or mid-migration; report honestly rather than throwing.
    return { configured: false, shifts: [], onDuty: [], coverage: null, headquarters: config.headquarters };
  }

  const cover = coverage(shifts);
  const duty = onDuty(shifts, at);

  return {
    configured: shifts.length > 0,
    at: at.toISOString(),
    utcHour: at.getUTCHours(),
    shifts,
    onDuty: duty,
    onDutyRegions: duty.map((shift) => shift.region),
    regions: Array.from(new Set(shifts.filter((s) => s.active).map((s) => s.region))),
    coverage: {
      complete: cover.complete,
      coveredHours: cover.covered.length,
      gaps: cover.gaps,
      gapRanges: describeGaps(cover.gaps)
    },
    nextHandover: nextHandover(shifts, at),
    // The rota rotates who is on duty; this does not. Kept separate from
    // onDuty/targets so a marker for it is never mistaken for a shift.
    headquarters: config.headquarters
  };
}

/* -------------------------------------------------------------- metrics */

/**
 * Median rather than mean, because one alert that sat over a weekend drags a
 * mean into meaninglessness while the median still describes the typical case.
 */
function median(values) {
  if (!values.length) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[middle]
    : Math.round((sorted[middle - 1] + sorted[middle]) / 2);
}

function percentile(values, p) {
  if (!values.length) return null;
  const sorted = values.slice().sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[index];
}

/**
 * Real triage performance, computed from the alerts themselves.
 *
 * Returns nulls rather than invented numbers when nothing has been triaged
 * yet: "no data" and "instant" are different answers, and a dashboard that
 * cannot tell them apart is worse than one that admits the gap.
 */
function triageMetrics({ sinceIso = null } = {}) {
  let rows = [];
  try {
    rows = repo.alerts.triageDurations(sinceIso);
  } catch {
    return { sampleSize: 0, medianSeconds: null, p90Seconds: null, criticalMedianSeconds: null };
  }

  const all = rows.map((row) => row.seconds);
  const critical = rows.filter((row) => row.severity === 'critical').map((row) => row.seconds);

  return {
    sampleSize: all.length,
    medianSeconds: median(all),
    p90Seconds: percentile(all, 90),
    criticalSampleSize: critical.length,
    criticalMedianSeconds: median(critical),
    since: sinceIso
  };
}

/** "47s", "3m 12s", "—" */
function formatDuration(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  if (minutes < 60) return rest ? `${minutes}m ${rest}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

/* ------------------------------------------------------ detection tuning */

// Why a detection fired on something benign. The category drives the advice,
// because "too broad" and "known-good process" need different fixes.
const FP_CATEGORIES = {
  expected_admin: 'Expected administrative activity',
  known_good_process: 'Known-good process or binary',
  scheduled_job: 'Scheduled job or automation',
  scanner: 'Authorised scanner or pen test',
  rule_too_broad: 'Rule matches too broadly',
  stale_intel: 'Indicator no longer relevant',
  test_traffic: 'Test or lab traffic'
};

const ADVICE = {
  expected_admin:
    'Scope the rule to exclude the administrative accounts or jump hosts this activity legitimately comes from.',
  known_good_process:
    'Add the signing certificate or binary hash to the rule exclusions rather than the process name, which is trivially renamed.',
  scheduled_job:
    'Constrain the rule by time window or parent process so the scheduled run does not match.',
  scanner:
    'Exclude the scanner source addresses, and confirm the scan window is registered so future runs are expected.',
  rule_too_broad:
    'Tighten the match conditions or raise the threshold. A rule producing mostly false positives is training analysts to ignore it.',
  stale_intel:
    'Retire or age out the indicator. Confidence should decay; an indicator nobody acts on is queue noise.',
  test_traffic:
    'Scope the rule to exclude the lab range, or tag the assets so test traffic is filtered before detection.'
};

/**
 * Per-rule false-positive analysis with concrete suggestions.
 *
 * This is what "monthly tuning against your own false-positive data" has to
 * mean in software: rules ranked by how much of their output was wrong, with
 * the reason analysts actually gave.
 */
function tuningReport({ sinceIso = null, minimumAlerts = 3 } = {}) {
  let rows = [];
  try {
    rows = repo.alerts.falsePositiveByRule(sinceIso);
  } catch {
    return { generatedAt: new Date().toISOString(), rules: [], overall: null };
  }

  const rules = rows
    .filter((row) => row.total >= minimumAlerts && row.falsePositives > 0)
    .map((row) => {
      const rate = row.falsePositives / row.total;

      // The dominant reason drives the advice; a rule with one cause is worth
      // tuning differently from one that is simply too broad.
      const categories = Object.entries(row.categories || {}).sort((a, b) => b[1] - a[1]);
      const leading = categories[0] ? categories[0][0] : null;

      return {
        ruleId: row.ruleId,
        rule: row.rule,
        severity: row.severity,
        total: row.total,
        falsePositives: row.falsePositives,
        falsePositiveRate: Math.round(rate * 1000) / 10,
        leadingCause: leading,
        leadingCauseLabel: leading ? FP_CATEGORIES[leading] || leading : null,
        categories: row.categories,
        suggestion: leading ? ADVICE[leading] : null,
        // Anything past half is actively harmful: it teaches analysts that
        // this rule means nothing.
        priority: rate >= 0.5 ? 'high' : rate >= 0.25 ? 'medium' : 'low'
      };
    })
    .sort((a, b) => b.falsePositives - a.falsePositives || b.falsePositiveRate - a.falsePositiveRate);

  const totalAlerts = rows.reduce((sum, row) => sum + row.total, 0);
  const totalFalse = rows.reduce((sum, row) => sum + row.falsePositives, 0);

  return {
    generatedAt: new Date().toISOString(),
    since: sinceIso,
    rules,
    overall: {
      alerts: totalAlerts,
      falsePositives: totalFalse,
      // Measured, not asserted. This replaced a hard-coded 3.7.
      rate: totalAlerts ? Math.round((totalFalse / totalAlerts) * 1000) / 10 : 0
    }
  };
}

module.exports = {
  hoursCovered,
  covers,
  coverage,
  describeGaps,
  onDuty,
  nextHandover,
  status,
  median,
  percentile,
  triageMetrics,
  formatDuration,
  tuningReport,
  FP_CATEGORIES,
  ADVICE
};
