'use strict';

/**
 * Typed query layer. Every function returns objects shaped exactly as the
 * HTTP API already emits them (camelCase, booleans, nested arrays), so the
 * routes and the frontend are unaffected by the storage change.
 *
 * All SQL uses positional placeholders — no string interpolation of caller
 * data anywhere in this file.
 */

const { handle, transaction } = require('./index');

/* ------------------------------------------------------------- utilities */

const bool = (v) => v === 1 || v === true;
const flag = (v) => (v ? 1 : 0);

function run(sql, params = []) {
  return handle().prepare(sql).run(...params);
}
function get(sql, params = []) {
  return handle().prepare(sql).get(...params);
}
function all(sql, params = []) {
  return handle().prepare(sql).all(...params);
}

/**
 * Builds `SET a = ?, b = ?` from a patch, restricted to an allow-list of
 * columns so a caller can never write to an unintended field.
 * @returns {{clause:string, values:Array}|null}
 */
function setClause(patch, columnMap) {
  const parts = [];
  const values = [];

  for (const [key, column] of Object.entries(columnMap)) {
    if (!(key in patch) || patch[key] === undefined) continue;
    parts.push(`${column} = ?`);
    const value = patch[key];
    values.push(typeof value === 'boolean' ? flag(value) : value);
  }

  if (!parts.length) return null;
  return { clause: parts.join(', '), values };
}

/* ------------------------------------------------------------------ users */

const USER_COLUMNS =
  'id, name, email, password_hash, role, org, title, created_at, last_login, disabled, mfa_enabled, demo, ' +
  'mfa_secret, mfa_pending_secret, mfa_confirmed_at, mfa_last_counter';

function mapUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    passwordHash: row.password_hash,
    role: row.role,
    org: row.org,
    title: row.title,
    createdAt: row.created_at,
    lastLogin: row.last_login,
    disabled: bool(row.disabled),
    mfaEnabled: bool(row.mfa_enabled),
    demo: bool(row.demo),
    // Secrets travel no further than this process: publicUser() in lib/auth
    // strips them before any user object reaches a response body.
    mfaSecret: row.mfa_secret,
    mfaPendingSecret: row.mfa_pending_secret,
    mfaConfirmedAt: row.mfa_confirmed_at,
    mfaLastCounter: row.mfa_last_counter
  };
}

const users = {
  byEmail(email) {
    return mapUser(get(`SELECT ${USER_COLUMNS} FROM users WHERE email = ?`, [String(email).toLowerCase()]));
  },

  byId(id) {
    return mapUser(get(`SELECT ${USER_COLUMNS} FROM users WHERE id = ?`, [id]));
  },

  insert(user) {
    run(
      `INSERT INTO users
         (id, name, email, password_hash, role, org, title, created_at, last_login, disabled, mfa_enabled, demo)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        user.id,
        user.name,
        String(user.email).toLowerCase(),
        user.passwordHash,
        user.role || 'analyst',
        user.org || null,
        user.title || null,
        user.createdAt,
        user.lastLogin || null,
        flag(user.disabled),
        flag(user.mfaEnabled),
        flag(user.demo)
      ]
    );
    return users.byId(user.id);
  },

  update(id, patch) {
    const set = setClause(patch, {
      name: 'name',
      passwordHash: 'password_hash',
      role: 'role',
      org: 'org',
      title: 'title',
      lastLogin: 'last_login',
      disabled: 'disabled',
      mfaEnabled: 'mfa_enabled',
      mfaSecret: 'mfa_secret',
      mfaPendingSecret: 'mfa_pending_secret',
      mfaConfirmedAt: 'mfa_confirmed_at',
      mfaLastCounter: 'mfa_last_counter'
    });
    if (!set) return users.byId(id);
    run(`UPDATE users SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return users.byId(id);
  },

  list() {
    return all(`SELECT ${USER_COLUMNS} FROM users ORDER BY created_at DESC`).map(mapUser);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM users').n;
  }
};

/* --------------------------------------------------------------- sessions */

function mapSession(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    revoked: bool(row.revoked),
    ip: row.ip,
    userAgent: row.user_agent
  };
}

const sessions = {
  insert(session) {
    run(
      `INSERT INTO sessions (id, user_id, issued_at, expires_at, revoked, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        session.id,
        session.userId,
        session.issuedAt,
        session.expiresAt,
        flag(session.revoked),
        session.ip || null,
        session.userAgent || null
      ]
    );
    return session;
  },

  byId(id) {
    return mapSession(get('SELECT * FROM sessions WHERE id = ?', [id]));
  },

  revoke(id) {
    return run('UPDATE sessions SET revoked = 1 WHERE id = ?', [id]).changes > 0;
  },

  /** Signs every other device out — used after a password change. */
  revokeAllForUser(userId, exceptId = null) {
    const result = exceptId
      ? run('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id <> ? AND revoked = 0', [userId, exceptId])
      : run('UPDATE sessions SET revoked = 1 WHERE user_id = ? AND revoked = 0', [userId]);
    return result.changes;
  },

  listForUser(userId) {
    return all(
      `SELECT * FROM sessions WHERE user_id = ? ORDER BY issued_at DESC LIMIT 50`,
      [userId]
    ).map(mapSession);
  },

  /** Drops rows that can no longer authenticate anything. */
  prune(now = new Date().toISOString()) {
    return run('DELETE FROM sessions WHERE expires_at < ?', [now]).changes;
  }
};

/* ----------------------------------------------------------------- alerts */

function mapAlert(row, notes = []) {
  if (!row) return null;
  return {
    id: row.id,
    ts: row.ts,
    ruleId: row.rule_id,
    rule: row.rule,
    severity: row.severity,
    tactic: row.tactic,
    technique: row.technique,
    techniqueName: row.technique_name,
    source: row.source,
    description: row.description,
    recommendation: row.recommendation,
    assetId: row.asset_id,
    host: row.host,
    ip: row.ip,
    zone: row.zone,
    assetType: row.asset_type,
    criticality: row.criticality,
    owner: row.owner,
    user: row.user,
    sourceIp: row.source_ip,
    destPort: row.dest_port,
    confidence: row.confidence,
    risk: row.risk,
    status: row.status,
    assignee: row.assignee,
    indicator: row.indicator,
    indicatorType: row.indicator_type,
    actor: row.actor,
    incidentId: row.incident_id || undefined,
    updatedAt: row.updated_at || undefined,
    triagedAt: row.triaged_at || undefined,
    triagedBy: row.triaged_by || undefined,
    falsePositive: bool(row.false_positive),
    fpReason: row.fp_reason || undefined,
    fpCategory: row.fp_category || undefined,
    fpMarkedBy: row.fp_marked_by || undefined,
    fpMarkedAt: row.fp_marked_at || undefined,
    notes
  };
}

/** One query for a whole page of notes, rather than one per row. */
function notesFor(ids) {
  if (!ids.length) return new Map();

  const placeholders = ids.map(() => '?').join(',');
  const rows = all(
    `SELECT alert_id, ts, author, text FROM alert_notes
      WHERE alert_id IN (${placeholders}) ORDER BY id ASC`,
    ids
  );

  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.alert_id)) grouped.set(row.alert_id, []);
    grouped.get(row.alert_id).push({ ts: row.ts, author: row.author, text: row.text });
  }
  return grouped;
}

function hydrateAlerts(rows) {
  const notes = notesFor(rows.map((r) => r.id));
  return rows.map((row) => mapAlert(row, notes.get(row.id) || []));
}

const SORT_COLUMNS = {
  ts: 'ts',
  risk: 'risk',
  severity: `CASE severity
               WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
               WHEN 'low' THEN 2 ELSE 1 END`
};

const alerts = {
  insert(alert) {
    run(
      `INSERT INTO alerts
         (id, ts, rule_id, rule, severity, tactic, technique, technique_name, source,
          description, recommendation, asset_id, host, ip, zone, asset_type, criticality,
          owner, "user", source_ip, dest_port, confidence, risk, status, assignee,
          indicator, indicator_type, actor, incident_id, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        alert.id, alert.ts, alert.ruleId, alert.rule, alert.severity, alert.tactic,
        alert.technique, alert.techniqueName, alert.source, alert.description,
        alert.recommendation, alert.assetId, alert.host, alert.ip, alert.zone,
        alert.assetType, alert.criticality, alert.owner, alert.user, alert.sourceIp,
        alert.destPort, alert.confidence, alert.risk, alert.status || 'new',
        alert.assignee || null, alert.indicator || null, alert.indicatorType || null,
        alert.actor || null, alert.incidentId || null, alert.updatedAt || null
      ]
    );
    return alert;
  },

  insertMany(rows) {
    return transaction(() => {
      for (const row of rows) alerts.insert(row);
      return rows.length;
    });
  },

  byId(id) {
    const row = get('SELECT * FROM alerts WHERE id = ?', [id]);
    if (!row) return null;
    return hydrateAlerts([row])[0];
  },

  /**
   * Filtered, sorted, paginated list.
   * @param {Object} q severity/status (comma lists), tactic, source, zone,
   *                   search text, since, sort, order, page, limit
   */
  query(q = {}) {
    const where = [];
    const params = [];

    const inList = (column, value) => {
      const wanted = String(value).split(',').map((s) => s.trim()).filter(Boolean);
      if (!wanted.length) return;
      where.push(`${column} IN (${wanted.map(() => '?').join(',')})`);
      params.push(...wanted);
    };

    if (q.severity) inList('severity', q.severity);
    if (q.status) inList('status', q.status);
    if (q.tactic) { where.push('tactic = ?'); params.push(q.tactic); }
    if (q.source) { where.push('source = ?'); params.push(q.source); }
    if (q.zone) { where.push('zone = ?'); params.push(q.zone); }
    if (q.assignee) { where.push('assignee = ?'); params.push(q.assignee); }

    if (q.since) {
      const cutoff = new Date(q.since);
      if (!Number.isNaN(cutoff.getTime())) {
        where.push('ts > ?');
        params.push(cutoff.toISOString());
      }
    }

    if (q.q) {
      const needle = `%${String(q.q).toLowerCase()}%`;
      where.push(
        `(LOWER(rule) LIKE ? OR LOWER(host) LIKE ? OR LOWER("user") LIKE ?
          OR LOWER(source_ip) LIKE ? OR LOWER(technique) LIKE ? OR LOWER(id) LIKE ?
          OR LOWER(COALESCE(indicator,'')) LIKE ? OR LOWER(COALESCE(actor,'')) LIKE ?)`
      );
      params.push(needle, needle, needle, needle, needle, needle, needle, needle);
    }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = get(`SELECT COUNT(*) AS n FROM alerts ${clause}`, params).n;

    const sort = SORT_COLUMNS[q.sort] || SORT_COLUMNS.ts;
    const direction = q.order === 'asc' ? 'ASC' : 'DESC';
    const limit = Math.min(Number(q.limit) || 25, 200);
    const page = Math.max(Number(q.page) || 1, 1);

    const rows = all(
      `SELECT * FROM alerts ${clause} ORDER BY ${sort} ${direction}, id ${direction} LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit]
    );

    return { rows: hydrateAlerts(rows), total, page, limit };
  },


  /**
   * How long each triaged alert waited, in seconds.
   *
   * Computed from triaged_at rather than updated_at: updated_at moves on
   * every later edit too, so it answers "when was this last touched", which
   * is a different and much larger number.
   */
  triageDurations(sinceIso = null) {
    const clause = sinceIso ? 'AND ts >= ?' : '';
    const params = sinceIso ? [sinceIso] : [];

    return all(
      `SELECT ts, triaged_at, severity FROM alerts
        WHERE triaged_at IS NOT NULL ${clause}`,
      params
    )
      .map((row) => ({
        severity: row.severity,
        seconds: Math.round((new Date(row.triaged_at) - new Date(row.ts)) / 1000)
      }))
      // A negative duration means the clock moved or the row was seeded out of
      // order; either way it is not a measurement.
      .filter((row) => Number.isFinite(row.seconds) && row.seconds >= 0);
  },

  /** Per-rule totals and false-positive breakdown, for the tuning report. */
  falsePositiveByRule(sinceIso = null) {
    const clause = sinceIso ? 'WHERE ts >= ?' : '';
    const params = sinceIso ? [sinceIso] : [];

    const totals = all(
      `SELECT rule_id, rule, severity,
              COUNT(*) AS total,
              SUM(false_positive) AS false_positives
         FROM alerts ${clause}
        GROUP BY rule_id`,
      params
    );

    const categories = all(
      `SELECT rule_id, fp_category, COUNT(*) AS n
         FROM alerts
        WHERE false_positive = 1 AND fp_category IS NOT NULL
          ${sinceIso ? 'AND ts >= ?' : ''}
        GROUP BY rule_id, fp_category`,
      params
    );

    const byRule = new Map();
    for (const row of categories) {
      if (!byRule.has(row.rule_id)) byRule.set(row.rule_id, {});
      byRule.get(row.rule_id)[row.fp_category] = row.n;
    }

    return totals.map((row) => ({
      ruleId: row.rule_id,
      rule: row.rule,
      severity: row.severity,
      total: row.total,
      falsePositives: row.false_positives || 0,
      categories: byRule.get(row.rule_id) || {}
    }));
  },

  falsePositiveCount() {
    return get('SELECT COUNT(*) AS n FROM alerts WHERE false_positive = 1').n;
  },

  recent(n = 8) {
    return hydrateAlerts(all('SELECT * FROM alerts ORDER BY ts DESC LIMIT ?', [n]));
  },

  update(id, patch) {
    const set = setClause(patch, {
      status: 'status',
      triagedAt: 'triaged_at',
      triagedBy: 'triaged_by',
      falsePositive: 'false_positive',
      fpReason: 'fp_reason',
      fpCategory: 'fp_category',
      fpMarkedBy: 'fp_marked_by',
      fpMarkedAt: 'fp_marked_at',
      assignee: 'assignee',
      incidentId: 'incident_id',
      updatedAt: 'updated_at'
    });
    if (set) run(`UPDATE alerts SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return alerts.byId(id);
  },

  addNote(alertId, note) {
    run('INSERT INTO alert_notes (alert_id, ts, author, text) VALUES (?, ?, ?, ?)', [
      alertId,
      note.ts,
      note.author,
      note.text
    ]);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM alerts').n;
  },

  /** Keeps the newest `max` rows; cascades delete their notes. */
  trim(max) {
    return run(
      `DELETE FROM alerts WHERE id NOT IN (
         SELECT id FROM alerts ORDER BY ts DESC LIMIT ?
       )`,
      [max]
    ).changes;
  },

  filterOptions() {
    const distinct = (column) =>
      all(`SELECT DISTINCT ${column} AS v FROM alerts WHERE ${column} IS NOT NULL ORDER BY v`)
        .map((r) => r.v);
    return {
      tactics: distinct('tactic'),
      sources: distinct('source'),
      zones: distinct('zone')
    };
  },

  /** Alert counts per asset within the window, for the inventory table. */
  countsByAsset(sinceIso) {
    const rows = all(
      'SELECT asset_id, COUNT(*) AS n FROM alerts WHERE ts >= ? GROUP BY asset_id',
      [sinceIso]
    );
    return new Map(rows.map((r) => [r.asset_id, r.n]));
  },

  /** Hits per ATT&CK technique, for the coverage matrix. */
  countsByTechnique() {
    const rows = all('SELECT technique, COUNT(*) AS n FROM alerts GROUP BY technique');
    return new Map(rows.map((r) => [r.technique, r.n]));
  },

  groupCount(column) {
    const allowed = ['severity', 'tactic', 'source', 'status'];
    if (!allowed.includes(column)) throw new Error(`groupCount: ${column} not allowed`);
    const rows = all(
      `SELECT ${column} AS k, COUNT(*) AS n FROM alerts WHERE ${column} IS NOT NULL GROUP BY ${column}`
    );
    const out = {};
    for (const row of rows) out[row.k] = row.n;
    return out;
  },

  /** Minimal projection for bucketing the 24h timeline in JS. */
  timelineRows(sinceIso) {
    return all('SELECT ts, severity FROM alerts WHERE ts >= ?', [sinceIso]);
  },

  countSince(sinceIso, severity) {
    return severity
      ? get('SELECT COUNT(*) AS n FROM alerts WHERE ts >= ? AND severity = ?', [sinceIso, severity]).n
      : get('SELECT COUNT(*) AS n FROM alerts WHERE ts >= ?', [sinceIso]).n;
  }
};

/* -------------------------------------------------------------- incidents */

function mapIncident(row, timeline = []) {
  if (!row) return null;
  return {
    id: row.id,
    title: row.title,
    severity: row.severity,
    status: row.status,
    priority: row.priority,
    summary: row.summary,
    ruleId: row.rule_id,
    rule: row.rule,
    technique: row.technique,
    tactic: row.tactic,
    assetId: row.asset_id,
    host: row.host,
    zone: row.zone,
    owner: row.owner,
    analyst: row.analyst,
    sourceAlertId: row.source_alert_id || undefined,
    openedAt: row.opened_at,
    acknowledgedAt: row.acknowledged_at,
    closedAt: row.closed_at,
    updatedAt: row.updated_at,
    seeded: bool(row.seeded),
    timeline
  };
}

function timelinesFor(ids) {
  if (!ids.length) return new Map();

  const placeholders = ids.map(() => '?').join(',');
  const rows = all(
    `SELECT incident_id, ts, actor, entry FROM incident_timeline
      WHERE incident_id IN (${placeholders}) ORDER BY id ASC`,
    ids
  );

  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.incident_id)) grouped.set(row.incident_id, []);
    grouped.get(row.incident_id).push({ ts: row.ts, actor: row.actor, entry: row.entry });
  }
  return grouped;
}

function hydrateIncidents(rows) {
  const timelines = timelinesFor(rows.map((r) => r.id));
  return rows.map((row) => mapIncident(row, timelines.get(row.id) || []));
}

const incidents = {
  insert(incident) {
    return transaction(() => {
      run(
        `INSERT INTO incidents
           (id, title, severity, status, priority, summary, rule_id, rule, technique, tactic,
            asset_id, host, zone, owner, analyst, source_alert_id, opened_at,
            acknowledged_at, closed_at, updated_at, seeded)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          incident.id, incident.title, incident.severity, incident.status, incident.priority,
          incident.summary, incident.ruleId || null, incident.rule || null,
          incident.technique || null, incident.tactic || null, incident.assetId || null,
          incident.host || null, incident.zone || null, incident.owner || null,
          incident.analyst || null, incident.sourceAlertId || null, incident.openedAt,
          incident.acknowledgedAt || null, incident.closedAt || null,
          incident.updatedAt || null, flag(incident.seeded)
        ]
      );

      for (const entry of incident.timeline || []) {
        incidents.addTimelineEntry(incident.id, entry);
      }

      return incidents.byId(incident.id);
    });
  },

  byId(id) {
    const row = get('SELECT * FROM incidents WHERE id = ?', [id]);
    if (!row) return null;
    return hydrateIncidents([row])[0];
  },

  bySourceAlert(alertId) {
    const row = get('SELECT * FROM incidents WHERE source_alert_id = ?', [alertId]);
    if (!row) return null;
    return hydrateIncidents([row])[0];
  },

  query(q = {}) {
    const where = [];
    const params = [];

    if (q.status === 'open') where.push("status <> 'closed'");
    else if (q.status) { where.push('status = ?'); params.push(q.status); }

    if (q.severity) { where.push('severity = ?'); params.push(q.severity); }

    if (q.q) {
      const needle = `%${String(q.q).toLowerCase()}%`;
      where.push(
        `(LOWER(title) LIKE ? OR LOWER(id) LIKE ? OR LOWER(COALESCE(host,'')) LIKE ?
          OR LOWER(COALESCE(summary,'')) LIKE ? OR LOWER(COALESCE(analyst,'')) LIKE ?)`
      );
      params.push(needle, needle, needle, needle, needle);
    }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = get(`SELECT COUNT(*) AS n FROM incidents ${clause}`, params).n;

    const limit = Math.min(Number(q.limit) || 20, 100);
    const page = Math.max(Number(q.page) || 1, 1);

    const rows = all(
      `SELECT * FROM incidents ${clause} ORDER BY opened_at DESC, id DESC LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit]
    );

    return { rows: hydrateIncidents(rows), total, page, limit };
  },

  update(id, patch) {
    const set = setClause(patch, {
      title: 'title',
      severity: 'severity',
      status: 'status',
      priority: 'priority',
      summary: 'summary',
      analyst: 'analyst',
      acknowledgedAt: 'acknowledged_at',
      closedAt: 'closed_at',
      updatedAt: 'updated_at'
    });
    if (set) run(`UPDATE incidents SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return incidents.byId(id);
  },

  addTimelineEntry(incidentId, entry) {
    run('INSERT INTO incident_timeline (incident_id, ts, actor, entry) VALUES (?, ?, ?, ?)', [
      incidentId,
      entry.ts,
      entry.actor || null,
      entry.entry
    ]);
  },

  remove(id) {
    return run('DELETE FROM incidents WHERE id = ?', [id]).changes > 0;
  },

  relatedAlerts(incidentId, sourceAlertId) {
    const rows = all(
      'SELECT * FROM alerts WHERE incident_id = ? OR id = ? ORDER BY ts DESC',
      [incidentId, sourceAlertId || '']
    );
    return hydrateAlerts(rows);
  },

  summary() {
    const row = get(`
      SELECT
        SUM(CASE WHEN status <> 'closed' THEN 1 ELSE 0 END)                              AS open,
        SUM(CASE WHEN severity = 'critical' AND status <> 'closed' THEN 1 ELSE 0 END)     AS critical,
        SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END)                                AS closed,
        COUNT(*)                                                                          AS total
      FROM incidents
    `);
    return {
      open: row.open || 0,
      critical: row.critical || 0,
      closed: row.closed || 0,
      total: row.total || 0
    };
  },

  /** Incident ids are human-facing (INC-2041…), so they run in a sequence. */
  nextSequence(base = 2041) {
    const row = get(
      `SELECT MAX(CAST(SUBSTR(id, 5) AS INTEGER)) AS n FROM incidents WHERE id LIKE 'INC-%'`
    );
    return Math.max(base, (row && row.n ? row.n : base - 1) + 1);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM incidents').n;
  },

  /** Mean minutes from open to acknowledge and to close. */
  responseTimes() {
    const mtta = get(`
      SELECT AVG((julianday(acknowledged_at) - julianday(opened_at)) * 1440) AS m
        FROM incidents WHERE acknowledged_at IS NOT NULL
    `).m;
    const mttr = get(`
      SELECT AVG((julianday(closed_at) - julianday(opened_at)) * 1440) AS m
        FROM incidents WHERE closed_at IS NOT NULL AND status = 'closed'
    `).m;
    return {
      mttaMinutes: mtta ? Math.round(mtta) : 0,
      mttrMinutes: mttr ? Math.round(mttr) : 0
    };
  }
};

/* ----------------------------------------------------------------- assets */

function mapAsset(row) {
  if (!row) return null;
  return {
    id: row.id,
    host: row.host,
    ip: row.ip,
    type: row.type,
    zone: row.zone,
    criticality: row.criticality,
    owner: row.owner,
    status: row.status,
    agentVersion: row.agent_version,
    lastSeen: row.last_seen,
    openFindings: row.open_findings
  };
}

const assets = {
  upsertMany(rows) {
    return transaction(() => {
      for (const asset of rows) {
        run(
          `INSERT INTO assets
             (id, host, ip, type, zone, criticality, owner, status, agent_version, last_seen, open_findings)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             host = excluded.host, ip = excluded.ip, type = excluded.type,
             zone = excluded.zone, criticality = excluded.criticality,
             owner = excluded.owner, status = excluded.status,
             agent_version = excluded.agent_version, last_seen = excluded.last_seen,
             open_findings = excluded.open_findings`,
          [
            asset.id, asset.host, asset.ip, asset.type, asset.zone, asset.criticality,
            asset.owner, asset.status || 'healthy', asset.agentVersion || null,
            asset.lastSeen || null, asset.openFindings || 0
          ]
        );
      }
      return rows.length;
    });
  },

  query(q = {}) {
    const where = [];
    const params = [];

    if (q.zone) { where.push('zone = ?'); params.push(q.zone); }
    if (q.criticality) { where.push('criticality = ?'); params.push(q.criticality); }
    if (q.q) {
      const needle = `%${String(q.q).toLowerCase()}%`;
      where.push('(LOWER(host) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(type) LIKE ? OR LOWER(owner) LIKE ?)');
      params.push(needle, needle, needle, needle);
    }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    return all(`SELECT * FROM assets ${clause} ORDER BY id`, params).map(mapAsset);
  },

  zones() {
    return all('SELECT DISTINCT zone AS v FROM assets WHERE zone IS NOT NULL ORDER BY v')
      .map((r) => r.v);
  },

  /**
   * Recomputes each asset's open-finding count from the findings table.
   *
   * Derived rather than incremented: a counter maintained by hand drifts the
   * first time a finding is resolved by a path that forgot to decrement it,
   * and then the inventory quietly disagrees with the queue.
   */
  refreshOpenFindings() {
    return run(
      `UPDATE assets SET open_findings = (
         SELECT COUNT(*) FROM vuln_findings f
          WHERE f.asset_id = assets.id AND f.status IN ('open','remediating')
       )`
    ).changes;
  },

  byId(id) {
    return mapAsset(get('SELECT * FROM assets WHERE id = ?', [id]));
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM assets').n;
  }
};

/* --------------------------------------------------------------- contacts */

function mapContact(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    company: row.company,
    employees: row.employees,
    interest: row.interest,
    urgency: row.urgency,
    message: row.message,
    ip: row.ip,
    submittedAt: row.submitted_at,
    status: row.status
  };
}

const contacts = {
  insert(contact) {
    run(
      `INSERT INTO contacts
         (id, name, email, company, employees, interest, urgency, message, ip, submitted_at, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        contact.id, contact.name, contact.email, contact.company, contact.employees,
        contact.interest, contact.urgency, contact.message, contact.ip,
        contact.submittedAt, contact.status || 'new'
      ]
    );
    return contact;
  },

  list(limit = 300) {
    return all('SELECT * FROM contacts ORDER BY submitted_at DESC LIMIT ?', [limit]).map(mapContact);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM contacts').n;
  },

  trim(max) {
    return run(
      `DELETE FROM contacts WHERE id NOT IN (
         SELECT id FROM contacts ORDER BY submitted_at DESC LIMIT ?
       )`,
      [max]
    ).changes;
  }
};

/* ---------------------------------------------------------------- audit */

const audit = {
  insert(entry) {
    run('INSERT INTO audit_log (id, ts, action, detail, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)', [
      entry.id,
      entry.ts,
      entry.action,
      entry.detail || null,
      entry.ip || null,
      entry.userAgent || null
    ]);
    return entry;
  },

  list(limit = 100) {
    return all('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?', [limit]).map((row) => ({
      id: row.id,
      ts: row.ts,
      action: row.action,
      detail: row.detail,
      ip: row.ip,
      userAgent: row.user_agent
    }));
  },

  trim(max) {
    return run(
      `DELETE FROM audit_log WHERE id NOT IN (
         SELECT id FROM audit_log ORDER BY ts DESC LIMIT ?
       )`,
      [max]
    ).changes;
  }
};

/* ----------------------------------------------------------------- admin */

const admin = {
  counts() {
    return {
      users: users.count(),
      sessions: get('SELECT COUNT(*) AS n FROM sessions').n,
      alerts: alerts.count(),
      alertNotes: get('SELECT COUNT(*) AS n FROM alert_notes').n,
      incidents: incidents.count(),
      timelineEntries: get('SELECT COUNT(*) AS n FROM incident_timeline').n,
      assets: assets.count(),
      contacts: contacts.count(),
      auditEntries: get('SELECT COUNT(*) AS n FROM audit_log').n
    };
  },

  /** Full tenant export. Password hashes are never included. */
  exportAll() {
    return {
      exportedAt: new Date().toISOString(),
      schemaVersion: get('PRAGMA user_version').user_version,
      counts: admin.counts(),
      users: users.list().map(({ passwordHash, ...safe }) => safe),
      alerts: hydrateAlerts(all('SELECT * FROM alerts ORDER BY ts DESC')),
      incidents: hydrateIncidents(all('SELECT * FROM incidents ORDER BY opened_at DESC')),
      assets: assets.query(),
      contacts: contacts.list(1000),
      auditLog: audit.list(1000)
    };
  }
};

/* -------------------------------------------------------- recovery codes */

const recoveryCodes = {
  /**
   * Replaces the whole set atomically. Regenerating always invalidates the
   * previous batch — a user who has printed a new sheet must not still be
   * able to authenticate with the old one.
   */
  replaceAll(userId, hashes, now = new Date().toISOString()) {
    return transaction(() => {
      run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId]);
      for (const hash of hashes) {
        run(
          'INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)',
          [userId, hash, now]
        );
      }
      return hashes.length;
    });
  },

  /**
   * Burns a code if it matches an unused one. Single statement so two
   * concurrent requests cannot both spend the same code.
   * @returns {boolean} whether a code was consumed
   */
  consume(userId, hash, now = new Date().toISOString()) {
    return (
      run(
        `UPDATE mfa_recovery_codes SET used_at = ?
          WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`,
        [now, userId, hash]
      ).changes > 0
    );
  },

  remaining(userId) {
    return get(
      'SELECT COUNT(*) AS n FROM mfa_recovery_codes WHERE user_id = ? AND used_at IS NULL',
      [userId]
    ).n;
  },

  clear(userId) {
    return run('DELETE FROM mfa_recovery_codes WHERE user_id = ?', [userId]).changes;
  }
};

/* -------------------------------------------------------- password resets */

function mapReset(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    issuedBy: row.issued_by,
    ip: row.ip
  };
}

const passwordResets = {
  insert(reset) {
    run(
      `INSERT INTO password_resets
         (id, user_id, token_hash, created_at, expires_at, used_at, issued_by, ip)
       VALUES (?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        reset.id,
        reset.userId,
        reset.tokenHash,
        reset.createdAt,
        reset.expiresAt,
        reset.issuedBy || null,
        reset.ip || null
      ]
    );
    return mapReset(get('SELECT * FROM password_resets WHERE id = ?', [reset.id]));
  },

  /** Exact-match lookup on the hash — the plaintext is never stored. */
  byTokenHash(hash) {
    return mapReset(get('SELECT * FROM password_resets WHERE token_hash = ?', [hash]));
  },

  markUsed(id, now = new Date().toISOString()) {
    return run('UPDATE password_resets SET used_at = ? WHERE id = ? AND used_at IS NULL', [
      now,
      id
    ]).changes > 0;
  },

  /** Issuing a new link retires any earlier outstanding one. */
  invalidateForUser(userId, now = new Date().toISOString()) {
    return run(
      'UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL',
      [now, userId]
    ).changes;
  },

  listForUser(userId) {
    return all(
      'SELECT * FROM password_resets WHERE user_id = ? ORDER BY created_at DESC LIMIT 20',
      [userId]
    ).map(mapReset);
  },

  prune(now = new Date().toISOString()) {
    return run('DELETE FROM password_resets WHERE expires_at < ? OR used_at IS NOT NULL', [
      now
    ]).changes;
  }
};

/* --------------------------------------------------------------- api keys */

function mapApiKey(row) {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    prefix: row.prefix,
    keyHash: row.key_hash,
    scopes: String(row.scopes || 'read').split(',').filter(Boolean),
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
    revoked: bool(row.revoked)
  };
}

const apiKeys = {
  insert(key) {
    run(
      `INSERT INTO api_keys
         (id, user_id, name, prefix, key_hash, scopes, created_at, last_used_at, expires_at, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, 0)`,
      [
        key.id,
        key.userId,
        key.name,
        key.prefix,
        key.keyHash,
        (key.scopes || ['read']).join(','),
        key.createdAt,
        key.expiresAt || null
      ]
    );
    return apiKeys.byId(key.id);
  },

  byId(id) {
    return mapApiKey(get('SELECT * FROM api_keys WHERE id = ?', [id]));
  },

  /**
   * Candidates sharing a plaintext prefix. Almost always one row, which is
   * the point: authentication does a single indexed lookup instead of
   * hashing the presented key against every row in the table.
   */
  byPrefix(prefix) {
    return all('SELECT * FROM api_keys WHERE prefix = ? AND revoked = 0', [prefix]).map(
      mapApiKey
    );
  },

  listForUser(userId) {
    return all('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', [
      userId
    ]).map(mapApiKey);
  },

  list() {
    return all('SELECT * FROM api_keys ORDER BY created_at DESC LIMIT 200').map(mapApiKey);
  },

  touch(id, now = new Date().toISOString()) {
    run('UPDATE api_keys SET last_used_at = ? WHERE id = ?', [now, id]);
  },

  revoke(id, userId = null) {
    const sql = userId
      ? 'UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ?'
      : 'UPDATE api_keys SET revoked = 1 WHERE id = ?';
    return run(sql, userId ? [id, userId] : [id]).changes > 0;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM api_keys WHERE revoked = 0').n;
  }
};

/* --------------------------------------------------------------- webhooks */

function mapWebhook(row) {
  if (!row) return null;
  return {
    id: row.id,
    url: row.url,
    description: row.description,
    secret: row.secret,
    events: String(row.events || '').split(',').filter(Boolean),
    active: bool(row.active),
    createdAt: row.created_at,
    createdBy: row.created_by,
    lastStatus: row.last_status,
    lastAttemptAt: row.last_attempt_at,
    lastError: row.last_error,
    failureCount: row.failure_count
  };
}

const webhooks = {
  insert(hook) {
    run(
      `INSERT INTO webhooks
         (id, url, description, secret, events, active, created_at, created_by, failure_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [
        hook.id,
        hook.url,
        hook.description || null,
        hook.secret,
        (hook.events || ['incident.opened']).join(','),
        flag(hook.active === undefined ? true : hook.active),
        hook.createdAt,
        hook.createdBy || null
      ]
    );
    return webhooks.byId(hook.id);
  },

  byId(id) {
    return mapWebhook(get('SELECT * FROM webhooks WHERE id = ?', [id]));
  },

  list() {
    return all('SELECT * FROM webhooks ORDER BY created_at DESC').map(mapWebhook);
  },

  /** Active subscribers for one event name — the dispatch hot path. */
  activeFor(event) {
    return all('SELECT * FROM webhooks WHERE active = 1')
      .map(mapWebhook)
      .filter((hook) => hook.events.includes(event) || hook.events.includes('*'));
  },

  update(id, patch) {
    const normalised = { ...patch };
    if (Array.isArray(normalised.events)) normalised.events = normalised.events.join(',');

    const set = setClause(normalised, {
      url: 'url',
      description: 'description',
      events: 'events',
      active: 'active'
    });
    if (!set) return webhooks.byId(id);
    run(`UPDATE webhooks SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return webhooks.byId(id);
  },

  remove(id) {
    return run('DELETE FROM webhooks WHERE id = ?', [id]).changes > 0;
  },

  /** Records the outcome and keeps a short per-hook delivery history. */
  recordDelivery(webhookId, delivery) {
    return transaction(() => {
      run(
        `INSERT INTO webhook_deliveries
           (webhook_id, event, status, response_code, error, attempted_at, duration_ms)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          webhookId,
          delivery.event,
          delivery.status,
          delivery.responseCode || null,
          delivery.error ? String(delivery.error).slice(0, 300) : null,
          delivery.attemptedAt,
          delivery.durationMs || null
        ]
      );

      const failed = delivery.status !== 'delivered';
      run(
        `UPDATE webhooks
            SET last_status = ?, last_attempt_at = ?, last_error = ?,
                failure_count = CASE WHEN ? THEN failure_count + 1 ELSE 0 END
          WHERE id = ?`,
        [
          delivery.status,
          delivery.attemptedAt,
          delivery.error ? String(delivery.error).slice(0, 300) : null,
          failed ? 1 : 0,
          webhookId
        ]
      );

      // History is for debugging the last few attempts, not an audit trail.
      run(
        `DELETE FROM webhook_deliveries
          WHERE webhook_id = ? AND id NOT IN (
            SELECT id FROM webhook_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT 20
          )`,
        [webhookId, webhookId]
      );
    });
  },

  deliveries(webhookId, limit = 20) {
    return all(
      'SELECT * FROM webhook_deliveries WHERE webhook_id = ? ORDER BY id DESC LIMIT ?',
      [webhookId, limit]
    ).map((row) => ({
      id: row.id,
      event: row.event,
      status: row.status,
      responseCode: row.response_code,
      error: row.error,
      attemptedAt: row.attempted_at,
      durationMs: row.duration_ms
    }));
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM webhooks WHERE active = 1').n;
  }
};


/* ------------------------------------------------------ detection rules */

function mapRule(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    technique: row.technique,
    techniqueName: row.technique_name,
    tactic: row.tactic,
    severity: row.severity,
    source: row.source,
    description: row.description,
    response: row.response,
    assetTypes: row.asset_types ? row.asset_types.split(',').filter(Boolean) : [],
    internalSource: bool(row.internal_source),
    enabled: bool(row.enabled),
    createdBy: row.created_by,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    custom: true
  };
}

const detectionRules = {
  insert(rule) {
    run(
      `INSERT INTO detection_rules
         (id, name, technique, technique_name, tactic, severity, source, description,
          response, asset_types, internal_source, enabled, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        rule.id,
        rule.name,
        rule.technique || null,
        rule.techniqueName || null,
        rule.tactic || null,
        rule.severity,
        rule.source || 'Custom',
        rule.description || null,
        rule.response || null,
        (rule.assetTypes || []).join(','),
        flag(rule.internalSource),
        flag(rule.enabled === undefined ? true : rule.enabled),
        rule.createdBy || null,
        rule.createdAt,
        rule.createdAt
      ]
    );
    return detectionRules.byId(rule.id);
  },

  byId(id) {
    return mapRule(get('SELECT * FROM detection_rules WHERE id = ?', [id]));
  },

  list() {
    return all('SELECT * FROM detection_rules ORDER BY created_at DESC').map(mapRule);
  },

  /** The detection pool the engine draws from. */
  enabled() {
    return all('SELECT * FROM detection_rules WHERE enabled = 1').map(mapRule);
  },

  update(id, patch) {
    const normalised = { ...patch, updatedAt: new Date().toISOString() };
    if (Array.isArray(normalised.assetTypes)) {
      normalised.assetTypes = normalised.assetTypes.join(',');
    }

    const set = setClause(normalised, {
      name: 'name',
      technique: 'technique',
      techniqueName: 'technique_name',
      tactic: 'tactic',
      severity: 'severity',
      source: 'source',
      description: 'description',
      response: 'response',
      assetTypes: 'asset_types',
      internalSource: 'internal_source',
      enabled: 'enabled',
      updatedAt: 'updated_at'
    });
    if (!set) return detectionRules.byId(id);
    run(`UPDATE detection_rules SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return detectionRules.byId(id);
  },

  remove(id) {
    return run('DELETE FROM detection_rules WHERE id = ?', [id]).changes > 0;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM detection_rules WHERE enabled = 1').n;
  }
};

/* -------------------------------------------------- notification prefs */

const DEFAULT_PREFS = {
  emailEnabled: false,
  minSeverity: 'high',
  cadence: 'immediate',
  onIncident: true,
  onCritical: true,
  onAssignment: true,
  quietHours: null
};

function mapPrefs(row, userId) {
  if (!row) return { userId, ...DEFAULT_PREFS, updatedAt: null };
  return {
    userId: row.user_id,
    emailEnabled: bool(row.email_enabled),
    minSeverity: row.min_severity,
    cadence: row.cadence,
    onIncident: bool(row.on_incident),
    onCritical: bool(row.on_critical),
    onAssignment: bool(row.on_assignment),
    quietHours: row.quiet_hours,
    updatedAt: row.updated_at
  };
}

const notificationPrefs = {
  /** Always returns a usable object; an absent row means "opted out". */
  forUser(userId) {
    return mapPrefs(get('SELECT * FROM notification_prefs WHERE user_id = ?', [userId]), userId);
  },

  upsert(userId, patch) {
    const current = notificationPrefs.forUser(userId);
    const next = { ...current, ...patch };

    run(
      `INSERT INTO notification_prefs
         (user_id, email_enabled, min_severity, cadence, on_incident, on_critical,
          on_assignment, quiet_hours, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         email_enabled = excluded.email_enabled,
         min_severity  = excluded.min_severity,
         cadence       = excluded.cadence,
         on_incident   = excluded.on_incident,
         on_critical   = excluded.on_critical,
         on_assignment = excluded.on_assignment,
         quiet_hours   = excluded.quiet_hours,
         updated_at    = excluded.updated_at`,
      [
        userId,
        flag(next.emailEnabled),
        next.minSeverity,
        next.cadence,
        flag(next.onIncident),
        flag(next.onCritical),
        flag(next.onAssignment),
        next.quietHours || null,
        new Date().toISOString()
      ]
    );

    return notificationPrefs.forUser(userId);
  },

  /** Everyone who has opted in — the fan-out list for an event. */
  subscribers() {
    const rows = all(
      `SELECT p.*, u.email, u.name, u.disabled
         FROM notification_prefs p
         JOIN users u ON u.id = p.user_id
        WHERE p.email_enabled = 1 AND u.disabled = 0`
    );
    return rows.map((row) => ({
      ...mapPrefs(row, row.user_id),
      email: row.email,
      name: row.name
    }));
  }
};

/* ------------------------------------------------------------ email log */

const emailLog = {
  insert(entry) {
    run(
      `INSERT INTO email_log (id, to_address, subject, kind, status, transport, error, preview, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.id,
        entry.to,
        entry.subject,
        entry.kind,
        entry.status,
        entry.transport,
        entry.error ? String(entry.error).slice(0, 300) : null,
        entry.preview ? String(entry.preview).slice(0, 400) : null,
        entry.createdAt
      ]
    );
    return entry;
  },

  list(limit = 100) {
    return all('SELECT * FROM email_log ORDER BY created_at DESC LIMIT ?', [limit]).map((row) => ({
      id: row.id,
      to: row.to_address,
      subject: row.subject,
      kind: row.kind,
      status: row.status,
      transport: row.transport,
      error: row.error,
      preview: row.preview,
      createdAt: row.created_at
    }));
  },

  trim(max) {
    return run(
      `DELETE FROM email_log WHERE id NOT IN (
         SELECT id FROM email_log ORDER BY created_at DESC LIMIT ?
       )`,
      [max]
    ).changes;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM email_log').n;
  }
};

/* --------------------------------------------------- notification queue */

const notificationQueue = {
  push(entry) {
    run(
      'INSERT INTO notification_queue (user_id, kind, subject, payload, created_at) VALUES (?, ?, ?, ?, ?)',
      [entry.userId, entry.kind, entry.subject, JSON.stringify(entry.payload), entry.createdAt]
    );
  },

  /** Undelivered items for one recipient, oldest first. */
  pendingFor(userId) {
    return all(
      'SELECT * FROM notification_queue WHERE user_id = ? AND sent_at IS NULL ORDER BY id',
      [userId]
    ).map((row) => ({
      id: row.id,
      kind: row.kind,
      subject: row.subject,
      payload: JSON.parse(row.payload),
      createdAt: row.created_at
    }));
  },

  /** Distinct recipients with something waiting. */
  pendingRecipients() {
    return all(
      'SELECT DISTINCT user_id FROM notification_queue WHERE sent_at IS NULL'
    ).map((row) => row.user_id);
  },

  markSent(ids, now = new Date().toISOString()) {
    if (!ids.length) return 0;
    return run(
      `UPDATE notification_queue SET sent_at = ? WHERE id IN (${ids.map(() => '?').join(',')})`,
      [now, ...ids]
    ).changes;
  },

  prune(before) {
    return run('DELETE FROM notification_queue WHERE sent_at IS NOT NULL AND sent_at < ?', [before])
      .changes;
  }
};

/* --------------------------------------------------- containment actions */

function mapContainment(row) {
  if (!row) return null;
  return {
    id: row.id,
    incidentId: row.incident_id,
    alertId: row.alert_id,
    action: row.action,
    target: row.target,
    scope: row.scope,
    reason: row.reason,
    authorisedBy: row.authorised_by,
    performedBy: row.performed_by,
    performedAt: row.performed_at,
    revertedAt: row.reverted_at,
    revertedBy: row.reverted_by,
    revertReason: row.revert_reason,
    active: !row.reverted_at
  };
}

const containment = {
  insert(action) {
    run(
      `INSERT INTO containment_actions
         (id, incident_id, alert_id, action, target, scope, reason,
          authorised_by, performed_by, performed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        action.id,
        action.incidentId || null,
        action.alertId || null,
        action.action,
        action.target,
        action.scope || null,
        action.reason,
        action.authorisedBy || null,
        action.performedBy,
        action.performedAt
      ]
    );
    return containment.byId(action.id);
  },

  byId(id) {
    return mapContainment(get('SELECT * FROM containment_actions WHERE id = ?', [id]));
  },

  forIncident(incidentId) {
    return all(
      'SELECT * FROM containment_actions WHERE incident_id = ? ORDER BY performed_at DESC, id DESC',
      [incidentId]
    ).map(mapContainment);
  },

  list(limit = 200) {
    return all('SELECT * FROM containment_actions ORDER BY performed_at DESC LIMIT ?', [
      limit
    ]).map(mapContainment);
  },

  /**
   * Marks a containment as lifted. Guarded in the statement so two analysts
   * cannot both record the reversal of the same action.
   */
  revert(id, { revertedBy, reason, now = new Date().toISOString() }) {
    return (
      run(
        `UPDATE containment_actions
            SET reverted_at = ?, reverted_by = ?, revert_reason = ?
          WHERE id = ? AND reverted_at IS NULL`,
        [now, revertedBy, reason || null, id]
      ).changes > 0
    );
  },

  activeCount() {
    return get('SELECT COUNT(*) AS n FROM containment_actions WHERE reverted_at IS NULL').n;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM containment_actions').n;
  }
};


/* -------------------------------------------------------- analyst pods */

function mapPod(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    region: row.region,
    description: row.description,
    createdAt: row.created_at,
    active: bool(row.active)
  };
}

const pods = {
  insert(pod) {
    run(
      'INSERT INTO analyst_pods (id, name, region, description, created_at, active) VALUES (?, ?, ?, ?, ?, ?)',
      [pod.id, pod.name, pod.region, pod.description || null, pod.createdAt, flag(pod.active === undefined ? true : pod.active)]
    );
    return pods.byId(pod.id);
  },

  byId(id) {
    return mapPod(get('SELECT * FROM analyst_pods WHERE id = ?', [id]));
  },

  list() {
    return all('SELECT * FROM analyst_pods ORDER BY region, name').map((row) => ({
      ...mapPod(row),
      members: pods.members(row.id)
    }));
  },

  /** Members with their tier, joined to the user so the console shows names. */
  members(podId) {
    return all(
      `SELECT m.tier, m.joined_at, u.id, u.name, u.email, u.role
         FROM pod_members m
         JOIN users u ON u.id = m.user_id
        WHERE m.pod_id = ?
        ORDER BY m.tier, u.name`,
      [podId]
    ).map((row) => ({
      userId: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      tier: row.tier,
      joinedAt: row.joined_at
    }));
  },

  addMember(podId, userId, tier, now = new Date().toISOString()) {
    run(
      `INSERT INTO pod_members (pod_id, user_id, tier, joined_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(pod_id, user_id) DO UPDATE SET tier = excluded.tier`,
      [podId, userId, tier, now]
    );
    return pods.members(podId);
  },

  removeMember(podId, userId) {
    return run('DELETE FROM pod_members WHERE pod_id = ? AND user_id = ?', [podId, userId]).changes > 0;
  },

  update(id, patch) {
    const set = setClause(patch, {
      name: 'name',
      region: 'region',
      description: 'description',
      active: 'active'
    });
    if (!set) return pods.byId(id);
    run(`UPDATE analyst_pods SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return pods.byId(id);
  },

  remove(id) {
    return run('DELETE FROM analyst_pods WHERE id = ?', [id]).changes > 0;
  },

  /** Which pods a user belongs to — used to route work to them. */
  forUser(userId) {
    return all(
      `SELECT p.*, m.tier FROM analyst_pods p
         JOIN pod_members m ON m.pod_id = p.id
        WHERE m.user_id = ?`,
      [userId]
    ).map((row) => ({ ...mapPod(row), tier: row.tier }));
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM analyst_pods WHERE active = 1').n;
  }
};

/* --------------------------------------------------------------- shifts */

function mapShift(row) {
  if (!row) return null;
  return {
    id: row.id,
    region: row.region,
    label: row.label,
    podId: row.pod_id,
    startHour: row.start_hour,
    endHour: row.end_hour,
    active: bool(row.active),
    createdAt: row.created_at
  };
}

const socShifts = {
  insert(shift) {
    run(
      `INSERT INTO soc_shifts (id, region, label, pod_id, start_hour, end_hour, active, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        shift.id,
        shift.region,
        shift.label,
        shift.podId || null,
        shift.startHour,
        shift.endHour,
        flag(shift.active === undefined ? true : shift.active),
        shift.createdAt
      ]
    );
    return socShifts.byId(shift.id);
  },

  byId(id) {
    return mapShift(get('SELECT * FROM soc_shifts WHERE id = ?', [id]));
  },

  list() {
    return all('SELECT * FROM soc_shifts ORDER BY start_hour, region').map((row) => {
      const shift = mapShift(row);
      shift.pod = shift.podId ? pods.byId(shift.podId) : null;
      return shift;
    });
  },

  update(id, patch) {
    const set = setClause(patch, {
      region: 'region',
      label: 'label',
      podId: 'pod_id',
      startHour: 'start_hour',
      endHour: 'end_hour',
      active: 'active'
    });
    if (!set) return socShifts.byId(id);
    run(`UPDATE soc_shifts SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return socShifts.byId(id);
  },

  remove(id) {
    return run('DELETE FROM soc_shifts WHERE id = ?', [id]).changes > 0;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM soc_shifts WHERE active = 1').n;
  }
};

/* ------------------------------------------------------------ handovers */

const handovers = {
  insert(entry) {
    run(
      `INSERT INTO shift_handovers
         (id, from_shift, to_shift, from_region, to_region, notes, open_incidents, open_count, created_by, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.id,
        entry.fromShift || null,
        entry.toShift || null,
        entry.fromRegion || null,
        entry.toRegion || null,
        entry.notes,
        JSON.stringify(entry.openIncidents || []),
        (entry.openIncidents || []).length,
        entry.createdBy,
        entry.createdAt
      ]
    );
    return handovers.byId(entry.id);
  },

  byId(id) {
    const row = get('SELECT * FROM shift_handovers WHERE id = ?', [id]);
    return row ? mapHandover(row) : null;
  },

  list(limit = 25) {
    return all('SELECT * FROM shift_handovers ORDER BY created_at DESC LIMIT ?', [limit]).map(
      mapHandover
    );
  },

  latest() {
    const row = get('SELECT * FROM shift_handovers ORDER BY created_at DESC LIMIT 1');
    return row ? mapHandover(row) : null;
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM shift_handovers').n;
  }
};

function mapHandover(row) {
  let openIncidents = [];
  try {
    openIncidents = JSON.parse(row.open_incidents || '[]');
  } catch {
    openIncidents = [];
  }
  return {
    id: row.id,
    fromShift: row.from_shift,
    toShift: row.to_shift,
    fromRegion: row.from_region,
    toRegion: row.to_region,
    notes: row.notes,
    openIncidents,
    openCount: row.open_count,
    createdBy: row.created_by,
    createdAt: row.created_at
  };
}

/* ---------------------------------------------------------- escalations */

function mapEscalation(row) {
  if (!row) return null;
  return {
    id: row.id,
    incidentId: row.incident_id,
    priority: row.priority,
    reason: row.reason,
    bridgeRef: row.bridge_ref,
    raisedBy: row.raised_by,
    raisedAt: row.raised_at,
    acknowledgedBy: row.acknowledged_by,
    acknowledgedAt: row.acknowledged_at,
    resolvedAt: row.resolved_at,
    resolution: row.resolution,
    open: !row.resolved_at,
    // The number the "analyst on your bridge in minutes" claim rests on.
    acknowledgeSeconds: row.acknowledged_at
      ? Math.round((new Date(row.acknowledged_at) - new Date(row.raised_at)) / 1000)
      : null
  };
}

const escalations = {
  insert(entry) {
    run(
      `INSERT INTO escalations (id, incident_id, priority, reason, bridge_ref, raised_by, raised_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        entry.id,
        entry.incidentId || null,
        entry.priority,
        entry.reason,
        entry.bridgeRef || null,
        entry.raisedBy,
        entry.raisedAt
      ]
    );
    return escalations.byId(entry.id);
  },

  byId(id) {
    return mapEscalation(get('SELECT * FROM escalations WHERE id = ?', [id]));
  },

  list(limit = 50) {
    return all('SELECT * FROM escalations ORDER BY raised_at DESC LIMIT ?', [limit]).map(
      mapEscalation
    );
  },

  forIncident(incidentId) {
    return all('SELECT * FROM escalations WHERE incident_id = ? ORDER BY raised_at DESC', [
      incidentId
    ]).map(mapEscalation);
  },

  /** Guarded in the statement so two responders cannot both claim the bridge. */
  acknowledge(id, { by, now = new Date().toISOString() }) {
    return (
      run(
        'UPDATE escalations SET acknowledged_by = ?, acknowledged_at = ? WHERE id = ? AND acknowledged_at IS NULL',
        [by, now, id]
      ).changes > 0
    );
  },

  resolve(id, { resolution, now = new Date().toISOString() }) {
    return (
      run(
        'UPDATE escalations SET resolved_at = ?, resolution = ? WHERE id = ? AND resolved_at IS NULL',
        [now, resolution || null, id]
      ).changes > 0
    );
  },

  openCount() {
    return get('SELECT COUNT(*) AS n FROM escalations WHERE resolved_at IS NULL').n;
  },

  /** Median acknowledgement time, from the records rather than a claim. */
  acknowledgeDurations(sinceIso = null) {
    const clause = sinceIso ? 'AND raised_at >= ?' : '';
    const params = sinceIso ? [sinceIso] : [];
    return all(
      `SELECT raised_at, acknowledged_at, priority FROM escalations
        WHERE acknowledged_at IS NOT NULL ${clause}`,
      params
    ).map((row) => ({
      priority: row.priority,
      seconds: Math.round((new Date(row.acknowledged_at) - new Date(row.raised_at)) / 1000)
    }));
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM escalations').n;
  }
};


/* ------------------------------------------------ vulnerability catalogue */

function mapVuln(row) {
  if (!row) return null;
  return {
    cve: row.cve,
    title: row.title,
    vendor: row.vendor,
    product: row.product,
    cvss: row.cvss,
    cvssVector: row.cvss_vector,
    epss: row.epss,
    epssPercentile: row.epss_percentile,
    kev: bool(row.kev),
    kevAdded: row.kev_added,
    published: row.published,
    summary: row.summary,
    fixVersion: row.fix_version,
    appliesTo: row.applies_to ? row.applies_to.split(',').filter(Boolean) : [],
    updatedAt: row.updated_at
  };
}

const vulnerabilities = {
  insert(vuln) {
    run(
      `INSERT INTO vulnerabilities
         (cve, title, vendor, product, cvss, cvss_vector, epss, epss_percentile,
          kev, kev_added, published, summary, fix_version, applies_to, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(cve) DO UPDATE SET
         cvss = excluded.cvss,
         epss = excluded.epss,
         epss_percentile = excluded.epss_percentile,
         kev = excluded.kev,
         kev_added = excluded.kev_added,
         fix_version = excluded.fix_version,
         updated_at = excluded.updated_at`,
      [
        vuln.cve,
        vuln.title,
        vuln.vendor || null,
        vuln.product,
        vuln.cvss,
        vuln.cvssVector || null,
        vuln.epss,
        vuln.epssPercentile || null,
        flag(vuln.kev),
        vuln.kevAdded || null,
        vuln.published || null,
        vuln.summary || null,
        vuln.fixVersion || null,
        (vuln.appliesTo || []).join(','),
        vuln.updatedAt || new Date().toISOString()
      ]
    );
    return vulnerabilities.byId(vuln.cve);
  },

  byId(cve) {
    return mapVuln(get('SELECT * FROM vulnerabilities WHERE cve = ?', [cve]));
  },

  list() {
    // Ordered by EPSS rather than CVSS — the catalogue's own default should
    // not contradict how findings are ranked.
    return all('SELECT * FROM vulnerabilities ORDER BY kev DESC, epss DESC').map(mapVuln);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM vulnerabilities').n;
  }
};

/* --------------------------------------------------------------- findings */

function mapFinding(row) {
  if (!row) return null;
  return {
    id: row.id,
    cve: row.cve,
    assetId: row.asset_id,
    surface: row.surface,
    status: row.status,
    exposureScore: row.exposure_score,
    firstSeen: row.first_seen,
    lastSeen: row.last_seen,
    assignedTo: row.assigned_to,
    dueAt: row.due_at,
    resolvedAt: row.resolved_at,
    resolvedBy: row.resolved_by,
    verifiedAt: row.verified_at,
    acceptedBy: row.accepted_by,
    acceptedUntil: row.accepted_until,
    acceptedReason: row.accepted_reason,
    notes: row.notes
  };
}

const vulnFindings = {
  insert(finding) {
    run(
      `INSERT INTO vuln_findings
         (id, cve, asset_id, surface, status, exposure_score, first_seen, last_seen, due_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        finding.id,
        finding.cve,
        finding.assetId,
        finding.surface || 'internal',
        finding.status || 'open',
        finding.exposureScore || 0,
        finding.firstSeen,
        finding.lastSeen,
        finding.dueAt || null
      ]
    );
    return vulnFindings.byId(finding.id);
  },

  byId(id) {
    return mapFinding(get('SELECT * FROM vuln_findings WHERE id = ?', [id]));
  },

  /** The uniqueness key: one open finding per CVE per asset per surface. */
  byKey(cve, assetId, surface) {
    return mapFinding(
      get('SELECT * FROM vuln_findings WHERE cve = ? AND asset_id = ? AND surface = ?', [
        cve,
        assetId,
        surface
      ])
    );
  },

  query(q = {}) {
    const where = [];
    const params = [];

    if (q.status && q.status !== 'all') {
      where.push('status = ?');
      params.push(q.status);
    }
    if (q.surface) {
      where.push('surface = ?');
      params.push(q.surface);
    }
    if (q.assetId) {
      where.push('asset_id = ?');
      params.push(q.assetId);
    }
    if (q.cve) {
      where.push('cve = ?');
      params.push(q.cve);
    }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const limit = Math.min(Number(q.limit) || 100, 1000);

    return all(
      `SELECT * FROM vuln_findings ${clause} ORDER BY exposure_score DESC, id LIMIT ?`,
      [...params, limit]
    ).map(mapFinding);
  },

  update(id, patch) {
    const set = setClause(patch, {
      status: 'status',
      exposureScore: 'exposure_score',
      lastSeen: 'last_seen',
      assignedTo: 'assigned_to',
      dueAt: 'due_at',
      resolvedAt: 'resolved_at',
      resolvedBy: 'resolved_by',
      verifiedAt: 'verified_at',
      acceptedBy: 'accepted_by',
      acceptedUntil: 'accepted_until',
      acceptedReason: 'accepted_reason',
      notes: 'notes'
    });
    if (!set) return vulnFindings.byId(id);
    run(`UPDATE vuln_findings SET ${set.clause} WHERE id = ?`, [...set.values, id]);
    return vulnFindings.byId(id);
  },

  /** Blast radius: how many assets this CVE is actually open on. */
  countForCve(cve) {
    return get(
      "SELECT COUNT(*) AS n FROM vuln_findings WHERE cve = ? AND status IN ('open','remediating')",
      [cve]
    ).n;
  },

  counts() {
    const row = get(
      `SELECT
         COUNT(*) AS total,
         SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
         SUM(CASE WHEN status = 'remediating' THEN 1 ELSE 0 END) AS remediating,
         SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved,
         SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
         SUM(CASE WHEN verified_at IS NOT NULL THEN 1 ELSE 0 END) AS verified
       FROM vuln_findings`
    );
    return {
      total: row.total || 0,
      open: row.open || 0,
      remediating: row.remediating || 0,
      resolved: row.resolved || 0,
      accepted: row.accepted || 0,
      verified: row.verified || 0
    };
  },

  overdueCount(now = new Date().toISOString()) {
    return get(
      "SELECT COUNT(*) AS n FROM vuln_findings WHERE due_at < ? AND status IN ('open','remediating')",
      [now]
    ).n;
  },

  /**
   * Risk acceptances that have run out.
   *
   * An acceptance without an expiry is a permanent exception nobody revisits,
   * so they carry one and come back when it lapses.
   */
  expiredAcceptances(now = new Date().toISOString()) {
    return all(
      "SELECT * FROM vuln_findings WHERE status = 'accepted' AND accepted_until IS NOT NULL AND accepted_until < ?",
      [now]
    ).map(mapFinding);
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM vuln_findings').n;
  }
};

/* ------------------------------------------------------------------ scans */

function mapScan(row) {
  if (!row) return null;
  return {
    id: row.id,
    kind: row.kind,
    surface: row.surface,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    assetsScanned: row.assets_scanned,
    findingsNew: row.findings_new,
    findingsResolved: row.findings_resolved,
    findingsSeen: row.findings_seen,
    triggeredBy: row.triggered_by,
    target: row.target,
    durationMs: row.finished_at
      ? new Date(row.finished_at) - new Date(row.started_at)
      : null
  };
}

const vulnScans = {
  insert(scan) {
    run(
      `INSERT INTO vuln_scans (id, kind, surface, started_at, triggered_by, target)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [scan.id, scan.kind, scan.surface || null, scan.startedAt, scan.triggeredBy || null, scan.target || null]
    );
    return vulnScans.byId(scan.id);
  },

  finish(id, result) {
    run(
      `UPDATE vuln_scans
          SET finished_at = ?, assets_scanned = ?, findings_new = ?,
              findings_resolved = ?, findings_seen = ?
        WHERE id = ?`,
      [
        result.finishedAt,
        result.assetsScanned || 0,
        result.findingsNew || 0,
        result.findingsResolved || 0,
        result.findingsSeen || 0,
        id
      ]
    );
    return vulnScans.byId(id);
  },

  byId(id) {
    return mapScan(get('SELECT * FROM vuln_scans WHERE id = ?', [id]));
  },

  list(limit = 25) {
    return all('SELECT * FROM vuln_scans ORDER BY started_at DESC LIMIT ?', [limit]).map(mapScan);
  },

  latest() {
    return mapScan(get('SELECT * FROM vuln_scans ORDER BY started_at DESC LIMIT 1'));
  },

  count() {
    return get('SELECT COUNT(*) AS n FROM vuln_scans').n;
  }
};

module.exports = {
  users,
  sessions,
  alerts,
  incidents,
  assets,
  contacts,
  audit,
  admin,
  recoveryCodes,
  passwordResets,
  apiKeys,
  webhooks,
  detectionRules,
  notificationPrefs,
  emailLog,
  notificationQueue,
  containment,
  pods,
  socShifts,
  handovers,
  escalations,
  vulnerabilities,
  vulnFindings,
  vulnScans
};
