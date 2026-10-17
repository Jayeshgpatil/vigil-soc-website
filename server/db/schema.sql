-- VGIL — baseline schema (migration 1)
--
-- Timestamps are stored as ISO-8601 UTC strings. That keeps them readable in
-- the file, sorts correctly under plain lexicographic comparison, and is
-- understood by SQLite's julianday()/strftime() for duration maths.
-- Booleans are INTEGER 0/1; the repository maps them back to JS booleans.

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  name          TEXT    NOT NULL,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  role          TEXT    NOT NULL DEFAULT 'analyst',
  org           TEXT,
  title         TEXT,
  created_at    TEXT    NOT NULL,
  last_login    TEXT,
  disabled      INTEGER NOT NULL DEFAULT 0,
  mfa_enabled   INTEGER NOT NULL DEFAULT 0,
  demo          INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issued_at  TEXT    NOT NULL,
  expires_at TEXT    NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0,
  ip         TEXT,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS assets (
  id             TEXT PRIMARY KEY,
  host           TEXT NOT NULL,
  ip             TEXT,
  type           TEXT,
  zone           TEXT,
  criticality    TEXT,
  owner          TEXT,
  status         TEXT,
  agent_version  TEXT,
  last_seen      TEXT,
  open_findings  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_assets_zone ON assets(zone);

CREATE TABLE IF NOT EXISTS incidents (
  id              TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL,
  status          TEXT NOT NULL,
  priority        TEXT,
  summary         TEXT,
  rule_id         TEXT,
  rule            TEXT,
  technique       TEXT,
  tactic          TEXT,
  asset_id        TEXT,
  host            TEXT,
  zone            TEXT,
  owner           TEXT,
  analyst         TEXT,
  source_alert_id TEXT,
  opened_at       TEXT NOT NULL,
  acknowledged_at TEXT,
  closed_at       TEXT,
  updated_at      TEXT,
  seeded          INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_incidents_opened   ON incidents(opened_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_source   ON incidents(source_alert_id);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts          TEXT NOT NULL,
  actor       TEXT,
  entry       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id, id);

CREATE TABLE IF NOT EXISTS alerts (
  id             TEXT PRIMARY KEY,
  ts             TEXT    NOT NULL,
  rule_id        TEXT    NOT NULL,
  rule           TEXT    NOT NULL,
  severity       TEXT    NOT NULL,
  tactic         TEXT,
  technique      TEXT,
  technique_name TEXT,
  source         TEXT,
  description    TEXT,
  recommendation TEXT,
  asset_id       TEXT,
  host           TEXT,
  ip             TEXT,
  zone           TEXT,
  asset_type     TEXT,
  criticality    TEXT,
  owner          TEXT,
  "user"         TEXT,
  source_ip      TEXT,
  dest_port      INTEGER,
  confidence     INTEGER,
  risk           INTEGER,
  status         TEXT    NOT NULL DEFAULT 'new',
  assignee       TEXT,
  indicator      TEXT,
  indicator_type TEXT,
  actor          TEXT,
  incident_id    TEXT,
  updated_at     TEXT
);

-- The console's default view is "newest first", and every list query filters
-- on some combination of severity/status/technique, so each gets an index.
CREATE INDEX IF NOT EXISTS idx_alerts_ts        ON alerts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status    ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_technique ON alerts(technique);
CREATE INDEX IF NOT EXISTS idx_alerts_asset     ON alerts(asset_id);
CREATE INDEX IF NOT EXISTS idx_alerts_incident  ON alerts(incident_id);
CREATE INDEX IF NOT EXISTS idx_alerts_risk      ON alerts(risk DESC);

CREATE TABLE IF NOT EXISTS alert_notes (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id TEXT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  ts       TEXT NOT NULL,
  author   TEXT,
  text     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_notes_alert ON alert_notes(alert_id, id);

CREATE TABLE IF NOT EXISTS contacts (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  email        TEXT NOT NULL,
  company      TEXT,
  employees    TEXT,
  interest     TEXT,
  urgency      TEXT,
  message      TEXT NOT NULL,
  ip           TEXT,
  submitted_at TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'new'
);

CREATE INDEX IF NOT EXISTS idx_contacts_submitted ON contacts(submitted_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY,
  ts         TEXT NOT NULL,
  action     TEXT NOT NULL,
  detail     TEXT,
  ip         TEXT,
  user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
