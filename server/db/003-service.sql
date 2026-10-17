-- VGIL — migration 3: the three plan features that had no implementation
--
-- The pricing page sold "email and portal alerting", "custom detection
-- engineering" and "managed containment actions" while only the portal half
-- of the first existed. These are the tables behind the other three.

-- --------------------------------------------------- custom detections ----

-- Customer-authored rules, alongside the built-in catalogue. Same shape, so
-- the engine treats both identically and a custom rule is a first-class
-- detection rather than a second tier.
CREATE TABLE IF NOT EXISTS detection_rules (
  id              TEXT PRIMARY KEY,
  name            TEXT    NOT NULL,
  technique       TEXT,
  technique_name  TEXT,
  tactic          TEXT,
  severity        TEXT    NOT NULL,
  source          TEXT,
  description     TEXT,
  response        TEXT,
  -- Comma-separated asset types this rule can fire on. Empty means any, which
  -- is what stopped a Kerberoasting alert appearing against an S3 bucket.
  asset_types     TEXT,
  internal_source INTEGER NOT NULL DEFAULT 0,
  enabled         INTEGER NOT NULL DEFAULT 1,
  created_by      TEXT,
  created_at      TEXT    NOT NULL,
  updated_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled ON detection_rules(enabled);

-- ------------------------------------------------ notification settings ----

-- One row per user. Absent means "never emailed": alerting is opt-in, because
-- a monitoring product that mails everyone by default trains its users to
-- filter it into a folder they never read.
CREATE TABLE IF NOT EXISTS notification_prefs (
  user_id         TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  email_enabled   INTEGER NOT NULL DEFAULT 0,
  min_severity    TEXT    NOT NULL DEFAULT 'high',
  -- immediate | hourly | daily. Anything but immediate batches into a digest
  -- so a noisy night does not become two hundred separate messages.
  cadence         TEXT    NOT NULL DEFAULT 'immediate',
  on_incident     INTEGER NOT NULL DEFAULT 1,
  on_critical     INTEGER NOT NULL DEFAULT 1,
  on_assignment   INTEGER NOT NULL DEFAULT 1,
  quiet_hours     TEXT,
  updated_at      TEXT
);

-- Delivery record. Holds a short preview rather than the message body: there
-- is no reason to keep a second copy of alert detail in a second table.
CREATE TABLE IF NOT EXISTS email_log (
  id           TEXT PRIMARY KEY,
  to_address   TEXT NOT NULL,
  subject      TEXT NOT NULL,
  kind         TEXT NOT NULL,
  status       TEXT NOT NULL,
  transport    TEXT NOT NULL,
  error        TEXT,
  preview      TEXT,
  created_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_created ON email_log(created_at DESC);

-- Queue for anything not sent immediately. A digest run drains it.
CREATE TABLE IF NOT EXISTS notification_queue (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  subject    TEXT NOT NULL,
  payload    TEXT NOT NULL,
  created_at TEXT NOT NULL,
  sent_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_queue_pending ON notification_queue(user_id, sent_at);

-- ---------------------------------------------------------- containment ----

-- A record of a containment decision, NOT an instruction to a machine.
--
-- This platform has no agents connected to it, so a button claiming to have
-- isolated a host would be asserting something untrue — the same reason the
-- dashboard derives status from telemetry rather than setting it. What an
-- analyst actually needs during an incident is a defensible account of what
-- was done, by whom, under what authority, and when it was lifted. That is
-- what this table is: evidence, with a reversal trail.
CREATE TABLE IF NOT EXISTS containment_actions (
  id           TEXT PRIMARY KEY,
  incident_id  TEXT REFERENCES incidents(id) ON DELETE CASCADE,
  alert_id     TEXT,
  action       TEXT NOT NULL,
  target       TEXT NOT NULL,
  scope        TEXT,
  reason       TEXT NOT NULL,
  authorised_by TEXT,
  performed_by TEXT NOT NULL,
  performed_at TEXT NOT NULL,
  reverted_at  TEXT,
  reverted_by  TEXT,
  revert_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_containment_incident ON containment_actions(incident_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_containment_active ON containment_actions(reverted_at);
