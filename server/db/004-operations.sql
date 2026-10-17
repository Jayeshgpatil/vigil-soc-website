-- VGIL — migration 4: the tooling behind the 24/7 SOC claims
--
-- The services page sells follow-the-sun coverage, a 47-second median triage,
-- named analyst pods, monthly tuning against your own false-positive data, and
-- a direct P1 escalation bridge. The staffing is people. The rota, the
-- measurement and the routing are software, and none of it existed — the
-- "47s" was a string in a static object and the false-positive rate was the
-- literal 3.7 in computeStats().

-- ------------------------------------------------------------- triage ----

-- When an alert first moved out of 'new'. Time-to-triage was previously
-- unmeasurable: updated_at moves on every later edit too, so it answers
-- "when was this last touched", not "how long did somebody take to look".
ALTER TABLE alerts ADD COLUMN triaged_at TEXT;
ALTER TABLE alerts ADD COLUMN triaged_by TEXT;

-- ---------------------------------------------------- false positives ----

-- Marked on the alert rather than in a side table: every query that counts
-- alerts needs to know, and a join for a boolean is a poor trade.
ALTER TABLE alerts ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN fp_reason TEXT;
ALTER TABLE alerts ADD COLUMN fp_category TEXT;
ALTER TABLE alerts ADD COLUMN fp_marked_by TEXT;
ALTER TABLE alerts ADD COLUMN fp_marked_at TEXT;

CREATE INDEX IF NOT EXISTS idx_alerts_fp ON alerts(false_positive, rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_triaged ON alerts(triaged_at);

-- --------------------------------------------------------------- pods ----

CREATE TABLE IF NOT EXISTS analyst_pods (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  region      TEXT NOT NULL,
  description TEXT,
  created_at  TEXT NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS pod_members (
  pod_id    TEXT NOT NULL REFERENCES analyst_pods(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  -- 1 triage, 2 investigation, 3 threat hunting — the tiers the service
  -- description names.
  tier      INTEGER NOT NULL DEFAULT 1,
  joined_at TEXT NOT NULL,
  PRIMARY KEY (pod_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_pod_members_user ON pod_members(user_id);

-- -------------------------------------------------------------- rota ----

-- Follow-the-sun is a recurring daily window per region, not a row per day.
-- Storing every shift instance would mean generating rows forever and still not
-- answering "is 03:00 UTC covered" without scanning them.
--
-- Hours are UTC and the window may wrap midnight (start 22, end 06).
CREATE TABLE IF NOT EXISTS soc_shifts (
  id         TEXT PRIMARY KEY,
  region     TEXT NOT NULL,
  label      TEXT NOT NULL,
  pod_id     TEXT REFERENCES analyst_pods(id) ON DELETE SET NULL,
  start_hour INTEGER NOT NULL,
  end_hour   INTEGER NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_shifts_active ON soc_shifts(active);

-- What one shift hands the next. The open-incident snapshot is stored rather
-- than recomputed, because the point of a handover record is what the
-- outgoing analyst actually saw and said about it.
CREATE TABLE IF NOT EXISTS shift_handovers (
  id            TEXT PRIMARY KEY,
  from_shift    TEXT,
  to_shift      TEXT,
  from_region   TEXT,
  to_region     TEXT,
  notes         TEXT NOT NULL,
  open_incidents TEXT,
  open_count    INTEGER NOT NULL DEFAULT 0,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handovers_created ON shift_handovers(created_at DESC);

-- -------------------------------------------------------- escalation ----

-- The "no ticket queue for P1" path. An escalation is acknowledged by a
-- person, and the time between raising and acknowledgement is the number the
-- claim actually rests on.
CREATE TABLE IF NOT EXISTS escalations (
  id              TEXT PRIMARY KEY,
  incident_id     TEXT REFERENCES incidents(id) ON DELETE CASCADE,
  priority        TEXT NOT NULL,
  reason          TEXT NOT NULL,
  bridge_ref      TEXT,
  raised_by       TEXT NOT NULL,
  raised_at       TEXT NOT NULL,
  acknowledged_by TEXT,
  acknowledged_at TEXT,
  resolved_at     TEXT,
  resolution      TEXT
);

CREATE INDEX IF NOT EXISTS idx_escalations_open ON escalations(acknowledged_at);
CREATE INDEX IF NOT EXISTS idx_escalations_incident ON escalations(incident_id, id DESC);
