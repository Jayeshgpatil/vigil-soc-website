-- VGIL — migration 5: vulnerability and exposure management
--
-- The services page says findings are "prioritised by real exploitability —
-- EPSS, known-exploited status and blast radius in your environment — rather
-- than raw CVSS". The endpoint behind it did `sort((a, b) => b.cvss - a.cvss)`
-- over six hard-coded rows whose "affected: 3" was a literal rather than
-- anything counted from the asset inventory.
--
-- The important structural change is the split: a vulnerability is a fact
-- about software, a finding is that vulnerability *on one of your assets*.
-- Blast radius is only real if it is counted from findings.

-- ------------------------------------------------- vulnerability catalogue

CREATE TABLE IF NOT EXISTS vulnerabilities (
  cve             TEXT PRIMARY KEY,
  title           TEXT NOT NULL,
  vendor          TEXT,
  product         TEXT NOT NULL,
  -- Severity as published. Deliberately not the ranking signal: CVSS says how
  -- bad exploitation would be, not whether anyone is doing it.
  cvss            REAL,
  cvss_vector     TEXT,
  -- EPSS: modelled probability of exploitation in the next 30 days, 0..1.
  epss            REAL,
  epss_percentile REAL,
  -- On CISA's Known Exploited Vulnerabilities list. Not a probability — an
  -- observation that it is being used right now.
  kev             INTEGER NOT NULL DEFAULT 0,
  kev_added       TEXT,
  published       TEXT,
  summary         TEXT,
  fix_version     TEXT,
  -- Asset types this can apply to, so discovery does not report a Tomcat flaw
  -- against a storage bucket.
  applies_to      TEXT,
  updated_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_epss ON vulnerabilities(epss DESC);
CREATE INDEX IF NOT EXISTS idx_vulns_kev  ON vulnerabilities(kev);

-- ------------------------------------------------------------- findings

-- One row per (vulnerability, asset). This is what makes blast radius a
-- count rather than a claim.
CREATE TABLE IF NOT EXISTS vuln_findings (
  id             TEXT PRIMARY KEY,
  cve            TEXT NOT NULL REFERENCES vulnerabilities(cve) ON DELETE CASCADE,
  asset_id       TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  -- Where it was found: internal, external or cloud. An internet-facing
  -- instance of the same flaw is a different proposition from an internal one.
  surface        TEXT NOT NULL DEFAULT 'internal',
  status         TEXT NOT NULL DEFAULT 'open',
  exposure_score INTEGER NOT NULL DEFAULT 0,
  first_seen     TEXT NOT NULL,
  last_seen      TEXT NOT NULL,
  assigned_to    TEXT,
  due_at         TEXT,
  resolved_at    TEXT,
  resolved_by    TEXT,
  -- Set by a verification rescan, not by whoever clicked "done". A patch
  -- nobody confirmed is a patch nobody applied.
  verified_at    TEXT,
  accepted_by    TEXT,
  accepted_until TEXT,
  accepted_reason TEXT,
  notes          TEXT
);

-- The same CVE can only be open once per asset per surface.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_unique
  ON vuln_findings(cve, asset_id, surface);

CREATE INDEX IF NOT EXISTS idx_findings_status   ON vuln_findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_score    ON vuln_findings(exposure_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset    ON vuln_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_findings_due      ON vuln_findings(due_at);

-- ---------------------------------------------------------------- scans

-- Discovery and verification runs. A verification rescan after remediation is
-- what turns "we patched it" into evidence.
CREATE TABLE IF NOT EXISTS vuln_scans (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL,
  surface           TEXT,
  started_at        TEXT NOT NULL,
  finished_at       TEXT,
  assets_scanned    INTEGER NOT NULL DEFAULT 0,
  findings_new      INTEGER NOT NULL DEFAULT 0,
  findings_resolved INTEGER NOT NULL DEFAULT 0,
  findings_seen     INTEGER NOT NULL DEFAULT 0,
  triggered_by      TEXT,
  target            TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_started ON vuln_scans(started_at DESC);
