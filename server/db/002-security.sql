-- VGIL — migration 2: second-factor auth, password recovery, API keys, webhooks
--
-- Same conventions as the baseline: ISO-8601 UTC strings for timestamps,
-- INTEGER 0/1 for booleans, mapped back to JS types by the repository.
--
-- Every credential stored here is hashed. Nothing in this migration keeps a
-- secret the server could hand back to anyone, including an administrator.

-- ---------------------------------------------------------------- 2FA ----

-- The confirmed TOTP secret. NULL until the user proves they can generate a
-- valid code, so an abandoned enrolment never locks anyone out.
ALTER TABLE users ADD COLUMN mfa_secret TEXT;

-- Held only between "show me the QR" and the first correct code.
ALTER TABLE users ADD COLUMN mfa_pending_secret TEXT;

ALTER TABLE users ADD COLUMN mfa_confirmed_at TEXT;

-- The last counter step accepted for this user. A code stays mathematically
-- valid for its whole 30-second window, so without this an attacker who
-- observes one can replay it until it expires.
ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER;

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  TEXT NOT NULL,
  created_at TEXT NOT NULL,
  used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_recovery_user ON mfa_recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_hash ON mfa_recovery_codes(code_hash);

-- ------------------------------------------------------ password resets ----

-- Issued by an administrator. There is no mail transport on this deployment,
-- so the link is handed over out of band rather than emailed; the row is the
-- same either way, which is what lets SMTP be added later without a schema
-- change.
CREATE TABLE IF NOT EXISTS password_resets (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at    TEXT,
  issued_by  TEXT,
  ip         TEXT
);

CREATE INDEX IF NOT EXISTS idx_resets_hash ON password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_resets_user ON password_resets(user_id);

-- ------------------------------------------------------------ api keys ----

-- `prefix` is the first 8 characters of the plaintext, stored alongside the
-- hash. It lets the console show which key is which, and lets lookup find the
-- candidate row directly instead of hashing the presented key against every
-- row in the table.
CREATE TABLE IF NOT EXISTS api_keys (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  key_hash     TEXT NOT NULL,
  scopes       TEXT NOT NULL DEFAULT 'read',
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  expires_at   TEXT,
  revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_apikeys_user   ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_apikeys_prefix ON api_keys(prefix);

-- ------------------------------------------------------------ webhooks ----

-- `secret` signs the outgoing payload so the receiver can verify it came from
-- this instance. It is stored in the clear because HMAC signing needs the
-- original key material — unlike every other credential here, it is not a
-- password being checked against a presented value.
CREATE TABLE IF NOT EXISTS webhooks (
  id              TEXT PRIMARY KEY,
  url             TEXT NOT NULL,
  description     TEXT,
  secret          TEXT NOT NULL,
  events          TEXT NOT NULL DEFAULT 'incident.opened',
  active          INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL,
  created_by      TEXT,
  last_status     TEXT,
  last_attempt_at TEXT,
  last_error      TEXT,
  failure_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  webhook_id    TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
  event         TEXT NOT NULL,
  status        TEXT NOT NULL,
  response_code INTEGER,
  error         TEXT,
  attempted_at  TEXT NOT NULL,
  duration_ms   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_deliveries_hook ON webhook_deliveries(webhook_id, id DESC);
