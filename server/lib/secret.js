'use strict';

/**
 * Session signing key.
 *
 * Resolution order:
 *   1. VGIL_SECRET from the environment — the right answer in production,
 *      where the key belongs in the deployment's secret store.
 *   2. server/data/.secret — generated once on first run so that sign-ins
 *      survive a restart during local development.
 *
 * Previously this fell back to a per-process random key, which meant every
 * restart silently invalidated every existing session.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const SECRET_FILE = path.join(DATA_DIR, '.secret');
const MIN_BYTES = 32;

function fromEnv() {
  const value = process.env.VGIL_SECRET;
  if (!value) return null;

  if (Buffer.byteLength(value) < MIN_BYTES) {
    throw new Error(
      `VGIL_SECRET is too short (${Buffer.byteLength(value)} bytes). ` +
        `Use at least ${MIN_BYTES}: openssl rand -hex 48`
    );
  }
  return value;
}

function fromFile() {
  try {
    const value = fs.readFileSync(SECRET_FILE, 'utf8').trim();
    return value.length >= MIN_BYTES ? value : null;
  } catch {
    return null;
  }
}

function generate() {
  const value = crypto.randomBytes(48).toString('hex');

  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

  // mode 0600 — owner read/write only. Advisory on Windows, enforced on POSIX.
  fs.writeFileSync(SECRET_FILE, value + '\n', { encoding: 'utf8', mode: 0o600 });

  console.warn(
    '[auth] generated a new signing key at server/data/.secret — ' +
      'set VGIL_SECRET in production instead.'
  );
  return value;
}

/**
 * In-memory keys are only acceptable where nothing is expected to persist,
 * which is exactly the test suite's situation.
 */
function ephemeral() {
  return crypto.randomBytes(48).toString('hex');
}

let cached = null;

function get() {
  if (cached) return cached;

  if (process.env.VGIL_DB === ':memory:' && !process.env.VGIL_SECRET) {
    cached = ephemeral();
    return cached;
  }

  cached = fromEnv() || fromFile() || generate();
  return cached;
}

module.exports = { get, SECRET_FILE, MIN_BYTES };
