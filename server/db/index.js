'use strict';

/**
 * SQLite connection. Uses node:sqlite, so there is no native module to build
 * and no third-party driver in the dependency tree.
 *
 * Set VGIL_DB to relocate the file, or to ':memory:' for a throwaway database
 * (the test suite does exactly that).
 */

const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { migrate } = require('./migrate');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DEFAULT_FILE = path.join(DATA_DIR, 'vgil.db');

let db = null;
let dbPath = null;

function resolvePath() {
  const configured = process.env.VGIL_DB;
  if (!configured) return DEFAULT_FILE;
  if (configured === ':memory:') return ':memory:';
  return path.isAbsolute(configured) ? configured : path.join(process.cwd(), configured);
}

/** Opens the connection (idempotent) and brings the schema up to date. */
function open({ quiet = false } = {}) {
  if (db) return db;

  dbPath = resolvePath();

  if (dbPath !== ':memory:') {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  db = new DatabaseSync(dbPath);

  // WAL lets the SSE-driven write stream continue while readers are active.
  // NORMAL synchronous is the right trade for WAL: durable across process
  // crashes, only at risk in a hard power loss.
  if (dbPath !== ':memory:') db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  db.exec('PRAGMA foreign_keys = ON');
  db.exec('PRAGMA busy_timeout = 5000');

  migrate(db, { quiet });

  return db;
}

function handle() {
  return db || open();
}

function close() {
  if (!db) return;
  try {
    // Fold the WAL back into the main file so a copied .db is complete.
    if (dbPath !== ':memory:') db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch {
    /* a checkpoint failure must not block shutdown */
  }
  db.close();
  db = null;
}

/**
 * Runs fn inside a transaction, rolling back if it throws.
 * Nested calls reuse the outer transaction rather than failing.
 */
let depth = 0;

function transaction(fn) {
  const conn = handle();

  if (depth > 0) return fn(conn);

  conn.exec('BEGIN');
  depth += 1;
  try {
    const result = fn(conn);
    conn.exec('COMMIT');
    return result;
  } catch (err) {
    conn.exec('ROLLBACK');
    throw err;
  } finally {
    depth -= 1;
  }
}

module.exports = {
  open,
  handle,
  close,
  transaction,
  get path() {
    return dbPath;
  }
};
