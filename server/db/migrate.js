'use strict';

/**
 * Versioned migrations, tracked in SQLite's own `user_version` pragma so no
 * bookkeeping table is needed.
 *
 * Each entry runs inside a transaction. To change the schema, append a new
 * entry — never edit an existing one, or databases already at that version
 * will silently diverge from fresh ones.
 */

const fs = require('fs');
const path = require('path');

const MIGRATIONS = [
  {
    version: 1,
    name: 'baseline',
    up(db) {
      db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
    }
  },
  {
    version: 2,
    name: 'security',
    up(db) {
      db.exec(fs.readFileSync(path.join(__dirname, '002-security.sql'), 'utf8'));
    }
  },
  {
    version: 3,
    name: 'service',
    up(db) {
      db.exec(fs.readFileSync(path.join(__dirname, '003-service.sql'), 'utf8'));
    }
  },
  {
    version: 4,
    name: 'operations',
    up(db) {
      db.exec(fs.readFileSync(path.join(__dirname, '004-operations.sql'), 'utf8'));
    }
  },
  {
    version: 5,
    name: 'exposure',
    up(db) {
      db.exec(fs.readFileSync(path.join(__dirname, '005-exposure.sql'), 'utf8'));
    }
  }
];

const LATEST = MIGRATIONS.reduce((max, m) => Math.max(max, m.version), 0);

function currentVersion(db) {
  return db.prepare('PRAGMA user_version').get().user_version;
}

/**
 * Applies every migration newer than the database's current version.
 * @returns {{from:number, to:number, applied:string[]}}
 */
function migrate(db, { quiet = false } = {}) {
  const from = currentVersion(db);
  const applied = [];

  for (const migration of MIGRATIONS) {
    if (migration.version <= from) continue;

    db.exec('BEGIN');
    try {
      migration.up(db);
      // PRAGMA does not accept a bound parameter, and the value is an integer
      // literal from this file rather than user input.
      db.exec(`PRAGMA user_version = ${migration.version}`);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      throw new Error(
        `migration ${migration.version} (${migration.name}) failed: ${err.message}`
      );
    }

    applied.push(`${migration.version}:${migration.name}`);
  }

  if (applied.length && !quiet) {
    console.log(`[db] migrated ${from} → ${LATEST} (${applied.join(', ')})`);
  }

  return { from, to: currentVersion(db), applied };
}

module.exports = { migrate, currentVersion, LATEST, MIGRATIONS };
