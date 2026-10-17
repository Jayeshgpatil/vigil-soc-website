'use strict';

/**
 * VGIL — Security Operations & Threat Monitoring
 * Process entry point: opens the database, seeds it, starts the detection
 * engine and listens.
 */

const database = require('./db');
const { currentVersion } = require('./db/migrate');
const engine = require('./lib/engine');
const notify = require('./lib/notify');
const seed = require('./lib/seed');
const { createApp } = require('./app');

const PORT = Number(process.env.PORT) || 3000;

const app = createApp();

// -------------------------------------------------------------------- startup

database.open();
seed.run();
engine.start(4000);

// Drains queued notifications for hourly/daily subscribers. Unref'd inside,
// so it never holds the process open on its own.
notify.startDigestTimer();

const server = app.listen(PORT, () => {
  const conn = database.handle();
  console.log('');
  console.log('  ██╗   ██╗ ██████╗ ██╗██╗');
  console.log('  ██║   ██║██╔════╝ ██║██║');
  console.log('  ██║   ██║██║  ███╗██║██║');
  console.log('  ╚██╗ ██╔╝██║   ██║██║██║');
  console.log('   ╚████╔╝ ╚██████╔╝██║███████╗');
  console.log('    ╚═══╝   ╚═════╝ ╚═╝╚══════╝');
  console.log('  Security Operations & Threat Monitoring');
  console.log('');
  console.log(`  ▸ Web console   http://localhost:${PORT}`);
  console.log(`  ▸ API root      http://localhost:${PORT}/api/health`);
  console.log(`  ▸ Live stream   http://localhost:${PORT}/api/alerts/stream`);
  console.log('');
  console.log(`  Database        sqlite · schema v${currentVersion(conn)}`);
  console.log(`                  ${database.path}`);
  console.log('');
  console.log('  Demo credentials');
  console.log('    analyst@vgil.io / Vgil#Demo2026   (analyst)');
  console.log('    admin@vgil.io   / Vgil#Admin2026  (admin)');
  console.log('');
});

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`\n[server] ${signal} received — closing database...`);
  engine.stop();

  server.close(() => {
    try {
      database.close();
    } catch (err) {
      console.error('[server] database close failed:', err.message);
    }
    process.exit(0);
  });

  // Don't let a hung connection hold the process open indefinitely.
  setTimeout(() => {
    try {
      database.close();
    } catch {
      /* already closing */
    }
    process.exit(0);
  }, 3000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = app;
