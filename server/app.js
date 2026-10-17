'use strict';

/**
 * Builds the Express application: middleware, routes, static hosting and
 * error handling.
 *
 * Deliberately free of side effects — no listen(), no seeding, no engine
 * start. server.js does that for the real process; the test suite imports
 * this module and binds its own port.
 */

const path = require('path');
const express = require('express');

const { securityHeaders, requestId, rateLimit } = require('./lib/security');

const authRoutes = require('./routes/auth');
const accountRoutes = require('./routes/account');
const adminRoutes = require('./routes/admin');
const alertRoutes = require('./routes/alerts');
const incidentRoutes = require('./routes/incidents');
const threatRoutes = require('./routes/threats');
const publicRoutes = require('./routes/public');
const exportRoutes = require('./routes/exports');
const detectionRoutes = require('./routes/detections');
const containmentRoutes = require('./routes/containment');
const socRoutes = require('./routes/soc');
const exposureRoutes = require('./routes/exposure');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

function createApp({ logRequests = true } = {}) {
  const app = express();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // ------------------------------------------------------------ middleware

  app.use(requestId);
  app.use(securityHeaders);
  app.use(express.json({ limit: '64kb' }));
  app.use(express.urlencoded({ extended: false, limit: '64kb' }));

  // Concise request log, skipping the noisy SSE stream.
  if (logRequests) {
    app.use((req, res, next) => {
      if (req.path === '/api/alerts/stream') return next();
      const started = Date.now();
      res.on('finish', () => {
        if (req.path.startsWith('/api')) {
          console.log(
            `${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - started}ms`
          );
        }
      });
      next();
    });
  }

  // Blanket API budget; individual routes tighten this further.
  app.use('/api', rateLimit({ windowMs: 60_000, max: 300, key: 'api' }));

  // ---------------------------------------------------------------- routes

  app.use('/api/auth', authRoutes);
  app.use('/api/account', accountRoutes);
  app.use('/api/admin', adminRoutes);
  app.use('/api/alerts', alertRoutes);
  app.use('/api/incidents', incidentRoutes);
  app.use('/api/threats', threatRoutes);
  app.use('/api/export', exportRoutes);
  app.use('/api/detections', detectionRoutes);
  app.use('/api/containment', containmentRoutes);
  app.use('/api/soc', socRoutes);
  app.use('/api/exposure', exposureRoutes);
  app.use('/api', publicRoutes);

  app.all('/api/*', (req, res) => {
    res.status(404).json({
      error: 'not_found',
      message: `No API route for ${req.method} ${req.path}`
    });
  });

  // --------------------------------------------------------------- statics

  app.use(
    express.static(PUBLIC_DIR, {
      extensions: ['html'],
      maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0,
      setHeaders(res, filePath) {
        if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
      }
    })
  );

  app.get('/', (_req, res) => res.sendFile(path.join(PUBLIC_DIR, 'index.html')));

  // Served explicitly: express.static ignores dot-directories by default, and
  // relaxing that globally would expose every other dotfile under public/ for
  // the sake of one well-known path.
  app.get('/.well-known/security.txt', (_req, res) => {
    res.type('text/plain; charset=utf-8');
    res.sendFile(path.join(PUBLIC_DIR, '.well-known', 'security.txt'));
  });

  // Unknown page → styled 404 rather than an Express stack trace.
  app.use((req, res) => {
    res.status(404);
    if (req.accepts('html')) return res.sendFile(path.join(PUBLIC_DIR, '404.html'));
    res.json({ error: 'not_found' });
  });

  // --------------------------------------------------------- error handler

  app.use((err, req, res, _next) => {
    console.error(`[error] ${req.id} ${err.stack || err.message}`);

    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'bad_json', message: 'Request body is not valid JSON.' });
    }
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ error: 'payload_too_large', message: 'Request body exceeds 64kb.' });
    }

    // Never leak internals to the client.
    res.status(500).json({
      error: 'internal_error',
      message: 'An unexpected error occurred.',
      requestId: req.id
    });
  });

  return app;
}

module.exports = { createApp, PUBLIC_DIR };
