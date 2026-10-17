'use strict';

/**
 * Administrative endpoints: user management, tenant export and storage stats.
 * Every route requires an authenticated admin.
 */

const crypto = require('crypto');
const express = require('express');
const database = require('../db');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const engine = require('../lib/engine');
const webhooks = require('../lib/webhooks');
const config = require('../lib/config');
const notify = require('../lib/notify');
const { validate, rateLimit, clientIp, sha256 } = require('../lib/security');
const { currentVersion, LATEST } = require('../db/migrate');

const router = express.Router();

router.use(auth.requireAuth, auth.requireRole('admin'));

function audit(req, action, detail) {
  repo.audit.insert({
    id: engine.id('AUD'),
    ts: new Date().toISOString(),
    action,
    detail,
    ip: clientIp(req),
    userAgent: (req.get('user-agent') || '').slice(0, 200)
  });
  repo.audit.trim(400);
}

/** GET /api/admin/users — all accounts on the tenant. */
router.get('/users', (_req, res) => {
  const users = repo.users.list().map((u) => auth.publicUser(u));
  res.json({
    data: users,
    total: users.length,
    admins: users.filter((u) => u.role === 'admin').length,
    disabled: users.filter((u) => u.disabled).length
  });
});

/**
 * PATCH /api/admin/users/:id — change a role or disable an account.
 * Disabling also revokes the account's live sessions, so access ends
 * immediately rather than when the token happens to expire.
 */
router.patch('/users/:id', (req, res) => {
  const target = repo.users.byId(req.params.id);
  if (!target) {
    return res.status(404).json({ error: 'not_found', message: 'User not found.' });
  }

  const { ok, errors, value } = validate(req.body, {
    role: { required: false, enum: ['analyst', 'admin'], label: 'Role' },
    disabled: { required: false, enum: ['true', 'false'], label: 'Disabled' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const patch = {};
  if (value.role) patch.role = value.role;
  if (value.disabled !== undefined) patch.disabled = value.disabled === 'true';

  if (!Object.keys(patch).length) {
    return res.status(400).json({
      error: 'nothing_to_update',
      message: 'Provide role and/or disabled.'
    });
  }

  // An admin must not be able to lock themselves out or drop their own
  // privileges — that would leave the tenant with no way back in.
  if (target.id === req.user.id) {
    if (patch.disabled === true || patch.role === 'analyst') {
      return res.status(400).json({
        error: 'self_lockout',
        message: 'You cannot disable or demote your own account.'
      });
    }
  }

  // Seeded demo accounts are shared and published; leave them alone.
  if (target.demo) {
    return res.status(403).json({
      error: 'protected_record',
      message: 'The shared demo accounts cannot be modified.'
    });
  }

  const updated = repo.users.update(target.id, patch);

  let revoked = 0;
  if (patch.disabled === true) revoked = repo.sessions.revokeAllForUser(target.id);

  audit(
    req,
    'admin.user.update',
    `${req.user.email} updated ${target.email}: ${JSON.stringify(patch)}`
  );

  res.json({ user: auth.publicUser(updated), sessionsRevoked: revoked });
});

/** GET /api/admin/stats — row counts and storage detail. */
router.get('/stats', (_req, res) => {
  const conn = database.handle();
  const pageCount = conn.prepare('PRAGMA page_count').get().page_count;
  const pageSize = conn.prepare('PRAGMA page_size').get().page_size;

  res.json({
    data: {
      database: {
        driver: 'node:sqlite',
        path: database.path,
        schemaVersion: currentVersion(conn),
        latestSchemaVersion: LATEST,
        journalMode: conn.prepare('PRAGMA journal_mode').get().journal_mode,
        sizeBytes: pageCount * pageSize,
        pageCount,
        pageSize
      },
      counts: repo.admin.counts(),
      process: {
        node: process.version,
        uptimeSeconds: Math.round(process.uptime()),
        rssBytes: process.memoryUsage().rss
      }
    }
  });
});

/**
 * GET /api/admin/export — full tenant export as JSON.
 * Rate limited because it serialises every row in the database.
 */
router.get(
  '/export',
  rateLimit({ windowMs: 60_000, max: 3, key: 'export' }),
  (req, res) => {
    const payload = repo.admin.exportAll();
    audit(req, 'admin.export', `${req.user.email} exported ${payload.counts.alerts} alerts`);

    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="vgil-export-${stamp}.json"`);
    res.send(JSON.stringify(payload, null, 2));
  }
);

/** GET /api/admin/audit — the full audit trail, deeper than the public route. */
router.get('/audit', (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 250, 1000);
  res.json({ data: repo.audit.list(limit), limit });
});

/* -------------------------------------------------- password reset links */

/**
 * POST /api/admin/users/:id/reset-link — issue a single-use recovery link.
 *
 * With a relay configured the link is emailed to the account holder, which is
 * the right channel: it reaches the person who owns the address rather than
 * passing through whoever is administering the tenant. The link is still
 * returned in the response, because an administrator issuing one for somebody
 * who has lost mailbox access needs to hand it over directly.
 */
router.post(
  '/users/:id/reset-link',
  rateLimit({ windowMs: 15 * 60_000, max: 20, key: 'resetlink' }),
  async (req, res) => {
    const user = repo.users.byId(req.params.id);
    if (!user) {
      return res.status(404).json({ error: 'not_found', message: 'No such user.' });
    }
    if (user.demo) {
      return res.status(403).json({
        error: 'demo_account',
        message: 'Shared demo accounts cannot have their password reset.'
      });
    }

    // Issuing a new link retires any outstanding one, so a link handed out an
    // hour ago and possibly seen by the wrong person stops working now.
    repo.passwordResets.invalidateForUser(user.id);

    const token = crypto.randomBytes(32).toString('base64url');
    const ttlMinutes = 60;
    const now = new Date();

    repo.passwordResets.insert({
      id: engine.id('RST'),
      userId: user.id,
      tokenHash: sha256(token),
      createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttlMinutes * 60_000).toISOString(),
      issuedBy: req.user.email,
      ip: clientIp(req)
    });

    repo.passwordResets.prune();
    audit(req, 'admin.reset_link.issued', `${req.user.email} issued a reset link for ${user.email}`);

    // Path only — the caller's own origin completes it, so the link is correct
    // behind a proxy or on a custom domain without configuration.
    const path = `/reset.html?token=${encodeURIComponent(token)}`;
    const expiresAt = new Date(now.getTime() + ttlMinutes * 60_000).toISOString();

    // Sent regardless of the recipient's notification preferences: this is an
    // account-security message, not an alert they can opt out of.
    const rendered = notify.renderEvent({
      kind: 'reset',
      title: 'Reset your VGIL password',
      summary: `${req.user.email} issued a password reset for your account. The link works once and expires in ${ttlMinutes} minutes. If you were not expecting this, tell your administrator — do not use the link.`,
      path,
      details: [
        ['Account', user.email],
        ['Issued by', req.user.email],
        ['Expires', expiresAt]
      ]
    });

    const delivery = await notify.deliver({
      to: user.email,
      subject: '[VGIL] Reset your password',
      text: rendered.text,
      html: rendered.html,
      kind: 'reset'
    });

    res.status(201).json({
      ok: true,
      path,
      expiresAt,
      expiresInMinutes: ttlMinutes,
      user: { id: user.id, email: user.email, name: user.name },
      delivery,
      message:
        delivery.status === 'sent'
          ? `Emailed to ${user.email}. The link works once and is not shown again.`
          : 'Single-use link. No SMTP relay is configured, so hand it to the account holder directly — it is not shown again.'
    });
  }
);

/* ---------------------------------------------------------------- api keys */

/** GET /api/admin/api-keys — every key on the tenant, secrets excluded. */
router.get('/api-keys', (_req, res) => {
  const data = repo.apiKeys.list().map(({ keyHash, ...safe }) => {
    const owner = repo.users.byId(safe.userId);
    return { ...safe, ownerEmail: owner ? owner.email : null };
  });
  res.json({ data, total: data.length, active: data.filter((k) => !k.revoked).length });
});

/** DELETE /api/admin/api-keys/:id — revoke anyone's key. */
router.delete('/api-keys/:id', (req, res) => {
  if (!repo.apiKeys.revoke(req.params.id)) {
    return res.status(404).json({ error: 'not_found', message: 'No such API key.' });
  }
  audit(req, 'admin.apikey.revoked', `${req.user.email} revoked ${req.params.id}`);
  res.json({ ok: true, revoked: req.params.id });
});

/* ---------------------------------------------------------------- webhooks */

/** GET /api/admin/webhooks — subscribers and their recent delivery health. */
router.get('/webhooks', (_req, res) => {
  const data = repo.webhooks.list().map(({ secret, ...safe }) => ({
    ...safe,
    // Shown once at creation and never again. Unlike an API key there is no
    // non-secret prefix worth displaying, so nothing derived from it is sent.
    secretSet: Boolean(secret),
    recentDeliveries: repo.webhooks.deliveries(safe.id, 5)
  }));
  res.json({ data, total: data.length, events: webhooks.EVENTS });
});

/** POST /api/admin/webhooks — subscribe an endpoint. */
router.post('/webhooks', async (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    url: { required: true, maxLength: 500, label: 'Endpoint URL' },
    description: { required: false, maxLength: 140, label: 'Description' }
  });
  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const verdict = await webhooks.validateUrl(value.url);
  if (!verdict.ok) {
    return res.status(400).json({ error: 'invalid_url', fields: { url: verdict.reason } });
  }

  const requested = Array.isArray(req.body?.events) ? req.body.events : ['incident.opened'];
  const events = requested.filter((e) => webhooks.EVENTS.includes(e) || e === '*');
  if (!events.length) {
    return res.status(400).json({
      error: 'invalid_events',
      fields: { events: `Choose at least one of: ${webhooks.EVENTS.join(', ')}` }
    });
  }

  const secret = webhooks.generateSecret();
  const hook = repo.webhooks.insert({
    id: engine.id('WHK'),
    url: value.url,
    description: value.description || null,
    secret,
    events,
    active: true,
    createdAt: new Date().toISOString(),
    createdBy: req.user.email
  });

  audit(req, 'admin.webhook.created', `${req.user.email} subscribed ${value.url}`);

  const { secret: _omit, ...safe } = hook;
  res.status(201).json({
    webhook: safe,
    secret,
    message: 'Copy this signing secret now — it is not shown again. Verify it against the X-VGIL-Signature header.'
  });
});

/** PATCH /api/admin/webhooks/:id — pause, retarget or re-scope a subscriber. */
router.patch('/webhooks/:id', async (req, res) => {
  const existing = repo.webhooks.byId(req.params.id);
  if (!existing) return res.status(404).json({ error: 'not_found', message: 'No such webhook.' });

  const patch = {};

  if (req.body?.url !== undefined) {
    const verdict = await webhooks.validateUrl(req.body.url);
    if (!verdict.ok) {
      return res.status(400).json({ error: 'invalid_url', fields: { url: verdict.reason } });
    }
    patch.url = String(req.body.url);
  }
  if (req.body?.active !== undefined) patch.active = Boolean(req.body.active);
  if (req.body?.description !== undefined) {
    patch.description = String(req.body.description).slice(0, 140);
  }
  if (Array.isArray(req.body?.events)) {
    const events = req.body.events.filter((e) => webhooks.EVENTS.includes(e) || e === '*');
    if (!events.length) {
      return res.status(400).json({ error: 'invalid_events', fields: { events: 'Choose at least one event.' } });
    }
    patch.events = events;
  }

  if (!Object.keys(patch).length) {
    return res.status(400).json({ error: 'nothing_to_update' });
  }

  const updated = repo.webhooks.update(req.params.id, patch);
  audit(req, 'admin.webhook.updated', `${req.user.email} updated ${req.params.id}`);

  const { secret, ...safe } = updated;
  res.json({ webhook: safe });
});

/** POST /api/admin/webhooks/:id/test — send a synthetic delivery. */
router.post('/webhooks/:id/test', async (req, res) => {
  const hook = repo.webhooks.byId(req.params.id);
  if (!hook) return res.status(404).json({ error: 'not_found', message: 'No such webhook.' });

  const delivered = await webhooks.test(hook);
  audit(req, 'admin.webhook.tested', `${req.user.email} tested ${hook.url}`);

  res.json({
    ok: delivered,
    delivered,
    recentDeliveries: repo.webhooks.deliveries(hook.id, 3),
    message: delivered
      ? 'Test delivery accepted by the endpoint.'
      : 'The endpoint did not accept the test delivery. See the attempt log.'
  });
});

/** DELETE /api/admin/webhooks/:id — unsubscribe. */
router.delete('/webhooks/:id', (req, res) => {
  if (!repo.webhooks.remove(req.params.id)) {
    return res.status(404).json({ error: 'not_found', message: 'No such webhook.' });
  }
  audit(req, 'admin.webhook.deleted', `${req.user.email} removed ${req.params.id}`);
  res.json({ ok: true, removed: req.params.id });
});

/* ------------------------------------------------------- delivery log */

/**
 * GET /api/admin/notifications — outbound mail across the tenant.
 *
 * Reports the transport as well as the log, because "no messages sent" and
 * "no relay configured" look identical from a list of zero rows.
 */
router.get('/notifications', (req, res) => {
  const rows = repo.emailLog.list(Math.min(Number(req.query.limit) || 100, 300));

  res.json({
    data: rows,
    total: rows.length,
    counts: {
      sent: rows.filter((r) => r.status === 'sent').length,
      spooled: rows.filter((r) => r.status === 'spooled').length,
      failed: rows.filter((r) => r.status === 'failed').length
    },
    transport: config.smtp.configured
      ? { mode: 'smtp', host: config.smtp.host, port: config.smtp.port, from: config.smtp.from }
      : {
          mode: 'spool',
          note:
            'No SMTP relay is configured. Notifications are selected, rendered and logged, but nothing leaves this server. Set VGIL_SMTP_HOST to enable delivery.'
        },
    subscribers: repo.notificationPrefs.subscribers().length
  });
});

module.exports = router;
