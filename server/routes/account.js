'use strict';

/**
 * Self-service account management for the signed-in user: profile, password
 * change and session control. Everything here operates on req.user only —
 * no route accepts a user id, so one account can never act on another.
 */

const express = require('express');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const totp = require('../lib/totp');
const notify = require('../lib/notify');
const config = require('../lib/config');
const engine = require('../lib/engine');
const {
  validate,
  passwordStrength,
  rateLimit,
  clientIp
} = require('../lib/security');

const router = express.Router();

// Every route below requires a session.
router.use(auth.requireAuth);

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

/** GET /api/account — the current profile. */
router.get('/', (req, res) => {
  res.json({ user: auth.publicUser(req.user) });
});

/** PATCH /api/account — update display details. */
router.patch('/', (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    name: { required: false, minLength: 2, maxLength: 80, label: 'Full name' },
    org: { required: false, maxLength: 100, label: 'Organisation' },
    title: { required: false, maxLength: 80, label: 'Job title' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  if (!Object.keys(value).length) {
    return res.status(400).json({
      error: 'nothing_to_update',
      message: 'Provide at least one of: name, org, title.'
    });
  }

  const updated = repo.users.update(req.user.id, value);
  audit(req, 'account.update', `${req.user.email} updated ${Object.keys(value).join(', ')}`);

  res.json({ user: auth.publicUser(updated) });
});

/**
 * POST /api/account/password — change password.
 * Requires the current password, and signs every other device out on success.
 */
router.post(
  '/password',
  rateLimit({ windowMs: 15 * 60_000, max: 6, key: 'pwchange' }),
  (req, res) => {
    const { ok, errors, value } = validate(req.body, {
      currentPassword: { required: true, raw: true, label: 'Current password' },
      newPassword: { required: true, raw: true, label: 'New password' }
    });

    if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

    if (!auth.verifyPassword(value.currentPassword, req.user.passwordHash)) {
      audit(req, 'account.password.failed', req.user.email);
      return res.status(403).json({
        error: 'incorrect_password',
        fields: { currentPassword: 'That is not your current password.' }
      });
    }

    if (value.newPassword === value.currentPassword) {
      return res.status(400).json({
        error: 'password_unchanged',
        fields: { newPassword: 'Choose a password you have not used here before.' }
      });
    }

    const strength = passwordStrength(value.newPassword);
    if (!strength.ok) {
      return res.status(400).json({
        error: 'weak_password',
        fields: { newPassword: `Password needs ${strength.issues.join(', ')}.` },
        score: strength.score
      });
    }

    // Demo accounts are shared, so letting one visitor change the password
    // would lock out everyone else using the published credentials.
    if (req.user.demo) {
      return res.status(403).json({
        error: 'demo_account',
        message: 'The shared demo accounts cannot have their password changed.'
      });
    }

    repo.users.update(req.user.id, {
      passwordHash: auth.hashPassword(value.newPassword)
    });

    // Keep the caller signed in; drop every other session.
    const revoked = repo.sessions.revokeAllForUser(req.user.id, req.sessionId);
    audit(req, 'account.password.changed', `${req.user.email}, ${revoked} session(s) revoked`);

    res.json({
      ok: true,
      message: 'Password updated.',
      otherSessionsRevoked: revoked
    });
  }
);

/** GET /api/account/sessions — where this account is signed in. */
router.get('/sessions', (req, res) => {
  const now = Date.now();

  const data = repo.sessions.listForUser(req.user.id).map((s) => ({
    id: s.id,
    issuedAt: s.issuedAt,
    expiresAt: s.expiresAt,
    revoked: s.revoked,
    active: !s.revoked && new Date(s.expiresAt).getTime() > now,
    current: s.id === req.sessionId,
    ip: s.ip,
    userAgent: s.userAgent
  }));

  res.json({
    data,
    active: data.filter((s) => s.active).length,
    total: data.length
  });
});

/** DELETE /api/account/sessions — sign out everywhere except here. */
router.delete('/sessions', (req, res) => {
  const revoked = repo.sessions.revokeAllForUser(req.user.id, req.sessionId);
  audit(req, 'account.sessions.revoked', `${req.user.email}, ${revoked} revoked`);
  res.json({ ok: true, revoked });
});

/* ------------------------------------------------------ two-factor auth */

const mfaLimit = rateLimit({ windowMs: 15 * 60_000, max: 15, key: 'mfa' });

/** GET /api/account/mfa — enrolment state for this account. */
router.get('/mfa', (req, res) => {
  res.json({
    enabled: req.user.mfaEnabled && Boolean(req.user.mfaSecret),
    pending: Boolean(req.user.mfaPendingSecret),
    confirmedAt: req.user.mfaConfirmedAt,
    recoveryCodesRemaining: repo.recoveryCodes.remaining(req.user.id)
  });
});

/**
 * POST /api/account/mfa/enrol — begin enrolment.
 *
 * Stores the new secret as *pending*: an abandoned enrolment leaves the
 * account exactly as it was, so nobody can lock themselves out by closing the
 * tab halfway through.
 */
router.post('/mfa/enrol', mfaLimit, (req, res) => {
  if (req.user.demo) {
    return res.status(403).json({
      error: 'demo_account',
      message: 'Shared demo accounts cannot enrol a second factor.'
    });
  }
  if (req.user.mfaEnabled && req.user.mfaSecret) {
    return res.status(409).json({
      error: 'already_enrolled',
      message: 'Two-factor authentication is already on. Turn it off first to re-enrol.'
    });
  }

  // Re-authenticate before minting a credential: a borrowed unlocked laptop
  // should not be enough to bind an attacker's authenticator to the account.
  const password = String(req.body?.password || '');
  if (!auth.verifyPassword(password, req.user.passwordHash)) {
    audit(req, 'account.mfa.enrol_denied', req.user.email);
    return res.status(403).json({
      error: 'incorrect_password',
      fields: { password: 'Confirm your password to continue.' }
    });
  }

  const secret = totp.generateSecret();
  repo.users.update(req.user.id, { mfaPendingSecret: secret });
  audit(req, 'account.mfa.enrol_started', req.user.email);

  res.json({
    secret,
    otpauthUrl: totp.otpauthUrl({ secret, email: req.user.email }),
    // Grouped in fours: this is what a person retypes when their camera or
    // the deep link does not cooperate.
    manualEntry: secret.match(/.{1,4}/g).join(' '),
    digits: totp.DIGITS,
    period: totp.STEP_SECONDS,
    algorithm: 'SHA1'
  });
});

/**
 * POST /api/account/mfa/confirm — prove the authenticator works, then arm it.
 *
 * Recovery codes are returned here and nowhere else. Only their hashes are
 * kept, so this response is the single opportunity to record them.
 */
router.post('/mfa/confirm', mfaLimit, (req, res) => {
  const pending = req.user.mfaPendingSecret;
  if (!pending) {
    return res.status(409).json({
      error: 'no_enrolment',
      message: 'Start enrolment before confirming a code.'
    });
  }

  const attempt = totp.verify(pending, String(req.body?.code || ''));
  if (!attempt.valid) {
    audit(req, 'account.mfa.confirm_failed', req.user.email);
    return res.status(400).json({
      error: 'invalid_code',
      fields: { code: 'That code is not valid. Check your authenticator and try again.' }
    });
  }

  const codes = totp.generateRecoveryCodes();
  repo.recoveryCodes.replaceAll(req.user.id, codes.map(totp.hashRecoveryCode));

  repo.users.update(req.user.id, {
    mfaSecret: pending,
    mfaPendingSecret: null,
    mfaEnabled: true,
    mfaConfirmedAt: new Date().toISOString(),
    mfaLastCounter: attempt.counter
  });

  audit(req, 'account.mfa.enabled', req.user.email);

  res.json({
    ok: true,
    enabled: true,
    recoveryCodes: codes,
    message: 'Two-factor authentication is on. Store these recovery codes somewhere safe — they are not shown again.'
  });
});

/** POST /api/account/mfa/recovery-codes — regenerate the set. */
router.post('/mfa/recovery-codes', mfaLimit, (req, res) => {
  if (!req.user.mfaEnabled || !req.user.mfaSecret) {
    return res.status(409).json({ error: 'not_enrolled', message: 'Two-factor authentication is not on.' });
  }
  if (!auth.verifyPassword(String(req.body?.password || ''), req.user.passwordHash)) {
    return res.status(403).json({
      error: 'incorrect_password',
      fields: { password: 'Confirm your password to continue.' }
    });
  }

  const codes = totp.generateRecoveryCodes();
  repo.recoveryCodes.replaceAll(req.user.id, codes.map(totp.hashRecoveryCode));
  audit(req, 'account.mfa.recovery_regenerated', req.user.email);

  res.json({
    ok: true,
    recoveryCodes: codes,
    message: 'New recovery codes generated. The previous set no longer works.'
  });
});

/**
 * POST /api/account/mfa/disable — turn the second factor off.
 *
 * Requires the password *and* a current code: knowing the password alone must
 * not be enough to strip the control that protects against a known password.
 */
router.post('/mfa/disable', mfaLimit, (req, res) => {
  if (!req.user.mfaEnabled || !req.user.mfaSecret) {
    return res.status(409).json({ error: 'not_enrolled', message: 'Two-factor authentication is not on.' });
  }

  if (!auth.verifyPassword(String(req.body?.password || ''), req.user.passwordHash)) {
    audit(req, 'account.mfa.disable_denied', req.user.email);
    return res.status(403).json({
      error: 'incorrect_password',
      fields: { password: 'Confirm your password to continue.' }
    });
  }

  const submitted = String(req.body?.code || '').trim();
  const byTotp = totp.verify(req.user.mfaSecret, submitted).valid;
  const byRecovery =
    !byTotp && repo.recoveryCodes.consume(req.user.id, totp.hashRecoveryCode(submitted));

  if (!byTotp && !byRecovery) {
    audit(req, 'account.mfa.disable_denied', req.user.email);
    return res.status(400).json({
      error: 'invalid_code',
      fields: { code: 'Enter a current code or one of your recovery codes.' }
    });
  }

  repo.users.update(req.user.id, {
    mfaSecret: null,
    mfaPendingSecret: null,
    mfaEnabled: false,
    mfaConfirmedAt: null,
    mfaLastCounter: null
  });
  repo.recoveryCodes.clear(req.user.id);
  audit(req, 'account.mfa.disabled', req.user.email);

  res.json({ ok: true, enabled: false, message: 'Two-factor authentication is off.' });
});

/* ------------------------------------------------------------- api keys */

/** GET /api/account/api-keys — the caller's keys, without the secrets. */
router.get('/api-keys', (req, res) => {
  const data = repo.apiKeys.listForUser(req.user.id).map(({ keyHash, ...safe }) => safe);
  res.json({ data, total: data.length });
});

/**
 * POST /api/account/api-keys — mint a read-only key.
 *
 * The plaintext appears in this response and never again; only its hash is
 * stored, so a lost key is replaced rather than recovered.
 */
router.post('/api-keys', rateLimit({ windowMs: 60 * 60_000, max: 10, key: 'apikey' }), (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    name: { required: true, minLength: 2, maxLength: 60, label: 'Key name' }
  });
  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const existing = repo.apiKeys.listForUser(req.user.id).filter((k) => !k.revoked);
  if (existing.length >= 10) {
    return res.status(409).json({
      error: 'too_many_keys',
      message: 'You already have 10 active keys. Revoke one before creating another.'
    });
  }

  const { key, prefix, hash } = auth.generateApiKey();
  const record = repo.apiKeys.insert({
    id: engine.id('KEY'),
    userId: req.user.id,
    name: value.name,
    prefix,
    keyHash: hash,
    scopes: ['read'],
    createdAt: new Date().toISOString()
  });

  audit(req, 'account.apikey.created', `${req.user.email} created "${value.name}" (${prefix}…)`);

  const { keyHash, ...safe } = record;
  res.status(201).json({
    key: safe,
    secret: key,
    message: 'Copy this key now — it is not shown again.'
  });
});

/** DELETE /api/account/api-keys/:id — revoke one of the caller's keys. */
router.delete('/api-keys/:id', (req, res) => {
  // Scoped by user id in the statement itself, so one account cannot revoke
  // another's key by guessing an id.
  if (!repo.apiKeys.revoke(req.params.id, req.user.id)) {
    return res.status(404).json({ error: 'not_found', message: 'No such API key.' });
  }
  audit(req, 'account.apikey.revoked', `${req.user.email} revoked ${req.params.id}`);
  res.json({ ok: true, revoked: req.params.id });
});


  /* ==================================================================
     NOTIFICATION PREFERENCES
     ================================================================== */

  /** GET /api/account/notifications — what this account has opted into. */
  router.get('/notifications', (req, res) => {
    const prefs = repo.notificationPrefs.forUser(req.user.id);
    const queued = repo.notificationQueue.pendingFor(req.user.id);

    res.json({
      prefs,
      pendingDigest: queued.length,
      // Surfaced so the settings page can be honest about what will happen:
      // without a relay configured, messages are recorded rather than sent.
      transport: config.smtp.configured
        ? { mode: 'smtp', host: config.smtp.host, from: config.smtp.from }
        : {
            mode: 'spool',
            note:
              'No SMTP relay is configured on this deployment, so notifications are recorded in the delivery log instead of being sent. Everything else about the flow is live.'
          },
      options: {
        severities: ['info', 'low', 'medium', 'high', 'critical'],
        cadences: ['immediate', 'hourly', 'daily']
      }
    });
  });

  /** PATCH /api/account/notifications — change them. */
  router.patch('/notifications', (req, res) => {
    const { ok, errors, value } = validate(req.body, {
      minSeverity: {
        required: false,
        enum: ['info', 'low', 'medium', 'high', 'critical'],
        label: 'Minimum severity'
      },
      cadence: { required: false, enum: ['immediate', 'hourly', 'daily'], label: 'Cadence' },
      quietHours: { required: false, maxLength: 11, label: 'Quiet hours' }
    });

    if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

    const patch = { ...value };

    for (const flagName of ['emailEnabled', 'onIncident', 'onCritical', 'onAssignment']) {
      if (req.body[flagName] !== undefined) patch[flagName] = Boolean(req.body[flagName]);
    }

    // validate() treats an empty string as "field absent", so a request that
    // clears the window never reaches the patch and the whole update comes
    // back as nothing_to_update. Read the raw body for that one case.
    if (req.body.quietHours !== undefined && String(req.body.quietHours).trim() === '') {
      patch.quietHours = null;
    } else if (patch.quietHours !== undefined) {
      if (!/^\d{2}:\d{2}-\d{2}:\d{2}$/.test(patch.quietHours)) {
        return res.status(400).json({
          error: 'validation_failed',
          fields: { quietHours: 'Use 24-hour times, for example 22:00-07:00.' }
        });
      }
    }

    if (!Object.keys(patch).length) {
      return res.status(400).json({ error: 'nothing_to_update' });
    }

    const prefs = repo.notificationPrefs.upsert(req.user.id, patch);
    audit(req, 'account.notifications.updated', `${req.user.email} updated ${Object.keys(patch).join(', ')}`);

    res.json({ prefs });
  });

  /**
   * POST /api/account/notifications/test — send one message to this account.
   *
   * The only way to be sure the settings work is to receive something.
   */
  router.post(
    '/notifications/test',
    rateLimit({ windowMs: 10 * 60_000, max: 5, key: 'notifytest' }),
    async (req, res) => {
      const result = await notify.sendTest(req.user);
      audit(req, 'account.notifications.test', `${req.user.email} — ${result.status}`);

      res.json({
        ...result,
        message:
          result.status === 'sent'
            ? `Sent to ${req.user.email}.`
            : result.status === 'spooled'
              ? 'Recorded in the delivery log. No SMTP relay is configured, so nothing left this server.'
              : `Delivery failed: ${result.error}`
      });
    }
  );

  /** POST /api/account/notifications/digest — flush this account's queue now. */
  router.post('/notifications/digest', async (req, res) => {
    const sent = await notify.runDigest({ userId: req.user.id });
    res.json({
      sent: sent.length,
      detail: sent[0] || null,
      message: sent.length
        ? `Digest of ${sent[0].count} notification(s) ${sent[0].status}.`
        : 'Nothing queued for this account.'
    });
  });

  /** GET /api/account/notifications/log — this account's delivery history. */
  router.get('/notifications/log', (req, res) => {
    const rows = repo.emailLog
      .list(200)
      .filter((entry) => entry.to === req.user.email)
      .slice(0, 25);

    res.json({ data: rows, total: rows.length });
  });

module.exports = router;
