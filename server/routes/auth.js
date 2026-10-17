'use strict';

const express = require('express');
const config = require('../lib/config');
const repo = require('../db/repository');
const auth = require('../lib/auth');
const totp = require('../lib/totp');
const engine = require('../lib/engine');
const { validate, passwordStrength, rateLimit, clientIp, sha256 } = require('../lib/security');

const router = express.Router();

// Auth endpoints get a much tighter budget than the read-only API.
const loginLimit = rateLimit({ windowMs: 15 * 60_000, max: 12, key: 'login' });
const registerLimit = rateLimit({ windowMs: 60 * 60_000, max: 6, key: 'register' });

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

/** Context recorded against each issued session. */
function sessionContext(req) {
  return {
    ip: clientIp(req),
    userAgent: (req.get('user-agent') || '').slice(0, 200)
  };
}

/** POST /api/auth/register — create a tenant account. */
router.post('/register', registerLimit, (req, res) => {
  if (!config.registrationOpen) {
    return res.status(403).json({
      error: 'registration_closed',
      message: 'Sign-up is disabled on this deployment. Ask an administrator for an account.'
    });
  }

  const { ok, errors, value } = validate(req.body, {
    name: { required: true, label: 'Full name', minLength: 2, maxLength: 80 },
    email: { required: true, type: 'email', label: 'Work email' },
    org: { required: false, label: 'Organisation', maxLength: 100, default: 'Independent' },
    password: { required: true, raw: true, label: 'Password' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const strength = passwordStrength(value.password);
  if (!strength.ok) {
    return res.status(400).json({
      error: 'weak_password',
      fields: { password: `Password needs ${strength.issues.join(', ')}.` },
      score: strength.score
    });
  }

  const email = value.email.toLowerCase();
  if (repo.users.byEmail(email)) {
    // Generic message — do not confirm which addresses are registered.
    return res.status(409).json({
      error: 'registration_failed',
      message: 'That account could not be created. Try signing in instead.'
    });
  }

  // With demo accounts off, a fresh instance would otherwise have no
  // administrator and no way to create one.
  const firstAccount = repo.users.count() === 0;
  const role = firstAccount && config.bootstrapFirstAdmin ? 'admin' : 'analyst';

  const user = repo.users.insert({
    id: engine.id('USR'),
    name: value.name,
    email,
    passwordHash: auth.hashPassword(value.password),
    role,
    org: value.org,
    title: role === 'admin' ? 'SOC Manager' : 'SOC Analyst',
    createdAt: new Date().toISOString(),
    lastLogin: null,
    disabled: false,
    mfaEnabled: false,
    demo: false
  });

  audit(req, 'user.register', `${email} registered`);
  const { token, expiresAt } = auth.issueToken(user, sessionContext(req));

  res.status(201).json({ user: auth.publicUser(user), token, expiresAt });
});

/** POST /api/auth/login — exchange credentials for a session token. */
router.post('/login', loginLimit, (req, res) => {
  const { ok, errors, value } = validate(req.body, {
    email: { required: true, type: 'email', label: 'Email' },
    password: { required: true, raw: true, label: 'Password' }
  });

  if (!ok) return res.status(400).json({ error: 'validation_failed', fields: errors });

  const email = value.email.toLowerCase();
  const user = repo.users.byEmail(email);

  // Always run a verification so timing does not reveal account existence.
  const dummy = 'scrypt$0000$0000';
  const valid = auth.verifyPassword(value.password, user ? user.passwordHash : dummy);

  if (!user || !valid || user.disabled) {
    audit(req, 'auth.login.failed', email);
    return res.status(401).json({
      error: 'invalid_credentials',
      message: 'Email or password is incorrect.'
    });
  }

  // Second factor enrolled: the password alone buys a short-lived challenge,
  // not a session. Nothing is authorised and no session row exists until the
  // code is presented to /login/mfa.
  if (user.mfaEnabled && user.mfaSecret) {
    const { challenge, expiresAt } = auth.issueChallenge(user);
    audit(req, 'auth.login.mfa_challenge', email);
    return res.json({
      mfaRequired: true,
      challenge,
      expiresAt,
      recoveryAvailable: repo.recoveryCodes.remaining(user.id) > 0
    });
  }

  const updated = repo.users.update(user.id, { lastLogin: new Date().toISOString() });
  audit(req, 'auth.login.success', email);

  const { token, expiresAt } = auth.issueToken(updated, sessionContext(req));
  res.json({ user: auth.publicUser(updated), token, expiresAt });
});

/**
 * POST /api/auth/login/mfa — complete a challenged sign-in.
 *
 * Accepts either a TOTP code or one of the printed recovery codes.
 */
router.post('/login/mfa', loginLimit, (req, res) => {
  const payload = auth.verifyChallenge(String(req.body?.challenge || ''));
  if (!payload) {
    return res.status(401).json({
      error: 'challenge_expired',
      message: 'That sign-in attempt expired. Enter your password again.'
    });
  }

  const user = repo.users.byId(payload.sub);
  if (!user || user.disabled || !user.mfaEnabled || !user.mfaSecret) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }

  const submitted = String(req.body?.code || '').trim();
  if (!submitted) {
    return res.status(400).json({
      error: 'validation_failed',
      fields: { code: 'Enter the 6-digit code from your authenticator.' }
    });
  }

  let method = null;

  const attempt = totp.verify(user.mfaSecret, submitted);
  if (attempt.valid) {
    // A code stays valid for its whole 30-second step, so without this an
    // observed code could be replayed until it expired.
    if (user.mfaLastCounter !== null && attempt.counter <= user.mfaLastCounter) {
      audit(req, 'auth.mfa.replay_blocked', user.email);
      return res.status(401).json({
        error: 'code_already_used',
        message: 'That code has already been used. Wait for the next one.'
      });
    }
    repo.users.update(user.id, { mfaLastCounter: attempt.counter });
    method = 'totp';
  } else if (repo.recoveryCodes.consume(user.id, totp.hashRecoveryCode(submitted))) {
    method = 'recovery';
  }

  if (!method) {
    audit(req, 'auth.mfa.failed', user.email);
    return res.status(401).json({
      error: 'invalid_code',
      message: 'That code is not valid. Check your authenticator and try again.'
    });
  }

  const updated = repo.users.update(user.id, { lastLogin: new Date().toISOString() });
  audit(req, 'auth.login.success', `${user.email} (${method})`);

  const { token, expiresAt } = auth.issueToken(updated, sessionContext(req));
  const remaining = repo.recoveryCodes.remaining(user.id);

  res.json({
    user: auth.publicUser(updated),
    token,
    expiresAt,
    method,
    // Surfaced so the console can warn before someone burns their last code.
    recoveryCodesRemaining: remaining,
    ...(method === 'recovery'
      ? {
          notice:
            remaining === 0
              ? 'That was your last recovery code. Generate a new set from your account page.'
              : `Recovery code accepted. ${remaining} remaining.`
        }
      : {})
  });
});

/** GET /api/auth/me — current session identity. */
router.get('/me', auth.requireAuth, (req, res) => {
  res.json({ user: auth.publicUser(req.user) });
});

/** POST /api/auth/logout — revoke the presented token. */
router.post('/logout', auth.requireAuth, (req, res) => {
  auth.revokeToken(req.token);
  audit(req, 'auth.logout', req.user.email);
  res.json({ ok: true });
});

/* ------------------------------------------------------- password reset */

/** Masks an address for a page reached with a token but no session. */
function maskEmail(email) {
  const [local, domain] = String(email).split('@');
  if (!domain) return '•••';
  const head = local.slice(0, 2);
  return `${head}${'•'.repeat(Math.max(local.length - 2, 1))}@${domain}`;
}

/**
 * Looks a reset token up and reports why it is unusable.
 * @returns {{reset:Object, user:Object}|{error:string, message:string}}
 */
function resolveReset(rawToken) {
  const token = String(rawToken || '').trim();
  if (!token) return { error: 'invalid_token', message: 'This reset link is not valid.' };

  const reset = repo.passwordResets.byTokenHash(sha256(token));
  if (!reset) return { error: 'invalid_token', message: 'This reset link is not valid.' };
  if (reset.usedAt) {
    return { error: 'token_used', message: 'This reset link has already been used.' };
  }
  if (new Date(reset.expiresAt) < new Date()) {
    return { error: 'token_expired', message: 'This reset link has expired. Ask for a new one.' };
  }

  const user = repo.users.byId(reset.userId);
  if (!user || user.disabled) {
    return { error: 'invalid_token', message: 'This reset link is not valid.' };
  }

  return { reset, user };
}

/** POST /api/auth/reset/verify — is this link still good? */
router.post('/reset/verify', rateLimit({ windowMs: 15 * 60_000, max: 20, key: 'resetverify' }), (req, res) => {
  const result = resolveReset(req.body?.token);
  if (result.error) return res.status(400).json(result);

  res.json({
    ok: true,
    email: maskEmail(result.user.email),
    expiresAt: result.reset.expiresAt
  });
});

/** POST /api/auth/reset — consume the link and set a new password. */
router.post('/reset', rateLimit({ windowMs: 15 * 60_000, max: 10, key: 'reset' }), (req, res) => {
  const result = resolveReset(req.body?.token);
  if (result.error) return res.status(400).json(result);

  const password = String(req.body?.password || '');
  const strength = passwordStrength(password);
  if (!strength.ok) {
    return res.status(400).json({
      error: 'weak_password',
      fields: { password: `Password needs ${strength.issues.join(', ')}.` },
      score: strength.score
    });
  }

  // Burn the token before touching the password: if two requests race, the
  // loser finds it already used rather than both succeeding.
  if (!repo.passwordResets.markUsed(result.reset.id)) {
    return res.status(400).json({ error: 'token_used', message: 'This reset link has already been used.' });
  }

  repo.users.update(result.user.id, { passwordHash: auth.hashPassword(password) });

  // Whoever prompted this reset may be the reason the account was at risk, so
  // every existing session is dropped rather than left running.
  const revoked = repo.sessions.revokeAllForUser(result.user.id);
  audit(req, 'auth.password.reset', `${result.user.email} (${revoked} session(s) revoked)`);

  res.json({
    ok: true,
    message: 'Password updated. Sign in with your new password.',
    sessionsRevoked: revoked
  });
});

/** POST /api/auth/password-check — live strength meter for the signup form. */
router.post('/password-check', rateLimit({ windowMs: 60_000, max: 60, key: 'pwcheck' }), (req, res) => {
  const password = String(req.body?.password || '');
  const strength = passwordStrength(password);
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
  res.json({
    score: strength.score,
    label: labels[strength.score] || 'Very weak',
    ok: strength.ok,
    issues: strength.issues
  });
});

module.exports = router;
