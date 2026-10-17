'use strict';

/**
 * Password hashing (scrypt) + stateless HMAC session tokens, backed by the
 * SQLite session table for revocation. Uses only node:crypto — no
 * third-party auth dependency.
 */

const crypto = require('crypto');
const repo = require('../db/repository');
const secret = require('./secret');

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };
const TOKEN_TTL_MS = 1000 * 60 * 60 * 12; // 12 hours

// Long enough to fetch a code from a phone, short enough that an intercepted
// challenge is not worth much.
const CHALLENGE_TTL_MS = 1000 * 60 * 5;

// Programmatic credentials are labelled so a leaked one is recognisable in a
// log or a public repository, the way most API providers now prefix theirs.
const API_KEY_SCHEME = 'vgil';
const API_KEY_PREFIX_LEN = 13; // "vgil_" + 8 characters

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto
    .scryptSync(password, salt, SCRYPT_PARAMS.keylen, SCRYPT_PARAMS)
    .toString('hex');
  return `scrypt$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, salt, hash] = String(stored).split('$');
    if (scheme !== 'scrypt' || !salt || !hash) return false;
    const derived = crypto.scryptSync(
      password,
      salt,
      SCRYPT_PARAMS.keylen,
      SCRYPT_PARAMS
    );
    const expected = Buffer.from(hash, 'hex');
    if (expected.length !== derived.length) return false;
    return crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function sign(payloadB64) {
  return crypto.createHmac('sha256', secret.get()).update(payloadB64).digest('base64url');
}

/**
 * @param {Object} user
 * @param {{ip?:string, userAgent?:string}} context recorded against the session
 */
function issueToken(user, context = {}) {
  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    iat: Date.now(),
    exp: Date.now() + TOKEN_TTL_MS,
    jti: crypto.randomUUID()
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const token = `${body}.${sign(body)}`;

  repo.sessions.insert({
    id: payload.jti,
    userId: user.id,
    issuedAt: new Date(payload.iat).toISOString(),
    expiresAt: new Date(payload.exp).toISOString(),
    revoked: false,
    ip: context.ip,
    userAgent: context.userAgent
  });

  // Expired rows can no longer authenticate anything, so they are dropped
  // rather than accumulating for the life of the deployment.
  repo.sessions.prune();

  return { token, expiresAt: payload.exp, sessionId: payload.jti };
}

function verifyToken(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;

  const expected = sign(body);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!payload.exp || payload.exp < Date.now()) return null;

  // Half-authenticated MFA challenge tokens are signed with the same key, so
  // without this check one would be accepted as a full session and the second
  // factor could be skipped entirely. Tokens issued before this field existed
  // carry no `typ` and are still sessions.
  if (payload.typ && payload.typ !== 'session') return null;

  const session = repo.sessions.byId(payload.jti);
  if (session && session.revoked) return null;

  return payload;
}

/**
 * A short-lived token proving only that the password step succeeded.
 *
 * Creates no session row: until the second factor is presented there is
 * nothing to revoke, and nothing this token can authorise.
 */
function issueChallenge(user) {
  const payload = {
    sub: user.id,
    typ: 'mfa',
    iat: Date.now(),
    exp: Date.now() + CHALLENGE_TTL_MS,
    jti: crypto.randomUUID()
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return { challenge: `${body}.${sign(body)}`, expiresAt: payload.exp };
}

/** Counterpart to issueChallenge — accepts *only* `typ: 'mfa'` tokens. */
function verifyChallenge(token) {
  if (typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;

  const expected = sign(body);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (payload.typ !== 'mfa') return null;
  if (!payload.exp || payload.exp < Date.now()) return null;

  return payload;
}

function revokeToken(token) {
  const payload = verifyToken(token);
  if (!payload) return false;
  return repo.sessions.revoke(payload.jti);
}

function bearerFrom(req) {
  const header = req.get('authorization') || '';
  if (header.toLowerCase().startsWith('bearer ')) return header.slice(7).trim();
  return null;
}

/** Hard gate: 401 when there is no valid session. */
function requireAuth(req, res, next) {
  const token = bearerFrom(req);
  const payload = token && verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'unauthorized', message: 'Valid session token required.' });
  }
  const user = repo.users.byId(payload.sub);
  if (!user || user.disabled) {
    return res.status(401).json({ error: 'unauthorized', message: 'Account is no longer active.' });
  }
  req.user = user;
  req.token = token;
  req.sessionId = payload.jti;
  next();
}

/**
 * Soft gate: attaches req.user when a credential is present, never blocks.
 *
 * Recognises API keys as well as session tokens so a scripted caller is
 * identified on the public read endpoints — which is what lets those requests
 * be attributed and given their own rate-limit budget.
 */
function optionalAuth(req, _res, next) {
  const presented = bearerFrom(req) || req.get('x-api-key');

  if (typeof presented === 'string' && presented.startsWith(`${API_KEY_SCHEME}_`)) {
    const result = authenticateApiKey(presented);
    if (result) {
      req.user = result.user;
      req.apiKey = result.key;
    }
    return next();
  }

  const payload = presented && verifyToken(presented);
  if (payload) {
    const user = repo.users.byId(payload.sub);
    if (user && !user.disabled) {
      req.user = user;
      req.token = presented;
      req.sessionId = payload.jti;
    }
  }
  next();
}

/* ------------------------------------------------------------- api keys */

/**
 * Mints a programmatic credential.
 *
 * The plaintext is returned once and never stored. `prefix` is kept in the
 * clear so the console can identify a key without being able to reconstruct
 * it, and so lookup is an indexed hit rather than a table scan.
 */
function generateApiKey() {
  const key = `${API_KEY_SCHEME}_${crypto.randomBytes(24).toString('base64url')}`;
  return { key, prefix: key.slice(0, API_KEY_PREFIX_LEN), hash: hashApiKey(key) };
}

/**
 * SHA-256 rather than scrypt, on purpose. Password hashing is slow to make
 * guessing a human-chosen secret expensive; an API key is 192 random bits,
 * so there is nothing to guess, and this runs on every API request.
 */
function hashApiKey(key) {
  return crypto.createHash('sha256').update(String(key)).digest('hex');
}

/**
 * Resolves a presented key to its owner.
 * @returns {{user:Object, key:Object}|null}
 */
function authenticateApiKey(raw) {
  if (typeof raw !== 'string' || !raw.startsWith(`${API_KEY_SCHEME}_`)) return null;

  const candidates = repo.apiKeys.byPrefix(raw.slice(0, API_KEY_PREFIX_LEN));
  if (!candidates.length) return null;

  const presented = Buffer.from(hashApiKey(raw), 'hex');

  for (const record of candidates) {
    const stored = Buffer.from(record.keyHash, 'hex');
    if (stored.length !== presented.length) continue;
    if (!crypto.timingSafeEqual(stored, presented)) continue;

    if (record.expiresAt && new Date(record.expiresAt) < new Date()) return null;

    const user = repo.users.byId(record.userId);
    if (!user || user.disabled) return null;

    repo.apiKeys.touch(record.id);
    return { user, key: record };
  }

  return null;
}

/**
 * Accepts either a browser session token or an API key.
 *
 * Keys are read-only: they exist so a SIEM or a script can pull alerts and
 * incidents out, not so an unattended credential can close an incident. Write
 * routes keep using requireAuth and are therefore unreachable with a key.
 */
function requireAuthOrKey(req, res, next) {
  const presented = bearerFrom(req) || req.get('x-api-key');

  if (typeof presented === 'string' && presented.startsWith(`${API_KEY_SCHEME}_`)) {
    const result = authenticateApiKey(presented);
    if (!result) {
      return res.status(401).json({ error: 'unauthorized', message: 'API key is not valid.' });
    }
    if (req.method !== 'GET') {
      return res.status(403).json({
        error: 'read_only_credential',
        message: 'API keys are read-only. Use a session token for write operations.'
      });
    }
    req.user = result.user;
    req.apiKey = result.key;
    return next();
  }

  return requireAuth(req, res, next);
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: 'forbidden',
        message: `Requires role: ${roles.join(' or ')}. You are ${req.user.role}.`
      });
    }
    next();
  };
}

/**
 * Strips every credential before a user object crosses the wire.
 *
 * Destructuring by name rather than picking an allow-list is deliberate here:
 * the repository returns exactly the columns the table has, so a new
 * non-secret column shows up in the API automatically. The trade-off is that
 * a future *secret* column must be added to this list — hence the explicit
 * naming of each one below rather than a spread with a comment.
 */
function publicUser(user) {
  if (!user) return null;
  const {
    passwordHash,
    mfaSecret,
    mfaPendingSecret,
    mfaLastCounter,
    ...safe
  } = user;
  return safe;
}

module.exports = {
  hashPassword,
  verifyPassword,
  issueToken,
  verifyToken,
  revokeToken,
  issueChallenge,
  verifyChallenge,
  generateApiKey,
  hashApiKey,
  authenticateApiKey,
  requireAuth,
  requireAuthOrKey,
  optionalAuth,
  requireRole,
  publicUser,
  TOKEN_TTL_MS,
  CHALLENGE_TTL_MS,
  API_KEY_SCHEME
};
