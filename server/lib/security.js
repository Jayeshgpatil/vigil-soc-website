'use strict';

/**
 * Security middleware: hardening headers, a sliding-window rate limiter,
 * and small validation/sanitisation helpers used by every route.
 */

const crypto = require('crypto');

/** Security response headers, roughly what helmet would set. */
function securityHeaders(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "object-src 'none'"
    ].join('; ')
  );
  res.removeHeader('X-Powered-By');
  next();
}

/** Attaches a per-request id, echoed back so clients can correlate logs. */
function requestId(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
}

const buckets = new Map();

/**
 * Multiplier applied to every route budget. Production leaves this at 1; an
 * integration test suite hitting the API from a single address needs more
 * headroom than a real client ever would, and raising it beats the
 * alternative of switching the limiter off and shipping it untested.
 */
const FACTOR = Math.max(Number(process.env.VGIL_RATE_FACTOR) || 1, 1);

/**
 * Sliding-window rate limiter keyed by IP + route bucket.
 * @param {{windowMs:number, max:number, key?:string, absolute?:boolean}} opts
 *   `absolute` opts out of the environment multiplier, so a test can pin an
 *   exact threshold.
 */
function rateLimit({ windowMs = 60_000, max = 60, key = 'global', absolute = false } = {}) {
  const limit = absolute ? max : Math.round(max * FACTOR);

  return (req, res, next) => {
    const ip = clientIp(req);
    const id = `${key}:${ip}`;
    const now = Date.now();

    let hits = buckets.get(id) || [];
    hits = hits.filter((t) => now - t < windowMs);

    if (hits.length >= limit) {
      const retryAfter = Math.ceil((windowMs - (now - hits[0])) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      res.setHeader('X-RateLimit-Remaining', '0');
      return res.status(429).json({
        error: 'rate_limited',
        message: `Too many requests. Retry in ${retryAfter}s.`
      });
    }

    hits.push(now);
    buckets.set(id, hits);
    res.setHeader('X-RateLimit-Limit', String(limit));
    res.setHeader('X-RateLimit-Remaining', String(limit - hits.length));
    next();
  };
}

// Periodic sweep so the limiter map cannot grow without bound.
setInterval(() => {
  const cutoff = Date.now() - 15 * 60_000;
  for (const [id, hits] of buckets) {
    const live = hits.filter((t) => t > cutoff);
    if (live.length === 0) buckets.delete(id);
    else buckets.set(id, live);
  }
}, 5 * 60_000).unref();

function clientIp(req) {
  return (
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

/** Neutralises HTML-significant characters in user-supplied strings. */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function cleanString(value, maxLen = 500) {
  if (value === undefined || value === null) return '';
  return escapeHtml(String(value).trim().slice(0, maxLen));
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
const isEmail = (v) => typeof v === 'string' && EMAIL_RE.test(v.trim()) && v.length <= 254;

/**
 * Validates a body against a simple schema.
 * @returns {{ok:boolean, errors:Object, value:Object}}
 */
function validate(body, schema) {
  const errors = {};
  const value = {};

  for (const [field, rule] of Object.entries(schema)) {
    const raw = body?.[field];
    const present = raw !== undefined && raw !== null && String(raw).trim() !== '';

    if (rule.required && !present) {
      errors[field] = `${rule.label || field} is required.`;
      continue;
    }
    if (!present) {
      if (rule.default !== undefined) value[field] = rule.default;
      continue;
    }

    if (rule.type === 'email' && !isEmail(raw)) {
      errors[field] = 'Enter a valid email address.';
      continue;
    }
    if (rule.type === 'number') {
      const n = Number(raw);
      if (Number.isNaN(n)) {
        errors[field] = `${rule.label || field} must be a number.`;
        continue;
      }
      if (rule.min !== undefined && n < rule.min) {
        errors[field] = `${rule.label || field} must be at least ${rule.min}.`;
        continue;
      }
      if (rule.max !== undefined && n > rule.max) {
        errors[field] = `${rule.label || field} must be at most ${rule.max}.`;
        continue;
      }
      value[field] = n;
      continue;
    }
    if (rule.enum && !rule.enum.includes(String(raw))) {
      errors[field] = `${rule.label || field} must be one of: ${rule.enum.join(', ')}.`;
      continue;
    }
    if (rule.minLength && String(raw).length < rule.minLength) {
      errors[field] = `${rule.label || field} must be at least ${rule.minLength} characters.`;
      continue;
    }

    // Passwords are hashed, never rendered — keep them byte-exact.
    value[field] = rule.raw
      ? String(raw)
      : cleanString(raw, rule.maxLength || 500);
  }

  return { ok: Object.keys(errors).length === 0, errors, value };
}

/** Rejects weak passwords before an account is ever created. */
function passwordStrength(password) {
  const issues = [];
  if (password.length < 10) issues.push('at least 10 characters');
  if (!/[a-z]/.test(password)) issues.push('a lowercase letter');
  if (!/[A-Z]/.test(password)) issues.push('an uppercase letter');
  if (!/[0-9]/.test(password)) issues.push('a number');
  if (!/[^A-Za-z0-9]/.test(password)) issues.push('a symbol');

  const common = ['password', 'qwerty', '12345', 'letmein', 'admin', 'welcome'];
  if (common.some((c) => password.toLowerCase().includes(c))) {
    issues.push('no common dictionary words');
  }

  const score = Math.max(0, 5 - issues.length);
  return { ok: issues.length === 0, issues, score };
}

/**
 * Digest for opaque, high-entropy tokens — reset links, API keys.
 *
 * Byte-exact: unlike a recovery code, these are case-sensitive and must not
 * be normalised before hashing. Deliberately fast, because there is no
 * low-entropy secret here for a work factor to protect.
 */
function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

module.exports = {
  securityHeaders,
  requestId,
  rateLimit,
  clientIp,
  escapeHtml,
  cleanString,
  isEmail,
  validate,
  passwordStrength,
  sha256
};
