'use strict';

/**
 * TOTP (RFC 6238) over HMAC-SHA1, plus the Base32 codec RFC 4648 requires.
 *
 * Implemented against node:crypto rather than pulled from npm: the algorithm
 * is roughly sixty lines, and an authentication primitive is the last place
 * to inherit a dependency tree that can be swapped under us.
 *
 * Interoperates with Google Authenticator, 1Password, Aegis and Authy, all of
 * which assume SHA-1 / 6 digits / 30-second steps regardless of what the
 * otpauth:// URI declares.
 */

const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const DIGITS = 6;
const STEP_SECONDS = 30;

// How many steps either side of "now" still verify. One step of tolerance
// absorbs clock drift between the phone and the server without meaningfully
// widening the window an attacker can guess into.
const DEFAULT_WINDOW = 1;

/* --------------------------------------------------------------- base32 */

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 31];

  return output;
}

function base32Decode(input) {
  // Authenticator apps display secrets in spaced groups, and some users paste
  // them back with the padding still attached.
  const clean = String(input).toUpperCase().replace(/[\s=]/g, '');

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error('Secret is not valid Base32.');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/* ------------------------------------------------------------------ totp */

/** A fresh 160-bit secret — the size RFC 4226 recommends for HMAC-SHA1. */
function generateSecret() {
  return base32Encode(crypto.randomBytes(20));
}

/**
 * The one-time code for a given counter step.
 * @param {string} secret Base32
 * @param {number} counter Unix time / 30, floored
 */
function codeForCounter(secret, counter) {
  const key = base32Decode(secret);

  // Counter is a 64-bit big-endian integer. Written as two 32-bit halves
  // because a JS bitwise op would truncate to 32 bits.
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);

  const digest = crypto.createHmac('sha1', key).update(buffer).digest();

  // Dynamic truncation (RFC 4226 §5.4): the low nibble of the last byte
  // selects which four bytes become the code.
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];

  return String(binary % 10 ** DIGITS).padStart(DIGITS, '0');
}

/** The code valid right now. */
function generate(secret, at = Date.now()) {
  return codeForCounter(secret, Math.floor(at / 1000 / STEP_SECONDS));
}

/**
 * Constant-time verification across a small window of steps.
 *
 * Returns the matched counter rather than `true` so the caller can persist it
 * and refuse a replay of the same code inside its validity window.
 *
 * @returns {{valid:boolean, counter:number|null}}
 */
function verify(secret, token, { at = Date.now(), window = DEFAULT_WINDOW } = {}) {
  const candidate = String(token || '').replace(/\D/g, '');
  if (candidate.length !== DIGITS) return { valid: false, counter: null };

  const current = Math.floor(at / 1000 / STEP_SECONDS);

  for (let drift = -window; drift <= window; drift += 1) {
    let expected;
    try {
      expected = codeForCounter(secret, current + drift);
    } catch {
      return { valid: false, counter: null };
    }
    const a = Buffer.from(expected);
    const b = Buffer.from(candidate);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return { valid: true, counter: current + drift };
    }
  }

  return { valid: false, counter: null };
}

/**
 * otpauth:// URI for the enrolment QR code.
 *
 * The label carries the account so a user with several VGIL environments can
 * tell the entries apart in their authenticator.
 */
function otpauthUrl({ secret, email, issuer = 'VGIL' }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS)
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/* -------------------------------------------------------- recovery codes */

/**
 * Single-use codes for when the authenticator is lost.
 *
 * Grouped in fours for legibility on the printed page. Returned in plaintext
 * exactly once; the caller stores only hashes.
 */
function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i += 1) {
    const raw = crypto.randomBytes(5).toString('hex').toUpperCase(); // 10 chars
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}

/**
 * Recovery codes are high-entropy and looked up by exact match, so a fast
 * digest is correct here — scrypt's work factor exists to slow guessing at a
 * low-entropy secret, which this is not.
 */
function hashRecoveryCode(code) {
  return crypto
    .createHash('sha256')
    .update(String(code).toUpperCase().replace(/[\s-]/g, ''))
    .digest('hex');
}

module.exports = {
  base32Encode,
  base32Decode,
  generateSecret,
  generate,
  verify,
  otpauthUrl,
  generateRecoveryCodes,
  hashRecoveryCode,
  DIGITS,
  STEP_SECONDS
};
