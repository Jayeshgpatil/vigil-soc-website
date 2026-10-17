'use strict';

/**
 * Outbound event delivery to subscriber endpoints (Slack, Teams, a SIEM, a
 * pager). Fire-and-forget: a slow or dead receiver must never delay the
 * request that produced the event.
 *
 * Payloads are signed so a receiver can prove the call came from this
 * instance rather than from anyone who learned the URL.
 */

const crypto = require('crypto');
const dns = require('dns').promises;
const net = require('net');

const repo = require('../db/repository');
const config = require('./config');

const TIMEOUT_MS = 5000;
const MAX_BODY_LOG = 300;

const EVENTS = [
  'incident.opened',
  'incident.escalated',
  'incident.closed',
  'alert.critical',
  'auth.mfa.disabled'
];

/* ----------------------------------------------------------------- SSRF */

// Loopback, link-local, and the RFC 1918 / RFC 4193 private ranges. A webhook
// URL is operator-supplied, which makes this endpoint a request forger's
// ideal primitive: it turns "admin can type a URL" into "admin can make the
// server probe its own cloud metadata service".
function isPrivateAddress(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true; // includes 169.254.169.254
    if (a >= 224) return true;
    return false;
  }
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower === '::') return true;
    if (lower.startsWith('fe80')) return true; // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local
    // IPv4-mapped, e.g. ::ffff:169.254.169.254
    const mapped = lower.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateAddress(mapped[1]);
    return false;
  }
  return false;
}

/**
 * Validates a webhook destination.
 *
 * In development the private-range check is relaxed, because testing a
 * webhook against a local listener is the normal way to set one up. It is
 * enforced as soon as NODE_ENV is production.
 *
 * @returns {{ok:true}|{ok:false, reason:string}}
 */
async function validateUrl(raw) {
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    return { ok: false, reason: 'That is not a valid URL.' };
  }

  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { ok: false, reason: 'Webhook URLs must be http or https.' };
  }
  if (config.production && url.protocol !== 'https:') {
    return { ok: false, reason: 'Webhook URLs must use https.' };
  }
  if (!config.production) return { ok: true };

  // Resolve before allowing it: a hostname that looks external can still
  // point at an internal address.
  let addresses;
  try {
    addresses = await dns.lookup(url.hostname, { all: true });
  } catch {
    return { ok: false, reason: 'That hostname could not be resolved.' };
  }

  if (addresses.some((entry) => isPrivateAddress(entry.address))) {
    return { ok: false, reason: 'That host resolves to a private address.' };
  }

  return { ok: true };
}

/* ------------------------------------------------------------- signing */

/** A receiver recomputes this over the raw body to authenticate the call. */
function signPayload(secret, timestamp, body) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${body}`)
    .digest('hex');
}

function generateSecret() {
  return `whsec_${crypto.randomBytes(24).toString('base64url')}`;
}

/* ------------------------------------------------------------ delivery */

/**
 * Delivers one event to one subscriber, recording the outcome either way.
 * Never throws — the caller is an event emitter, not a request handler.
 */
async function deliverTo(hook, event, payload) {
  const attemptedAt = new Date().toISOString();
  const started = Date.now();

  const body = JSON.stringify({
    event,
    instance: 'vgil',
    deliveredAt: attemptedAt,
    data: payload
  });

  const timestamp = Math.floor(Date.now() / 1000);

  try {
    const response = await fetch(hook.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'VGIL-Webhook/1.0',
        'x-vgil-event': event,
        'x-vgil-timestamp': String(timestamp),
        // Timestamp is inside the signed string, so a captured payload cannot
        // be replayed later against a receiver that checks its freshness.
        'x-vgil-signature': `sha256=${signPayload(hook.secret, timestamp, body)}`
      },
      body,
      signal: AbortSignal.timeout(TIMEOUT_MS),
      redirect: 'error'
    });

    repo.webhooks.recordDelivery(hook.id, {
      event,
      status: response.ok ? 'delivered' : 'failed',
      responseCode: response.status,
      error: response.ok ? null : `Receiver returned ${response.status}`,
      attemptedAt,
      durationMs: Date.now() - started
    });

    return response.ok;
  } catch (err) {
    repo.webhooks.recordDelivery(hook.id, {
      event,
      status: 'failed',
      responseCode: null,
      error: String(err.message || err).slice(0, MAX_BODY_LOG),
      attemptedAt,
      durationMs: Date.now() - started
    });
    return false;
  }
}

/**
 * Publishes an event to every active subscriber.
 *
 * Returns immediately; delivery continues in the background. Callers on a
 * request path must not await this.
 */
function dispatch(event, payload) {
  let hooks;
  try {
    hooks = repo.webhooks.activeFor(event);
  } catch {
    // A webhook table that is missing or mid-migration must not break the
    // request that triggered the event.
    return 0;
  }
  if (!hooks.length) return 0;

  for (const hook of hooks) {
    // Detached on purpose: an unreachable receiver should not surface as an
    // unhandled rejection, and deliverTo already records its own failures.
    deliverTo(hook, event, payload).catch(() => {});
  }

  return hooks.length;
}

/** Sends a synthetic event so an operator can confirm a new endpoint works. */
async function test(hook) {
  return deliverTo(hook, 'webhook.test', {
    message: 'This is a test delivery from VGIL.',
    sentAt: new Date().toISOString()
  });
}

module.exports = {
  EVENTS,
  dispatch,
  deliverTo,
  test,
  validateUrl,
  signPayload,
  generateSecret,
  isPrivateAddress
};
