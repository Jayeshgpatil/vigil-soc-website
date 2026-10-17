'use strict';

/**
 * Email alerting: decides who should hear about an event, renders the
 * message, and delivers or spools it.
 *
 * Two design points worth stating.
 *
 * Alerting is opt-in. A monitoring product that mails everyone by default
 * teaches its users to filter it into a folder they never open, which is
 * worse than not mailing them at all.
 *
 * With no SMTP host configured, notifications are still selected, rendered
 * and recorded — they land in the delivery log marked "spooled". The whole
 * decision path stays exercisable on a machine with no mail server, and the
 * failure mode is a visible log entry rather than silence.
 */

const config = require('./config');
const repo = require('../db/repository');
const smtp = require('./smtp');
const { escapeHtml } = require('./security');

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/* ------------------------------------------------------------ selection */

function meetsSeverity(severity, minimum) {
  return (SEVERITY_RANK[severity] ?? 0) >= (SEVERITY_RANK[minimum] ?? 3);
}

/**
 * Quiet hours as "22:00-07:00", interpreted in server local time and allowed
 * to wrap past midnight.
 *
 * A critical event ignores them. Someone who asked not to be woken at 03:00
 * still wants to know the domain controller is compromised — quiet hours are
 * for noise, not for emergencies.
 */
function inQuietHours(spec, at = new Date()) {
  if (!spec || !/^\d{2}:\d{2}-\d{2}:\d{2}$/.test(spec)) return false;

  const [from, to] = spec.split('-');
  const minutes = at.getHours() * 60 + at.getMinutes();
  const parse = (value) => Number(value.slice(0, 2)) * 60 + Number(value.slice(3, 5));

  const start = parse(from);
  const end = parse(to);

  return start <= end ? minutes >= start && minutes < end : minutes >= start || minutes < end;
}

/**
 * Whether one subscriber should be told about one event.
 * @returns {{send:boolean, defer:boolean, reason:string}}
 */
function decide(prefs, event) {
  if (!prefs.emailEnabled) return { send: false, defer: false, reason: 'not subscribed' };

  if (event.kind === 'incident' && !prefs.onIncident) {
    return { send: false, defer: false, reason: 'incident notifications off' };
  }
  if (event.kind === 'alert' && !prefs.onCritical) {
    return { send: false, defer: false, reason: 'alert notifications off' };
  }
  if (event.kind === 'assignment' && !prefs.onAssignment) {
    return { send: false, defer: false, reason: 'assignment notifications off' };
  }

  if (event.severity && !meetsSeverity(event.severity, prefs.minSeverity)) {
    return { send: false, defer: false, reason: `below ${prefs.minSeverity}` };
  }

  const isCritical = event.severity === 'critical';

  if (!isCritical && inQuietHours(prefs.quietHours)) {
    return { send: false, defer: true, reason: 'quiet hours' };
  }
  if (!isCritical && prefs.cadence !== 'immediate') {
    return { send: false, defer: true, reason: `${prefs.cadence} digest` };
  }

  return { send: true, defer: false, reason: 'immediate' };
}

/* ------------------------------------------------------------ rendering */

function severityLabel(severity) {
  return String(severity || 'info').toUpperCase();
}

/**
 * Plain text and HTML for one event.
 *
 * Every interpolated value is escaped for the HTML part. Alert fields carry
 * hostnames, usernames and rule names that originate in telemetry, which is
 * attacker-influenced — an unescaped one is a stored-XSS payload delivered
 * straight to an analyst's mail client.
 */
function renderEvent(event) {
  const url = `${config.publicUrl}${event.path || '/dashboard.html'}`;
  const rows = event.details || [];

  const text = [
    event.title,
    '',
    event.summary || '',
    '',
    ...rows.map(([label, value]) => `${label}: ${value}`),
    '',
    `View in VGIL: ${url}`,
    '',
    '— VGIL Security Operations',
    'Change what you receive: ' + config.publicUrl + '/account.html#notifications'
  ].join('\n');

  const html = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f4f7fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0d1520">
  <div style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #dde4ed;border-radius:10px;overflow:hidden">
    <div style="padding:14px 20px;background:#05080d;color:#e7eef7">
      <strong style="letter-spacing:.08em;font-size:13px">VGIL</strong>
      <span style="color:#8d9db2;font-size:12px"> · SECURITY OPERATIONS</span>
    </div>
    <div style="padding:20px">
      ${
        event.severity
          ? `<div style="display:inline-block;padding:3px 9px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.06em;background:${
              event.severity === 'critical' ? '#cc1f3d' : event.severity === 'high' ? '#b85c00' : '#4a5b70'
            };color:#fff">${escapeHtml(severityLabel(event.severity))}</div>`
          : ''
      }
      <h1 style="margin:12px 0 6px;font-size:18px;line-height:1.35">${escapeHtml(event.title)}</h1>
      ${event.summary ? `<p style="margin:0 0 16px;color:#4a5b70;font-size:14px;line-height:1.55">${escapeHtml(event.summary)}</p>` : ''}
      ${
        rows.length
          ? `<table style="width:100%;border-collapse:collapse;font-size:13px">${rows
              .map(
                ([label, value]) =>
                  `<tr><td style="padding:6px 0;color:#4a5b70;width:38%">${escapeHtml(label)}</td><td style="padding:6px 0;font-family:ui-monospace,Consolas,monospace">${escapeHtml(String(value))}</td></tr>`
              )
              .join('')}</table>`
          : ''
      }
      <p style="margin:22px 0 0">
        <a href="${escapeHtml(url)}" style="display:inline-block;padding:10px 18px;background:#00805a;color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600">Open in VGIL</a>
      </p>
    </div>
    <div style="padding:14px 20px;border-top:1px solid #dde4ed;color:#616e7f;font-size:12px">
      You are receiving this because email alerting is on for your account.
      <a href="${escapeHtml(config.publicUrl)}/account.html#notifications" style="color:#00805a">Change what you receive</a>.
    </div>
  </div>
</body></html>`;

  return { text, html };
}

/* ------------------------------------------------------------ delivery */

let idCounter = 0;
function logId() {
  idCounter += 1;
  return `EML-${Date.now().toString(36).toUpperCase()}${idCounter.toString(36).toUpperCase()}`;
}

/**
 * Sends one message, or records why it could not be sent.
 * Never throws — a failed notification must not break the request that
 * triggered it.
 *
 * @returns {Promise<{status:string, transport:string, error?:string}>}
 */
async function deliver({ to, subject, text, html, kind }) {
  const createdAt = new Date().toISOString();
  const preview = String(text || '').slice(0, 400);

  if (!config.smtp.configured) {
    repo.emailLog.insert({
      id: logId(),
      to,
      subject,
      kind,
      status: 'spooled',
      transport: 'spool',
      preview,
      createdAt
    });
    repo.emailLog.trim(300);
    return { status: 'spooled', transport: 'spool' };
  }

  try {
    await smtp.send(config.smtp, {
      from: config.smtp.from,
      fromName: config.smtp.fromName,
      to,
      subject,
      text,
      html
    });

    repo.emailLog.insert({
      id: logId(),
      to,
      subject,
      kind,
      status: 'sent',
      transport: 'smtp',
      preview,
      createdAt
    });
    repo.emailLog.trim(300);
    return { status: 'sent', transport: 'smtp' };
  } catch (err) {
    repo.emailLog.insert({
      id: logId(),
      to,
      subject,
      kind,
      status: 'failed',
      transport: 'smtp',
      error: err.message,
      preview,
      createdAt
    });
    repo.emailLog.trim(300);
    return { status: 'failed', transport: 'smtp', error: err.message };
  }
}

/* --------------------------------------------------------------- events */

/**
 * Fans one event out to everyone subscribed to it.
 *
 * Returns immediately; delivery continues in the background so an unreachable
 * mail server cannot slow the request that produced the event.
 *
 * @returns {{matched:number, immediate:number, deferred:number}}
 */
function dispatch(event) {
  let subscribers;
  try {
    subscribers = repo.notificationPrefs.subscribers();
  } catch {
    // A missing or mid-migration table must not break the caller.
    return { matched: 0, immediate: 0, deferred: 0 };
  }

  const rendered = renderEvent(event);
  let immediate = 0;
  let deferred = 0;

  for (const subscriber of subscribers) {
    // Never tell someone about their own action.
    if (event.actorEmail && subscriber.email === event.actorEmail) continue;

    const verdict = decide(subscriber, event);

    if (verdict.send) {
      immediate += 1;
      deliver({
        to: subscriber.email,
        subject: event.subject || event.title,
        text: rendered.text,
        html: rendered.html,
        kind: event.kind
      }).catch(() => {});
    } else if (verdict.defer) {
      deferred += 1;
      repo.notificationQueue.push({
        userId: subscriber.userId,
        kind: event.kind,
        subject: event.subject || event.title,
        payload: event,
        createdAt: new Date().toISOString()
      });
    }
  }

  return { matched: subscribers.length, immediate, deferred };
}

/** Convenience wrappers so callers do not assemble the event shape by hand. */
function incidentOpened(incident, actorEmail) {
  return dispatch({
    kind: 'incident',
    severity: incident.severity,
    actorEmail,
    title: `${incident.id}: ${incident.title}`,
    subject: `[VGIL ${severityLabel(incident.severity)}] ${incident.id} — ${incident.title}`,
    summary: incident.summary,
    path: `/incidents.html?id=${encodeURIComponent(incident.id)}`,
    details: [
      ['Incident', incident.id],
      ['Severity', severityLabel(incident.severity)],
      ['Priority', incident.priority || '—'],
      ['Asset', incident.host || '—'],
      ['Technique', incident.technique || '—'],
      ['Opened', incident.openedAt]
    ]
  });
}

function incidentStatusChanged(incident, previous, actorEmail) {
  return dispatch({
    kind: 'incident',
    severity: incident.severity,
    actorEmail,
    title: `${incident.id} is now ${incident.status}`,
    subject: `[VGIL] ${incident.id} — ${previous} → ${incident.status}`,
    summary: incident.title,
    path: `/incidents.html?id=${encodeURIComponent(incident.id)}`,
    details: [
      ['Incident', incident.id],
      ['Was', previous],
      ['Now', incident.status],
      ['Severity', severityLabel(incident.severity)],
      ['Asset', incident.host || '—']
    ]
  });
}

function criticalAlert(alert) {
  return dispatch({
    kind: 'alert',
    severity: alert.severity,
    title: `${alert.rule} on ${alert.host}`,
    subject: `[VGIL CRITICAL] ${alert.rule} — ${alert.host}`,
    summary: alert.description,
    path: `/dashboard.html?alert=${encodeURIComponent(alert.id)}`,
    details: [
      ['Alert', alert.id],
      ['Rule', alert.rule],
      ['Technique', `${alert.technique || '—'} ${alert.techniqueName || ''}`.trim()],
      ['Asset', alert.host || '—'],
      ['Source', alert.sourceIp || '—'],
      ['Risk', `${alert.risk}/100`]
    ]
  });
}

/* --------------------------------------------------------------- digest */

/**
 * Drains the queue into one message per recipient.
 *
 * Called on a timer for hourly/daily subscribers, and on demand from the
 * account page so somebody can see what a digest looks like without waiting
 * an hour for one.
 */
async function runDigest({ userId = null } = {}) {
  const recipients = userId ? [userId] : repo.notificationQueue.pendingRecipients();
  const sent = [];

  for (const recipient of recipients) {
    const pending = repo.notificationQueue.pendingFor(recipient);
    if (!pending.length) continue;

    const user = repo.users.byId(recipient);
    if (!user || user.disabled) continue;

    const prefs = repo.notificationPrefs.forUser(recipient);
    if (!prefs.emailEnabled) continue;

    const lines = pending.map((item) => `• ${item.subject}`);
    const text = [
      `${pending.length} notification${pending.length === 1 ? '' : 's'} from VGIL`,
      '',
      ...lines,
      '',
      `View the console: ${config.publicUrl}/dashboard.html`,
      '',
      '— VGIL Security Operations'
    ].join('\n');

    const html = `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f4f7fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0d1520">
  <div style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #dde4ed;border-radius:10px;overflow:hidden">
    <div style="padding:14px 20px;background:#05080d;color:#e7eef7">
      <strong style="letter-spacing:.08em;font-size:13px">VGIL</strong>
      <span style="color:#8d9db2;font-size:12px"> · DIGEST</span>
    </div>
    <div style="padding:20px">
      <h1 style="margin:0 0 14px;font-size:18px">${pending.length} notification${pending.length === 1 ? '' : 's'}</h1>
      <ul style="margin:0;padding-left:18px;font-size:14px;line-height:1.7">
        ${pending.map((item) => `<li>${escapeHtml(item.subject)}</li>`).join('')}
      </ul>
      <p style="margin:22px 0 0">
        <a href="${escapeHtml(config.publicUrl)}/dashboard.html" style="display:inline-block;padding:10px 18px;background:#00805a;color:#fff;text-decoration:none;border-radius:6px;font-size:14px;font-weight:600">Open the console</a>
      </p>
    </div>
  </div>
</body></html>`;

    const result = await deliver({
      to: user.email,
      subject: `[VGIL] ${pending.length} notification${pending.length === 1 ? '' : 's'}`,
      text,
      html,
      kind: 'digest'
    });

    // Marked sent even when spooled: the queue tracks what has been rolled
    // into a digest, and the delivery log is what records the outcome.
    repo.notificationQueue.markSent(pending.map((item) => item.id));
    sent.push({ userId: recipient, count: pending.length, ...result });
  }

  return sent;
}

/** Sends a one-off message so somebody can prove their settings work. */
async function sendTest(user) {
  const rendered = renderEvent({
    kind: 'test',
    severity: 'info',
    title: 'Test notification',
    summary:
      'If you are reading this, email alerting is working for your account. This message was sent on request and is not tied to any detection.',
    path: '/account.html#notifications',
    details: [
      ['Account', user.email],
      ['Transport', config.smtp.configured ? `SMTP · ${config.smtp.host}` : 'Spooled (no SMTP host configured)'],
      ['Sent', new Date().toISOString()]
    ]
  });

  return deliver({
    to: user.email,
    subject: '[VGIL] Test notification',
    text: rendered.text,
    html: rendered.html,
    kind: 'test'
  });
}

let digestTimer = null;

/** Periodic digest drain. Idempotent — calling twice does not double up. */
function startDigestTimer(intervalMs = 15 * 60_000) {
  if (digestTimer) return digestTimer;
  digestTimer = setInterval(() => {
    runDigest().catch(() => {});
    repo.notificationQueue.prune(new Date(Date.now() - 7 * 24 * 3600_000).toISOString());
  }, intervalMs);
  if (digestTimer.unref) digestTimer.unref();
  return digestTimer;
}

function stopDigestTimer() {
  if (digestTimer) clearInterval(digestTimer);
  digestTimer = null;
}

module.exports = {
  decide,
  inQuietHours,
  meetsSeverity,
  renderEvent,
  deliver,
  dispatch,
  incidentOpened,
  incidentStatusChanged,
  criticalAlert,
  runDigest,
  sendTest,
  startDigestTimer,
  stopDigestTimer,
  SEVERITY_RANK
};
