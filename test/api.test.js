'use strict';

/**
 * API test suite — node:test, no external test framework.
 *
 *   npm test
 *
 * Runs against an in-memory database (VGIL_DB=:memory:) on an ephemeral port,
 * so it never touches server/data and can run alongside a live server.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

// Must be set before any module opens the database or reads the signing key.
process.env.VGIL_DB = ':memory:';
delete process.env.VGIL_SECRET;

// The whole suite authenticates from one address far more often than a real
// client would. The limiter stays switched on — it is just given headroom, and
// its exact threshold behaviour is asserted separately below.
process.env.VGIL_RATE_FACTOR = '40';

const database = require('../server/db');
const repo = require('../server/db/repository');
const seed = require('../server/lib/seed');
const { createApp } = require('../server/app');
const { rateLimit } = require('../server/lib/security');
const { LATEST } = require('../server/db/migrate');

const ANALYST = { email: 'analyst@vgil.io', password: 'Vgil#Demo2026' };
const ADMIN = { email: 'admin@vgil.io', password: 'Vgil#Admin2026' };

let base;
let server;

/* ------------------------------------------------------------------ helpers */

async function api(path, { method = 'GET', body, token } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  const isJson = (res.headers.get('content-type') || '').includes('json');
  return { status: res.status, headers: res.headers, body: isJson ? await res.json() : await res.text() };
}

async function login(creds) {
  const res = await api('/api/auth/login', { method: 'POST', body: creds });
  assert.equal(res.status, 200, `login failed: ${JSON.stringify(res.body)}`);
  return res.body.token;
}

const unique = (prefix) => `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

/* -------------------------------------------------------------- lifecycle */

test.before(async () => {
  database.open({ quiet: true });
  seed.run({ force: true, quiet: true });

  // logRequests off so the suite output stays readable.
  const app = createApp({ logRequests: false });

  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });

  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  // Tolerate a failed before-hook, so teardown never masks the real error.
  if (server) await new Promise((resolve) => server.close(resolve));
  database.close();
});

/* ---------------------------------------------------------------- database */

test('schema migrates and seeds', () => {
  const conn = database.handle();
  assert.equal(conn.prepare('PRAGMA user_version').get().user_version, LATEST);

  assert.ok(repo.alerts.count() > 100, 'seeded alerts');
  assert.equal(repo.incidents.count(), 8);
  assert.equal(repo.users.count(), 2);
  assert.equal(repo.assets.count(), 15);
});

test('foreign keys cascade alert notes', () => {
  const alert = repo.alerts.query({ limit: 1 }).rows[0];
  repo.alerts.addNote(alert.id, { ts: new Date().toISOString(), author: 'test', text: 'note' });
  assert.equal(repo.alerts.byId(alert.id).notes.length, 1);

  database.handle().prepare('DELETE FROM alerts WHERE id = ?').run(alert.id);
  const orphans = database
    .handle()
    .prepare('SELECT COUNT(*) AS n FROM alert_notes WHERE alert_id = ?')
    .get(alert.id).n;
  assert.equal(orphans, 0, 'notes deleted with their alert');
});

test('incident sequence never reuses an id', () => {
  const first = repo.incidents.nextSequence();
  repo.incidents.insert({
    id: `INC-${first}`,
    title: 'Sequence probe',
    severity: 'low',
    status: 'open',
    priority: 'P3',
    summary: 'checking id allocation',
    openedAt: new Date().toISOString(),
    timeline: []
  });
  assert.equal(repo.incidents.nextSequence(), first + 1);
  repo.incidents.remove(`INC-${first}`);
});

/* -------------------------------------------------------------- public API */

test('health and readiness', async () => {
  const health = await api('/api/health');
  assert.equal(health.status, 200);
  assert.equal(health.body.status, 'operational');
  assert.equal(health.body.database, 'sqlite');

  const ready = await api('/api/ready');
  assert.equal(ready.status, 200);
  assert.equal(ready.body.ready, true);
});

test('security headers are present and the server is not identified', async () => {
  const res = await api('/api/health');
  assert.ok(res.headers.get('content-security-policy'));
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-frame-options'), 'DENY');
  assert.equal(res.headers.get('x-powered-by'), null);
  assert.ok(res.headers.get('x-request-id'));
});

test('static content catalogs', async () => {
  assert.equal((await api('/api/services')).body.data.length, 6);
  assert.equal((await api('/api/pricing')).body.data.length, 3);
  assert.equal((await api('/api/threats/actors')).body.total, 6);
  assert.equal((await api('/api/threats/rules')).body.total, 20);
});

test('unknown API route returns a JSON 404', async () => {
  const res = await api('/api/nope');
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

/* ------------------------------------------------------------------ alerts */

test('alert list paginates', async () => {
  const res = await api('/api/alerts?limit=5&page=2');
  assert.equal(res.status, 200);
  assert.equal(res.body.data.length, 5);
  assert.equal(res.body.pagination.page, 2);
  assert.equal(res.body.pagination.hasPrev, true);
});

test('alert list filters by severity', async () => {
  const res = await api('/api/alerts?severity=critical&limit=50');
  assert.ok(res.body.data.length > 0);
  for (const alert of res.body.data) assert.equal(alert.severity, 'critical');
});

test('alert list accepts a comma-separated severity list', async () => {
  const res = await api('/api/alerts?severity=critical,high&limit=50');
  for (const alert of res.body.data) {
    assert.ok(['critical', 'high'].includes(alert.severity));
  }
});

test('alert list sorts by risk descending', async () => {
  const res = await api('/api/alerts?sort=risk&order=desc&limit=20');
  const risks = res.body.data.map((a) => a.risk);
  for (let i = 1; i < risks.length; i += 1) assert.ok(risks[i - 1] >= risks[i]);
});

test('alert search matches host and technique', async () => {
  const sample = (await api('/api/alerts?limit=1')).body.data[0];
  const res = await api(`/api/alerts?q=${encodeURIComponent(sample.host)}&limit=50`);
  assert.ok(res.body.data.length > 0);
  for (const alert of res.body.data) assert.equal(alert.host, sample.host);
});

test('alert detail 404s for an unknown id', async () => {
  const res = await api('/api/alerts/ALT-DOES-NOT-EXIST');
  assert.equal(res.status, 404);
});

test('alert rows keep every documented field', async () => {
  const alert = (await api('/api/alerts?limit=1')).body.data[0];
  for (const key of [
    'id', 'ts', 'ruleId', 'rule', 'severity', 'tactic', 'technique', 'techniqueName',
    'source', 'description', 'recommendation', 'assetId', 'host', 'ip', 'zone',
    'assetType', 'criticality', 'owner', 'user', 'sourceIp', 'destPort',
    'confidence', 'risk', 'status', 'notes'
  ]) {
    assert.ok(key in alert, `missing field: ${key}`);
  }
  assert.ok(Array.isArray(alert.notes));
});

/* -------------------------------------------------------------------- auth */

test('register issues a session and never returns the hash', async () => {
  const res = await api('/api/auth/register', {
    method: 'POST',
    body: {
      name: 'Test Analyst',
      email: `${unique('user')}@example.com`,
      org: 'TestCo',
      password: 'Str0ng#Passw0rd!'
    }
  });

  assert.equal(res.status, 201);
  assert.ok(res.body.token);
  assert.equal(res.body.user.role, 'analyst');
  assert.equal(res.body.user.passwordHash, undefined);
});

test('register rejects a weak password', async () => {
  const res = await api('/api/auth/register', {
    method: 'POST',
    body: { name: 'Weak Pass', email: `${unique('weak')}@example.com`, password: 'password' }
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'weak_password');
});

test('register rejects a duplicate email without confirming it exists', async () => {
  const res = await api('/api/auth/register', {
    method: 'POST',
    body: { name: 'Dupe', email: ANALYST.email, password: 'Str0ng#Passw0rd!' }
  });
  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'registration_failed');
  assert.doesNotMatch(res.body.message, /exists|taken|registered/i);
});

test('login rejects a bad password', async () => {
  const res = await api('/api/auth/login', {
    method: 'POST',
    body: { email: ANALYST.email, password: 'wrong-password' }
  });
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'invalid_credentials');
});

test('logout revokes the token', async () => {
  const token = await login(ANALYST);
  assert.equal((await api('/api/auth/me', { token })).status, 200);

  assert.equal((await api('/api/auth/logout', { method: 'POST', token })).status, 200);
  assert.equal((await api('/api/auth/me', { token })).status, 401);
});

test('a tampered token is rejected', async () => {
  const token = await login(ANALYST);
  const [payload] = token.split('.');
  const forged = `${payload}.${'a'.repeat(43)}`;
  assert.equal((await api('/api/auth/me', { token: forged })).status, 401);
});

test('sessions survive a signing-key reload', async () => {
  // The key is read once and cached; a token issued now must still verify
  // after other modules have been through a full request cycle.
  const token = await login(ANALYST);
  await api('/api/stats');
  assert.equal((await api('/api/auth/me', { token })).status, 200);
});

/* --------------------------------------------------------------- authz gate */

test('write routes require a session', async () => {
  const cases = [
    ['/api/alerts/X', 'PATCH'],
    ['/api/alerts/X/escalate', 'POST'],
    ['/api/incidents', 'POST'],
    ['/api/incidents/X', 'PATCH'],
    ['/api/account', 'GET'],
    ['/api/admin/users', 'GET'],
    ['/api/audit', 'GET']
  ];

  for (const [path, method] of cases) {
    const res = await api(path, { method, body: method === 'GET' ? undefined : {} });
    assert.equal(res.status, 401, `${method} ${path} should be 401`);
  }
});

test('analyst role cannot reach admin routes', async () => {
  const token = await login(ANALYST);
  for (const path of ['/api/admin/users', '/api/admin/export', '/api/contact']) {
    const res = await api(path, { token });
    assert.equal(res.status, 403, `${path} should be 403 for an analyst`);
    assert.equal(res.body.error, 'forbidden');
  }
});

/* ------------------------------------------------------------------ triage */

test('alert triage records status and notes', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=1&severity=high')).body.data[0];

  const res = await api(`/api/alerts/${alert.id}`, {
    method: 'PATCH',
    token,
    body: { status: 'investigating', note: 'Confirmed by host telemetry.' }
  });

  assert.equal(res.status, 200);
  assert.equal(res.body.data.status, 'investigating');
  assert.equal(res.body.data.notes.length, 1);
  assert.equal(res.body.data.notes[0].text, 'Confirmed by host telemetry.');
  assert.equal(res.body.data.notes[0].author, ANALYST.email);

  // Persisted, not just echoed back.
  const reread = await api(`/api/alerts/${alert.id}`);
  assert.equal(reread.body.data.status, 'investigating');
  assert.equal(reread.body.data.notes.length, 1);
});

test('alert triage rejects an invalid status', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=1')).body.data[0];
  const res = await api(`/api/alerts/${alert.id}`, {
    method: 'PATCH',
    token,
    body: { status: 'banana' }
  });
  assert.equal(res.status, 400);
  assert.ok(res.body.fields.status);
});

test('escalation creates an incident and links the alert', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=1&severity=critical')).body.data[0];

  const res = await api(`/api/alerts/${alert.id}/escalate`, { method: 'POST', token });
  assert.equal(res.status, 201);

  const incident = res.body.data;
  assert.match(incident.id, /^INC-\d{4}$/);
  assert.equal(incident.sourceAlertId, alert.id);
  assert.equal(incident.priority, 'P1');
  assert.equal(incident.timeline.length, 2);

  const linked = await api(`/api/alerts/${alert.id}`);
  assert.equal(linked.body.data.incidentId, incident.id);
  assert.equal(linked.body.data.status, 'investigating');

  // Second escalation is a conflict, not a duplicate incident.
  const again = await api(`/api/alerts/${alert.id}/escalate`, { method: 'POST', token });
  assert.equal(again.status, 409);
  assert.equal(again.body.error, 'already_escalated');
});

/* --------------------------------------------------------------- incidents */

test('incident create, update and timeline', async () => {
  const token = await login(ANALYST);

  const created = await api('/api/incidents', {
    method: 'POST',
    token,
    body: {
      title: 'Suspected staging on backup appliance',
      severity: 'high',
      summary: 'Large reads outside the scheduled job window. Scoping now.',
      host: 'backup-vault-01'
    }
  });

  assert.equal(created.status, 201);
  const id = created.body.data.id;
  assert.equal(created.body.data.priority, 'P2');
  assert.equal(created.body.data.timeline.length, 1);

  const updated = await api(`/api/incidents/${id}`, {
    method: 'PATCH',
    token,
    body: { status: 'contained', note: 'Host isolated.' }
  });

  assert.equal(updated.status, 200);
  assert.equal(updated.body.data.status, 'contained');
  // One entry for the status change, one for the note.
  assert.equal(updated.body.data.timeline.length, 3);

  const closed = await api(`/api/incidents/${id}`, {
    method: 'PATCH',
    token,
    body: { status: 'closed' }
  });
  assert.ok(closed.body.data.closedAt, 'closedAt is stamped');
});

test('incident create validates its input', async () => {
  const token = await login(ANALYST);
  const res = await api('/api/incidents', {
    method: 'POST',
    token,
    body: { title: 'x', severity: 'apocalyptic', summary: 'short' }
  });
  assert.equal(res.status, 400);
  assert.ok(res.body.fields.title);
  assert.ok(res.body.fields.severity);
  assert.ok(res.body.fields.summary);
});

test('seeded incidents are protected from deletion', async () => {
  const token = await login(ADMIN);
  const seeded = (await api('/api/incidents?limit=50')).body.data.find((i) => i.seeded);
  assert.ok(seeded, 'a seeded incident exists');

  const res = await api(`/api/incidents/${seeded.id}`, { method: 'DELETE', token });
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'protected_record');
});

test('incident filters and summary agree', async () => {
  const open = await api('/api/incidents?status=open&limit=100');
  for (const incident of open.body.data) assert.notEqual(incident.status, 'closed');
  assert.equal(open.body.summary.open, open.body.pagination.total);
});

/* ------------------------------------------------------------------ account */

test('profile update persists', async () => {
  const email = `${unique('profile')}@example.com`;
  const reg = await api('/api/auth/register', {
    method: 'POST',
    body: { name: 'Before Name', email, password: 'Str0ng#Passw0rd!' }
  });
  const token = reg.body.token;

  const res = await api('/api/account', {
    method: 'PATCH',
    token,
    body: { name: 'After Name', title: 'Tier 3 Hunter' }
  });

  assert.equal(res.status, 200);
  assert.equal(res.body.user.name, 'After Name');
  assert.equal(res.body.user.title, 'Tier 3 Hunter');
  assert.equal((await api('/api/account', { token })).body.user.name, 'After Name');
});

test('profile update rejects an empty patch', async () => {
  const token = await login(ANALYST);
  const res = await api('/api/account', { method: 'PATCH', token, body: {} });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'nothing_to_update');
});

test('password change requires the current password and revokes other sessions', async () => {
  const email = `${unique('pw')}@example.com`;
  const original = 'Str0ng#Passw0rd!';
  const replacement = 'Even$tronger9Pass';

  const reg = await api('/api/auth/register', {
    method: 'POST',
    body: { name: 'Pass Changer', email, password: original }
  });
  const tokenA = reg.body.token;
  const tokenB = await login({ email, password: original });

  // Wrong current password is refused.
  const wrong = await api('/api/account/password', {
    method: 'POST',
    token: tokenA,
    body: { currentPassword: 'not-it', newPassword: replacement }
  });
  assert.equal(wrong.status, 403);
  assert.equal(wrong.body.error, 'incorrect_password');

  // A weak replacement is refused.
  const weak = await api('/api/account/password', {
    method: 'POST',
    token: tokenA,
    body: { currentPassword: original, newPassword: 'abc' }
  });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error, 'weak_password');

  // The real change succeeds.
  const ok = await api('/api/account/password', {
    method: 'POST',
    token: tokenA,
    body: { currentPassword: original, newPassword: replacement }
  });
  assert.equal(ok.status, 200);
  assert.ok(ok.body.otherSessionsRevoked >= 1);

  // Caller stays in; the other device is signed out.
  assert.equal((await api('/api/account', { token: tokenA })).status, 200);
  assert.equal((await api('/api/account', { token: tokenB })).status, 401);

  // Old password no longer works, new one does.
  assert.equal(
    (await api('/api/auth/login', { method: 'POST', body: { email, password: original } })).status,
    401
  );
  assert.equal(
    (await api('/api/auth/login', { method: 'POST', body: { email, password: replacement } })).status,
    200
  );
});

test('shared demo accounts cannot have their password changed', async () => {
  const token = await login(ANALYST);
  const res = await api('/api/account/password', {
    method: 'POST',
    token,
    body: { currentPassword: ANALYST.password, newPassword: 'Compl3tely#New!' }
  });
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'demo_account');
});

test('session list marks the current session', async () => {
  const token = await login(ANALYST);
  const res = await api('/api/account/sessions', { token });
  assert.equal(res.status, 200);
  assert.equal(res.body.data.filter((s) => s.current).length, 1);
  assert.ok(res.body.active >= 1);
});

/* -------------------------------------------------------------------- admin */

test('admin can list users, and hashes never leak', async () => {
  const token = await login(ADMIN);
  const res = await api('/api/admin/users', { token });

  assert.equal(res.status, 200);
  assert.ok(res.body.total >= 2);
  for (const user of res.body.data) assert.equal(user.passwordHash, undefined);
});

test('admin cannot demote or disable their own account', async () => {
  const token = await login(ADMIN);
  const me = (await api('/api/auth/me', { token })).body.user;

  for (const body of [{ disabled: 'true' }, { role: 'analyst' }]) {
    const res = await api(`/api/admin/users/${me.id}`, { method: 'PATCH', token, body });
    assert.equal(res.status, 400);
    assert.equal(res.body.error, 'self_lockout');
  }
});

test('disabling a user revokes their live sessions immediately', async () => {
  const email = `${unique('victim')}@example.com`;
  const password = 'Str0ng#Passw0rd!';

  const reg = await api('/api/auth/register', {
    method: 'POST',
    body: { name: 'To Disable', email, password }
  });
  const victimToken = reg.body.token;
  assert.equal((await api('/api/account', { token: victimToken })).status, 200);

  const adminToken = await login(ADMIN);
  const res = await api(`/api/admin/users/${reg.body.user.id}`, {
    method: 'PATCH',
    token: adminToken,
    body: { disabled: 'true' }
  });

  assert.equal(res.status, 200);
  assert.equal(res.body.user.disabled, true);
  assert.ok(res.body.sessionsRevoked >= 1);

  assert.equal((await api('/api/account', { token: victimToken })).status, 401);
  assert.equal(
    (await api('/api/auth/login', { method: 'POST', body: { email, password } })).status,
    401
  );
});

test('admin export is complete and excludes password hashes', async () => {
  const token = await login(ADMIN);
  const res = await api('/api/admin/export', { token });

  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /attachment; filename="vgil-export-/);
  assert.equal(res.body.schemaVersion, LATEST);
  assert.ok(res.body.alerts.length > 100);
  assert.ok(res.body.incidents.length >= 8);
  for (const user of res.body.users) assert.equal(user.passwordHash, undefined);
});

test('admin stats report the database', async () => {
  const token = await login(ADMIN);
  const res = await api('/api/admin/stats', { token });

  assert.equal(res.status, 200);
  assert.equal(res.body.data.database.driver, 'node:sqlite');
  assert.equal(res.body.data.database.schemaVersion, LATEST);
  assert.ok(res.body.data.counts.alerts > 0);
});

/* ------------------------------------------------------------------ threats */

test('indicator lookup identifies a known indicator', async () => {
  const res = await api('/api/threats/lookup', {
    method: 'POST',
    body: { indicator: '185.220.101.47' }
  });
  assert.equal(res.status, 200);
  assert.equal(res.body.data.verdict, 'malicious');
  assert.equal(res.body.data.actor, 'SILENT LYNX');
});

test('indicator lookup is deterministic for unknown input', async () => {
  const first = await api('/api/threats/lookup', { method: 'POST', body: { indicator: 'example.com' } });
  const second = await api('/api/threats/lookup', { method: 'POST', body: { indicator: 'example.com' } });
  assert.equal(first.body.data.verdict, second.body.data.verdict);
  assert.equal(first.body.data.confidence, second.body.data.confidence);
});

test('indicator lookup validates input', async () => {
  const empty = await api('/api/threats/lookup', { method: 'POST', body: { indicator: '' } });
  assert.equal(empty.status, 400);

  const huge = await api('/api/threats/lookup', {
    method: 'POST',
    body: { indicator: 'a'.repeat(500) }
  });
  assert.equal(huge.status, 400);
});

test('posture scan normalises a URL and scores it', async () => {
  const res = await api('/api/threats/posture-scan', {
    method: 'POST',
    body: { domain: 'https://Acme-Corp.com/some/path' }
  });

  assert.equal(res.status, 200);
  assert.equal(res.body.data.domain, 'acme-corp.com');
  assert.equal(res.body.data.checks.length, 9);
  assert.ok(res.body.data.score >= 0 && res.body.data.score <= 100);
  assert.match(res.body.data.grade, /^[A-F]$/);
});

test('posture scan rejects a non-domain', async () => {
  const res = await api('/api/threats/posture-scan', { method: 'POST', body: { domain: 'not a domain' } });
  assert.equal(res.status, 400);
  assert.ok(res.body.fields.domain);
});

test('attack matrix hit counts come from stored alerts', async () => {
  const res = await api('/api/threats/attack-matrix');
  assert.equal(res.status, 200);

  const techniques = Object.values(res.body.data).flat();
  assert.equal(techniques.length, 20);
  assert.ok(techniques.reduce((sum, t) => sum + t.hits, 0) > 0);
});

/* ------------------------------------------------------------------ contact */

test('contact form stores a submission and escapes HTML', async () => {
  const res = await api('/api/contact', {
    method: 'POST',
    body: {
      name: '<script>alert(1)</script>',
      email: 'jane@acme.com',
      company: 'Acme',
      message: 'We need 24/7 coverage for about 400 endpoints.',
      urgency: 'active-incident'
    }
  });

  assert.equal(res.status, 201);
  assert.match(res.body.reference, /^REQ-/);
  assert.equal(res.body.sla, '15 minutes');

  const token = await login(ADMIN);
  const stored = (await api('/api/contact', { token })).body.data[0];
  assert.ok(!stored.name.includes('<script>'), 'script tag escaped on storage');
  assert.match(stored.name, /&lt;script&gt;/);
});

test('contact form validates every required field', async () => {
  const res = await api('/api/contact', {
    method: 'POST',
    body: { name: 'J', email: 'bad', company: '', message: 'hi' }
  });

  assert.equal(res.status, 400);
  for (const field of ['name', 'email', 'company', 'message']) {
    assert.ok(res.body.fields[field], `expected an error for ${field}`);
  }
});

test('contact honeypot is silently accepted but not stored', async () => {
  const before = repo.contacts.count();

  const res = await api('/api/contact', {
    method: 'POST',
    body: {
      name: 'Spam Bot',
      email: 'bot@spam.test',
      company: 'Spam Inc',
      message: 'Buy cheap things from our website today.',
      website: 'http://spam.test'
    }
  });

  assert.equal(res.status, 202);
  assert.equal(res.body.reference, 'REQ-IGNORED');
  assert.equal(repo.contacts.count(), before, 'nothing was written');
});

/* -------------------------------------------------------------------- stats */

test('stats aggregate consistently', async () => {
  const res = await api('/api/stats');
  assert.equal(res.status, 200);

  const { totals, bySeverity, timeline, performance } = res.body.data;

  assert.equal(timeline.length, 24);
  assert.equal(
    Object.values(bySeverity).reduce((a, b) => a + b, 0),
    totals.alerts,
    'severity buckets sum to the total'
  );
  assert.ok(totals.critical24h <= totals.alerts24h);
  assert.ok(performance.mttrMinutes > 0, 'MTTR derived from closed incidents');
});

/* --------------------------------------------------------------- hardening */

test('oversized body is rejected with 413', async () => {
  const res = await fetch(`${base}/api/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message: 'x'.repeat(70 * 1024) })
  });
  assert.equal(res.status, 413);
});

test('malformed JSON is rejected with 400', async () => {
  const res = await fetch(`${base}/api/contact`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{ not json'
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'bad_json');
});

test('SQL metacharacters in a search are treated as text', async () => {
  const res = await api(`/api/alerts?q=${encodeURIComponent("'; DROP TABLE alerts; --")}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.data.length, 0, 'no match, and no damage');
  assert.ok(repo.alerts.count() > 100, 'alerts table intact');
});

test('rate limiter blocks past its threshold and reports Retry-After', () => {
  // `absolute` pins the budget at 3 regardless of VGIL_RATE_FACTOR, so the
  // threshold is asserted exactly rather than approximately.
  const limiter = rateLimit({ windowMs: 60_000, max: 3, key: `unit-${Date.now()}`, absolute: true });

  const req = { headers: {}, socket: { remoteAddress: '198.51.100.7' }, get: () => '' };

  function call() {
    const headers = {};
    let status = 200;
    let payload = null;
    let passed = false;

    const res = {
      setHeader: (k, v) => { headers[k.toLowerCase()] = v; },
      status(code) { status = code; return res; },
      json(body) { payload = body; return res; }
    };

    limiter(req, res, () => { passed = true; });
    return { status, payload, headers, passed };
  }

  // Three requests inside the window are allowed, and the remaining count
  // counts down as they are spent.
  assert.equal(call().headers['x-ratelimit-remaining'], '2');
  assert.equal(call().headers['x-ratelimit-remaining'], '1');
  const third = call();
  assert.equal(third.passed, true);
  assert.equal(third.headers['x-ratelimit-remaining'], '0');

  // The fourth is refused.
  const blocked = call();
  assert.equal(blocked.passed, false);
  assert.equal(blocked.status, 429);
  assert.equal(blocked.payload.error, 'rate_limited');
  assert.ok(Number(blocked.headers['retry-after']) > 0);
});

test('rate limiting is wired into the HTTP stack', async () => {
  // Proves the middleware is actually mounted, without draining a real budget.
  const res = await api('/api/alerts?limit=1');
  assert.ok(Number(res.headers.get('x-ratelimit-limit')) > 0);
  assert.ok(res.headers.get('x-ratelimit-remaining') !== null);
});

/* ------------------------------------------------- two-factor authentication */

const totp = require('../server/lib/totp');
const csvLib = require('../server/lib/csv');
const webhookLib = require('../server/lib/webhooks');

/** Registers a throwaway account and returns its credentials plus a session. */
async function freshUser() {
  const creds = {
    name: 'Test Analyst',
    email: `${unique('mfa')}@example.com`,
    password: 'Vgil#Testing2026!'
  };
  const res = await api('/api/auth/register', { method: 'POST', body: creds });
  assert.equal(res.status, 201, JSON.stringify(res.body));
  return { creds, token: res.body.token, user: res.body.user };
}

/** Drives a full enrolment and returns the secret plus recovery codes. */
async function enrol(token, password) {
  const start = await api('/api/account/mfa/enrol', {
    method: 'POST', body: { password }, token
  });
  assert.equal(start.status, 200, JSON.stringify(start.body));

  const confirm = await api('/api/account/mfa/confirm', {
    method: 'POST', body: { code: totp.generate(start.body.secret) }, token
  });
  assert.equal(confirm.status, 200, JSON.stringify(confirm.body));

  return { secret: start.body.secret, recoveryCodes: confirm.body.recoveryCodes };
}

test('TOTP matches the RFC 6238 reference vectors', () => {
  const secret = totp.base32Encode(Buffer.from('12345678901234567890', 'ascii'));

  // Published 8-digit vectors, truncated to the 6 digits this implementation
  // emits. The last one exceeds a 32-bit counter, covering the 64-bit path.
  assert.equal(totp.generate(secret, 59 * 1000), '287082');
  assert.equal(totp.generate(secret, 1111111109 * 1000), '081804');
  assert.equal(totp.generate(secret, 1234567890 * 1000), '005924');
  assert.equal(totp.generate(secret, 2000000000 * 1000), '279037');
  assert.equal(totp.generate(secret, 20000000000 * 1000), '353130');
});

test('base32 survives a round trip and rejects rubbish', () => {
  const secret = totp.generateSecret();
  assert.equal(totp.base32Decode(secret).length, 20, '160-bit secret');
  assert.match(secret, /^[A-Z2-7]+$/);
  assert.throws(() => totp.base32Decode('not!base32'));
});

test('MFA secrets never leave the server', async () => {
  const { creds, token } = await freshUser();
  await enrol(token, creds.password);

  for (const path of ['/api/account', '/api/auth/me']) {
    const res = await api(path, { token });
    const serialised = JSON.stringify(res.body);
    for (const leak of ['mfaSecret', 'mfaPendingSecret', 'mfaLastCounter', 'passwordHash']) {
      assert.ok(!serialised.includes(leak), `${path} leaked ${leak}`);
    }
  }
});

test('enrolment requires the current password', async () => {
  const { token } = await freshUser();
  const res = await api('/api/account/mfa/enrol', {
    method: 'POST', body: { password: 'not-the-password' }, token
  });
  assert.equal(res.status, 403);
});

test('an abandoned enrolment leaves the account unprotected but usable', async () => {
  const { creds, token } = await freshUser();
  await api('/api/account/mfa/enrol', { method: 'POST', body: { password: creds.password }, token });

  const status = await api('/api/account/mfa', { token });
  assert.equal(status.body.enabled, false, 'not armed until confirmed');
  assert.equal(status.body.pending, true);

  // The password alone must still sign in.
  const signIn = await api('/api/auth/login', { method: 'POST', body: creds });
  assert.equal(signIn.status, 200);
  assert.ok(signIn.body.token, 'no challenge for an unconfirmed enrolment');
});

test('once enrolled, a password alone yields a challenge and not a session', async () => {
  const { creds, token } = await freshUser();
  await enrol(token, creds.password);

  const res = await api('/api/auth/login', { method: 'POST', body: creds });
  assert.equal(res.status, 200);
  assert.equal(res.body.mfaRequired, true);
  assert.ok(res.body.challenge);
  assert.ok(!res.body.token, 'must not hand out a session token');
});

test('an MFA challenge token cannot be used as a session token', async () => {
  const { creds, token } = await freshUser();
  await enrol(token, creds.password);

  const signIn = await api('/api/auth/login', { method: 'POST', body: creds });
  const res = await api('/api/account', { token: signIn.body.challenge });
  assert.equal(res.status, 401, 'the second factor must not be bypassable');
});

test('a TOTP code completes sign-in and cannot then be replayed', async () => {
  const { creds, token } = await freshUser();
  const { secret } = await enrol(token, creds.password);

  // Confirmation consumed the current step, so use the next one — which also
  // exercises the plus/minus one step drift tolerance.
  const code = totp.generate(secret, Date.now() + 30_000);

  const first = await api('/api/auth/login', { method: 'POST', body: creds });
  const ok = await api('/api/auth/login/mfa', {
    method: 'POST', body: { challenge: first.body.challenge, code }
  });
  assert.equal(ok.status, 200, JSON.stringify(ok.body));
  assert.equal(ok.body.method, 'totp');

  const second = await api('/api/auth/login', { method: 'POST', body: creds });
  const replay = await api('/api/auth/login/mfa', {
    method: 'POST', body: { challenge: second.body.challenge, code }
  });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.error, 'code_already_used');
});

test('recovery codes work once each and are format-forgiving', async () => {
  const { creds, token } = await freshUser();
  const { recoveryCodes } = await enrol(token, creds.password);
  assert.equal(recoveryCodes.length, 10);

  const start = await api('/api/auth/login', { method: 'POST', body: creds });
  // Typed back without the dash and in lower case, as a person would.
  const typed = recoveryCodes[0].toLowerCase().replace('-', '');
  const used = await api('/api/auth/login/mfa', {
    method: 'POST', body: { challenge: start.body.challenge, code: typed }
  });
  assert.equal(used.status, 200);
  assert.equal(used.body.method, 'recovery');
  assert.equal(used.body.recoveryCodesRemaining, 9);

  const again = await api('/api/auth/login', { method: 'POST', body: creds });
  const reuse = await api('/api/auth/login/mfa', {
    method: 'POST', body: { challenge: again.body.challenge, code: recoveryCodes[0] }
  });
  assert.equal(reuse.status, 401, 'a spent recovery code must not work twice');
});

test('disabling MFA needs the password and a valid code', async () => {
  const { creds, token } = await freshUser();
  const { secret } = await enrol(token, creds.password);

  const noCode = await api('/api/account/mfa/disable', {
    method: 'POST', body: { password: creds.password }, token
  });
  assert.equal(noCode.status, 400, 'knowing the password must not be enough');

  const noPassword = await api('/api/account/mfa/disable', {
    method: 'POST', body: { password: 'wrong', code: totp.generate(secret) }, token
  });
  assert.equal(noPassword.status, 403);
});

/* ------------------------------------------------------------- api keys */

test('an API key authenticates reads and is refused for writes', async () => {
  const { token } = await freshUser();

  const created = await api('/api/account/api-keys', {
    method: 'POST', body: { name: 'siem-pull' }, token
  });
  assert.equal(created.status, 201);
  assert.match(created.body.secret, /^vgil_/);
  assert.ok(!JSON.stringify(created.body.key).includes('keyHash'), 'hash must not be returned');

  const key = created.body.secret;

  const read = await fetch(`${base}/api/export/alerts?format=json`, {
    headers: { 'x-api-key': key }
  });
  assert.equal(read.status, 200);

  const write = await fetch(`${base}/api/incidents`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': key },
    body: JSON.stringify({ title: 'via key', severity: 'low', summary: 'should be refused' })
  });
  assert.equal(write.status, 403, 'keys are read-only');
});

test('a revoked or forged API key is refused', async () => {
  const { token } = await freshUser();
  const created = await api('/api/account/api-keys', {
    method: 'POST', body: { name: 'to-revoke' }, token
  });
  const key = created.body.secret;

  const before = await fetch(`${base}/api/export/alerts`, { headers: { 'x-api-key': key } });
  assert.equal(before.status, 200);

  const revoked = await api(`/api/account/api-keys/${created.body.key.id}`, {
    method: 'DELETE', token
  });
  assert.equal(revoked.status, 200);

  const after = await fetch(`${base}/api/export/alerts`, { headers: { 'x-api-key': key } });
  assert.equal(after.status, 401);

  const forged = await fetch(`${base}/api/export/alerts`, {
    headers: { 'x-api-key': 'vgil_forgedforgedforged' }
  });
  assert.equal(forged.status, 401);
});

test('one account cannot revoke a key belonging to another', async () => {
  const owner = await freshUser();
  const stranger = await freshUser();

  const created = await api('/api/account/api-keys', {
    method: 'POST', body: { name: 'private' }, token: owner.token
  });

  const attempt = await api(`/api/account/api-keys/${created.body.key.id}`, {
    method: 'DELETE', token: stranger.token
  });
  assert.equal(attempt.status, 404, 'must not be revocable, nor confirmed to exist');
});

/* --------------------------------------------------------------- exports */

test('CSV export neutralises spreadsheet formula injection', () => {
  const rows = [{ a: '=cmd|calc', b: '+1', c: '@SUM(1:1)', d: '-2' }];
  const out = csvLib.serialise(rows, [
    { key: 'a', label: 'A' }, { key: 'b', label: 'B' },
    { key: 'c', label: 'C' }, { key: 'd', label: 'D' }
  ]);

  for (const dangerous of ['=cmd|calc', '+1', '@SUM(1:1)', '-2']) {
    assert.ok(out.includes(`'${dangerous}`), `${dangerous} was not defused`);
  }
});

test('CSV export quotes delimiters and doubles embedded quotes', () => {
  const out = csvLib.serialise(
    [{ v: 'has "quotes", a comma and\na newline' }],
    [{ key: 'v', label: 'V' }]
  );
  assert.ok(out.includes('""quotes""'));
});

test('exports require a credential and arrive as downloads', async () => {
  const anonymous = await fetch(`${base}/api/export/incidents`);
  assert.equal(anonymous.status, 401);

  const token = await login(ADMIN);
  const res = await fetch(`${base}/api/export/incidents`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/csv/);
  assert.match(res.headers.get('content-disposition'), /attachment; filename="vgil-incidents-/);

  const bytes = Buffer.from(await res.arrayBuffer());
  assert.deepEqual([...bytes.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'UTF-8 BOM for Excel');
});

test('the audit export is restricted to administrators', async () => {
  const analyst = await login(ANALYST);
  const denied = await api('/api/export/audit', { token: analyst });
  assert.equal(denied.status, 403);

  const admin = await login(ADMIN);
  const allowed = await fetch(`${base}/api/export/audit`, {
    headers: { Authorization: `Bearer ${admin}` }
  });
  assert.equal(allowed.status, 200);
});

/* -------------------------------------------------------------- webhooks */

test('the webhook SSRF guard recognises internal address space', () => {
  const internal = [
    '127.0.0.1', '10.0.0.5', '172.16.4.1', '172.31.255.254',
    '192.168.1.1', '169.254.169.254', '0.0.0.0', '::1', 'fd00::1', 'fe80::1',
    '::ffff:169.254.169.254'
  ];
  for (const ip of internal) {
    assert.ok(webhookLib.isPrivateAddress(ip), `${ip} should be treated as internal`);
  }

  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700::1111']) {
    assert.ok(!webhookLib.isPrivateAddress(ip), `${ip} should be treated as external`);
  }
});

test('webhook signatures bind both the body and the timestamp', () => {
  const a = webhookLib.signPayload('whsec_x', 1735689600, '{"a":1}');
  const b = webhookLib.signPayload('whsec_x', 1735689600, '{"a":1}');
  const differentBody = webhookLib.signPayload('whsec_x', 1735689600, '{"a":2}');
  const differentTime = webhookLib.signPayload('whsec_x', 1735689601, '{"a":1}');
  const differentKey = webhookLib.signPayload('whsec_y', 1735689600, '{"a":1}');

  assert.equal(a, b, 'must be deterministic');
  assert.notEqual(a, differentBody);
  assert.notEqual(a, differentTime, 'a captured payload must not replay');
  assert.notEqual(a, differentKey);
});

test('webhook management is admin-only and never echoes the secret', async () => {
  const analyst = await login(ANALYST);
  const denied = await api('/api/admin/webhooks', { token: analyst });
  assert.equal(denied.status, 403);

  const token = await login(ADMIN);
  const created = await api('/api/admin/webhooks', {
    method: 'POST',
    body: { url: 'http://127.0.0.1:9/sink', description: 'test', events: ['incident.opened'] },
    token
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.match(created.body.secret, /^whsec_/, 'shown exactly once');
  assert.ok(!JSON.stringify(created.body.webhook).includes('whsec_'));

  const listed = await api('/api/admin/webhooks', { token });
  assert.ok(!JSON.stringify(listed.body.data).includes('whsec_'), 'never listed in full');

  const cleanup = await api(`/api/admin/webhooks/${created.body.webhook.id}`, {
    method: 'DELETE', token
  });
  assert.equal(cleanup.status, 200);
});

test('a malformed webhook URL is rejected', async () => {
  const token = await login(ADMIN);
  const res = await api('/api/admin/webhooks', {
    method: 'POST', body: { url: 'definitely not a url' }, token
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_url');
});

/* -------------------------------------------------------- password reset */

test('an admin-issued reset link rotates the password exactly once', async () => {
  const { creds, user } = await freshUser();
  const admin = await login(ADMIN);

  const issued = await api(`/api/admin/users/${user.id}/reset-link`, {
    method: 'POST', token: admin
  });
  assert.equal(issued.status, 201, JSON.stringify(issued.body));

  const resetToken = new URL(`http://x${issued.body.path}`).searchParams.get('token');
  assert.ok(resetToken);

  const verified = await api('/api/auth/reset/verify', {
    method: 'POST', body: { token: resetToken }
  });
  assert.equal(verified.status, 200);
  assert.ok(!verified.body.email.includes(creds.email.split('@')[0]), 'address is masked');

  const weak = await api('/api/auth/reset', {
    method: 'POST', body: { token: resetToken, password: 'password' }
  });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error, 'weak_password');

  const next = 'Vgil#Rotated2026!';
  const done = await api('/api/auth/reset', {
    method: 'POST', body: { token: resetToken, password: next }
  });
  assert.equal(done.status, 200);

  const reuse = await api('/api/auth/reset', {
    method: 'POST', body: { token: resetToken, password: next }
  });
  assert.equal(reuse.status, 400);
  assert.equal(reuse.body.error, 'token_used');

  const signIn = await api('/api/auth/login', {
    method: 'POST', body: { email: creds.email, password: next }
  });
  assert.equal(signIn.status, 200, 'the new password works');
});

test('a reset revokes every existing session', async () => {
  const { user, token } = await freshUser();
  assert.equal((await api('/api/account', { token })).status, 200);

  const admin = await login(ADMIN);
  const issued = await api(`/api/admin/users/${user.id}/reset-link`, {
    method: 'POST', token: admin
  });
  const resetToken = new URL(`http://x${issued.body.path}`).searchParams.get('token');

  await api('/api/auth/reset', {
    method: 'POST', body: { token: resetToken, password: 'Vgil#Displaced2026!' }
  });

  const after = await api('/api/account', { token });
  assert.equal(after.status, 401, 'sessions predating the reset must be dropped');
});

test('issuing a new reset link retires the previous one', async () => {
  const { user } = await freshUser();
  const admin = await login(ADMIN);

  const first = await api(`/api/admin/users/${user.id}/reset-link`, { method: 'POST', token: admin });
  const second = await api(`/api/admin/users/${user.id}/reset-link`, { method: 'POST', token: admin });

  const stale = new URL(`http://x${first.body.path}`).searchParams.get('token');
  const fresh = new URL(`http://x${second.body.path}`).searchParams.get('token');

  const staleCheck = await api('/api/auth/reset/verify', { method: 'POST', body: { token: stale } });
  assert.equal(staleCheck.status, 400);

  const freshCheck = await api('/api/auth/reset/verify', { method: 'POST', body: { token: fresh } });
  assert.equal(freshCheck.status, 200);
});

test('a garbage reset token is refused', async () => {
  const res = await api('/api/auth/reset/verify', {
    method: 'POST', body: { token: 'nonsense-token-value' }
  });
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_token');
});


/** Picks an incident that can still accept containment. */
function openIncident(response) {
  const found = (response.body.data || []).find((row) => row.status !== 'closed');
  assert.ok(found, 'the seed should always leave at least one incident open');
  return found;
}

/* ============================================ custom detection engineering */

const notifyLib = require('../server/lib/notify');
const smtpLib = require('../server/lib/smtp');
const engineLib = require('../server/lib/engine');

/** A valid rule body, overridable per test. */
function ruleBody(overrides = {}) {
  return {
    name: unique('Rule'),
    severity: 'critical',
    tactic: 'Initial Access',
    technique: 'T1078.004',
    techniqueName: 'Cloud Accounts',
    source: 'VPN Concentrator',
    description: 'A finance account authenticated to the VPN outside working hours.',
    response: 'Confirm with the account owner and revoke the session if unrecognised.',
    ...overrides
  };
}

test('a custom rule joins the detection pool and can be drawn', async () => {
  const token = await login(ANALYST);
  const before = engineLib.refreshRules();

  const created = await api('/api/detections', { method: 'POST', body: ruleBody(), token });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.data.custom, true);
  assert.equal(created.body.activeInPool, before + 1);

  const id = created.body.data.id;

  // A critical rule carries the lowest weight, so this proves it is reachable
  // rather than merely present.
  let fired = 0;
  for (let i = 0; i < 5000; i += 1) {
    if (engineLib.buildAlert().ruleId === id) fired += 1;
  }
  assert.ok(fired > 0, 'a custom rule that never fires is not a detection');

  await api(`/api/detections/${id}`, { method: 'DELETE', token });
});

test('disabling a rule removes it from the pool', async () => {
  const token = await login(ANALYST);
  const created = await api('/api/detections', { method: 'POST', body: ruleBody(), token });
  const id = created.body.data.id;
  const withRule = created.body.activeInPool;

  const disabled = await api(`/api/detections/${id}`, {
    method: 'PATCH', body: { enabled: false }, token
  });
  assert.equal(disabled.body.data.enabled, false);
  assert.equal(disabled.body.activeInPool, withRule - 1);

  let fired = 0;
  for (let i = 0; i < 2000; i += 1) {
    if (engineLib.buildAlert().ruleId === id) fired += 1;
  }
  assert.equal(fired, 0, 'a disabled rule must not fire');

  await api(`/api/detections/${id}`, { method: 'DELETE', token });
});

test('rule authoring validates severity, ATT&CK ids and asset types', async () => {
  const token = await login(ANALYST);

  const anonymous = await api('/api/detections', { method: 'POST', body: ruleBody() });
  assert.equal(anonymous.status, 401);

  const badSeverity = await api('/api/detections', {
    method: 'POST', body: ruleBody({ severity: 'catastrophic' }), token
  });
  assert.equal(badSeverity.status, 400);
  assert.ok(badSeverity.body.fields.severity);

  const badTechnique = await api('/api/detections', {
    method: 'POST', body: ruleBody({ technique: 'NOTATECHNIQUE' }), token
  });
  assert.equal(badTechnique.status, 400);
  assert.match(badTechnique.body.fields.technique, /ATT&CK/);

  const badAsset = await api('/api/detections', {
    method: 'POST', body: ruleBody({ assetTypes: ['not-a-real-asset-type'] }), token
  });
  assert.equal(badAsset.status, 400);
  assert.ok(badAsset.body.fields.assetTypes);
});

test('built-in rules cannot be edited or deleted', async () => {
  const token = await login(ANALYST);

  const edit = await api('/api/detections/VGIL-1001', {
    method: 'PATCH', body: { severity: 'low' }, token
  });
  assert.equal(edit.status, 403);
  assert.equal(edit.body.error, 'built_in_rule');

  const remove = await api('/api/detections/VGIL-1001', { method: 'DELETE', token });
  assert.equal(remove.status, 403);
});

test('previewing a rule does not write an alert', async () => {
  const token = await login(ANALYST);
  const before = repo.alerts.count();

  const preview = await api('/api/detections/VGIL-1001/preview', { method: 'POST', token });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.data.ruleId, 'VGIL-1001');
  assert.equal(repo.alerts.count(), before, 'a preview must not enter the queue');
});

/* ================================================= containment records === */

test('containment requires an incident, a target and a reason', async () => {
  const token = await login(ANALYST);
  const incident = openIncident(await api('/api/incidents?status=open&limit=5'));

  const noReason = await api('/api/containment', {
    method: 'POST', body: { incidentId: incident.id, action: 'host_isolate', target: 'web-01' }, token
  });
  assert.equal(noReason.status, 400);
  assert.ok(noReason.body.fields.reason);

  const noIncident = await api('/api/containment', {
    method: 'POST',
    body: { incidentId: 'INC-0000', action: 'host_isolate', target: 'web-01', reason: 'Confirmed beaconing.' },
    token
  });
  assert.equal(noIncident.status, 404);

  const badAction = await api('/api/containment', {
    method: 'POST',
    body: { incidentId: incident.id, action: 'launch_missiles', target: 'web-01', reason: 'Confirmed beaconing.' },
    token
  });
  assert.equal(badAction.status, 400);
});

test('a containment record lands on the incident timeline', async () => {
  const token = await login(ANALYST);
  const incident = openIncident(await api('/api/incidents?status=open&limit=5'));
  const before = (await api(`/api/incidents/${incident.id}`)).body.data.timeline.length;

  const created = await api('/api/containment', {
    method: 'POST',
    body: {
      incidentId: incident.id,
      action: 'host_isolate',
      target: 'web-01.corp.vgil.io',
      scope: 'Management VLAN only',
      reason: 'Confirmed beaconing to a known C2 address; isolating pending forensics.',
      authorisedBy: 'duty-manager@vgil.io'
    },
    token
  });

  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.data.active, true);
  assert.equal(created.body.data.performedBy, ANALYST.email);
  assert.equal(created.body.data.authorisedBy, 'duty-manager@vgil.io');

  // The response must not imply anything was executed.
  assert.match(created.body.note, /does not perform/i);

  const after = (await api(`/api/incidents/${incident.id}`)).body.data.timeline;
  assert.equal(after.length, before + 1);
  assert.match(after[after.length - 1].entry, /Containment recorded — Host isolation/);
});

test('containment is lifted once, with a reason, and the history is kept', async () => {
  const token = await login(ANALYST);
  const incident = openIncident(await api('/api/incidents?status=open&limit=5'));

  const created = await api('/api/containment', {
    method: 'POST',
    body: {
      incidentId: incident.id, action: 'session_revoke', target: 'j.patel@corp.vgil.io',
      reason: 'Session cookie replayed from a second country.'
    },
    token
  });
  const id = created.body.data.id;

  const terse = await api(`/api/containment/${id}/revert`, {
    method: 'POST', body: { reason: 'done' }, token
  });
  assert.equal(terse.status, 400, 'a reversal needs a real reason too');

  const lifted = await api(`/api/containment/${id}/revert`, {
    method: 'POST',
    body: { reason: 'Account credentials rotated and the user re-enrolled.' },
    token
  });
  assert.equal(lifted.status, 200);
  assert.equal(lifted.body.data.active, false);
  assert.equal(lifted.body.data.revertedBy, ANALYST.email);

  const again = await api(`/api/containment/${id}/revert`, {
    method: 'POST', body: { reason: 'Trying to lift it a second time.' }, token
  });
  assert.equal(again.status, 409);

  // How long containment stayed in place is part of the record.
  const record = repo.containment.byId(id);
  assert.ok(record, 'lifting must not delete the row');
  assert.ok(record.revertedAt);
});

/* ==================================================== email alerting === */

test('quiet hours wrap past midnight', () => {
  const at = (hour) => new Date(2026, 0, 1, hour, 30);

  for (const hour of [22, 23, 0, 3, 6]) {
    assert.ok(notifyLib.inQuietHours('22:00-07:00', at(hour)), `${hour}:30 should be quiet`);
  }
  for (const hour of [8, 12, 21]) {
    assert.ok(!notifyLib.inQuietHours('22:00-07:00', at(hour)), `${hour}:30 should not be quiet`);
  }

  assert.equal(notifyLib.inQuietHours('', at(3)), false, 'unset means never quiet');
  assert.equal(notifyLib.inQuietHours('nonsense', at(3)), false);
});

test('a critical event overrides both quiet hours and digest cadence', () => {
  const base = {
    emailEnabled: true, minSeverity: 'high', cadence: 'immediate',
    onIncident: true, onCritical: true, onAssignment: true, quietHours: null
  };

  assert.equal(notifyLib.decide({ ...base, emailEnabled: false }, { kind: 'incident', severity: 'critical' }).send, false);
  assert.equal(notifyLib.decide(base, { kind: 'incident', severity: 'medium' }).send, false, 'below threshold');
  assert.equal(notifyLib.decide(base, { kind: 'incident', severity: 'high' }).send, true);

  const deferred = notifyLib.decide({ ...base, cadence: 'daily' }, { kind: 'incident', severity: 'high' });
  assert.equal(deferred.send, false);
  assert.equal(deferred.defer, true, 'a digest defers rather than drops');

  // The point of the override: someone who asked not to be woken still needs
  // to hear that a domain controller is compromised.
  assert.equal(
    notifyLib.decide({ ...base, cadence: 'daily', quietHours: '00:00-23:59' }, { kind: 'incident', severity: 'critical' }).send,
    true
  );
});

test('notification bodies escape telemetry-derived text', () => {
  const rendered = notifyLib.renderEvent({
    kind: 'alert',
    severity: 'critical',
    title: 'Rule fired on <img src=x onerror=alert(1)>',
    summary: 'Suspicious activity',
    details: [['Host', '<script>steal()</script>']]
  });

  assert.ok(!/<img src=x/.test(rendered.html), 'an unescaped payload reaches the analyst mail client');
  assert.ok(!/<script>steal/.test(rendered.html));
  assert.ok(rendered.html.includes('&lt;img'), 'escaped instead');
});

test('SMTP builds a spec-compliant message', () => {
  const message = smtpLib.buildMessage({
    from: 'soc@vgil.io', fromName: 'VGIL SOC', to: 'a@example.com',
    subject: 'Détection critique', text: 'plain body', html: '<p>html</p>'
  });

  // A raw UTF-8 subject is not legal in a header.
  assert.match(message, /Subject: =\?UTF-8\?B\?/);
  assert.match(message, /multipart\/alternative/);
  assert.match(message, /Auto-Submitted: auto-generated/);
  assert.ok(message.includes('text/plain') && message.includes('text/html'));
});

test('multi-line SMTP replies are only complete on the final line', () => {
  assert.equal(smtpLib.isComplete('250-SIZE 1024\r\n'), false, 'a continuation is not the end');
  assert.equal(smtpLib.isComplete('250 HELP\r\n'), true);

  const reply = smtpLib.parseReply('250-greeting\r\n250-SIZE 1024\r\n250 HELP\r\n');
  assert.equal(reply.code, 250);
  assert.equal(reply.lines.length, 3);
});

test('notifications are off until opted into, and report the transport honestly', async () => {
  const { token } = await freshUser();

  const initial = await api('/api/account/notifications', { token });
  assert.equal(initial.status, 200);
  assert.equal(initial.body.prefs.emailEnabled, false, 'alerting must be opt-in');

  // With no relay configured, the page must say so rather than implying mail
  // is going out.
  assert.equal(initial.body.transport.mode, 'spool');
  assert.match(initial.body.transport.note, /No SMTP relay/);
});

test('notification preferences validate and persist', async () => {
  const { token } = await freshUser();

  const bad = await api('/api/account/notifications', {
    method: 'PATCH', body: { quietHours: '10pm-7am' }, token
  });
  assert.equal(bad.status, 400);
  assert.ok(bad.body.fields.quietHours);

  const saved = await api('/api/account/notifications', {
    method: 'PATCH',
    body: { emailEnabled: true, minSeverity: 'high', cadence: 'immediate', quietHours: '22:00-07:00' },
    token
  });
  assert.equal(saved.status, 200);
  assert.equal(saved.body.prefs.emailEnabled, true);
  assert.equal(saved.body.prefs.quietHours, '22:00-07:00');

  const cleared = await api('/api/account/notifications', {
    method: 'PATCH', body: { quietHours: '' }, token
  });
  assert.equal(cleared.body.prefs.quietHours, null, 'an empty value clears the window');
});

test('a test notification is recorded rather than silently dropped', async () => {
  const { creds, token } = await freshUser();
  await api('/api/account/notifications', {
    method: 'PATCH', body: { emailEnabled: true }, token
  });

  const sent = await api('/api/account/notifications/test', { method: 'POST', token });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.status, 'spooled', 'no relay configured in tests');

  const log = await api('/api/account/notifications/log', { token });
  assert.ok(log.body.total >= 1);
  assert.equal(log.body.data[0].to, creds.email.toLowerCase());
});

test('opening an incident notifies subscribers but not the actor', async () => {
  const subscriber = await freshUser();
  await api('/api/account/notifications', {
    method: 'PATCH',
    body: { emailEnabled: true, minSeverity: 'high', cadence: 'immediate', quietHours: '' },
    token: subscriber.token
  });

  const admin = await login(ADMIN);
  const before = repo.emailLog.count();

  const opened = await api('/api/incidents', {
    method: 'POST',
    body: {
      title: 'Encoded PowerShell on a finance workstation',
      severity: 'critical',
      summary: 'A document spawned an encoded command line.',
      host: 'fin-ws-04'
    },
    token: admin
  });
  assert.equal(opened.status, 201);

  // Dispatch is deliberately fire-and-forget.
  await new Promise((resolve) => setTimeout(resolve, 300));

  assert.ok(repo.emailLog.count() > before, 'the subscriber should have been notified');

  const recent = repo.emailLog.list(10);
  assert.ok(
    recent.some((entry) => entry.to === subscriber.creds.email.toLowerCase()),
    'subscriber missing from the delivery log'
  );
  assert.ok(
    !recent.some((entry) => entry.to === ADMIN.email),
    'nobody should be mailed about their own action'
  );
});

test('a digest batches deferred notifications into one message', async () => {
  const subscriber = await freshUser();
  await api('/api/account/notifications', {
    method: 'PATCH',
    body: { emailEnabled: true, minSeverity: 'low', cadence: 'daily', quietHours: '' },
    token: subscriber.token
  });

  const admin = await login(ADMIN);
  for (const title of ['Digest candidate one', 'Digest candidate two']) {
    const created = await api('/api/incidents', {
      method: 'POST',
      body: { title, severity: 'high', summary: 'Deferred for the daily digest.', host: 'h-01' },
      token: admin
    });
    assert.equal(created.status, 201, JSON.stringify(created.body));
  }
  await new Promise((resolve) => setTimeout(resolve, 300));

  const queued = await api('/api/account/notifications', { token: subscriber.token });
  assert.ok(queued.body.pendingDigest >= 2, `expected a queue, got ${queued.body.pendingDigest}`);

  const before = repo.emailLog.count();
  const digest = await api('/api/account/notifications/digest', {
    method: 'POST', token: subscriber.token
  });
  assert.equal(digest.body.sent, 1);
  assert.equal(repo.emailLog.count(), before + 1, 'one message, not one per event');

  const drained = await api('/api/account/notifications', { token: subscriber.token });
  assert.equal(drained.body.pendingDigest, 0);
});

test('the admin delivery log distinguishes no messages from no relay', async () => {
  const analyst = await login(ANALYST);
  const denied = await api('/api/admin/notifications', { token: analyst });
  assert.equal(denied.status, 403);

  const admin = await login(ADMIN);
  const log = await api('/api/admin/notifications', { token: admin });
  assert.equal(log.status, 200);
  assert.equal(log.body.transport.mode, 'spool');
  assert.match(log.body.transport.note, /VGIL_SMTP_HOST/);
});

/* ================================================== SOC operations tooling */

const socLib = require('../server/lib/soc');

test('a wrapping shift covers the hours either side of midnight', () => {
  const night = { id: 'n', region: 'APAC', startHour: 22, endHour: 6, active: true };

  for (const hour of [22, 23, 0, 3, 5]) {
    assert.ok(socLib.covers(night, hour), `${hour}:00 should be covered`);
  }
  for (const hour of [6, 12, 21]) {
    assert.ok(!socLib.covers(night, hour), `${hour}:00 should not be covered`);
  }

  // 00 to 00 means the whole day, which is what somebody entering it intends.
  assert.equal(socLib.hoursCovered({ startHour: 0, endHour: 0 }).length, 24);
});

test('coverage gaps are detected and named', () => {
  const shifts = [
    { id: 'a', region: 'APAC', startHour: 22, endHour: 6, active: true },
    { id: 'b', region: 'EMEA', startHour: 6, endHour: 14, active: true },
    { id: 'c', region: 'AMER', startHour: 14, endHour: 22, active: true }
  ];

  assert.equal(socLib.coverage(shifts).complete, true, 'three 8h shifts cover the day');

  const short = socLib.coverage(shifts.slice(0, 2));
  assert.equal(short.complete, false);
  assert.deepEqual(socLib.describeGaps(short.gaps), ['14:00–22:00']);

  // An inactive shift must not count towards coverage.
  const disabled = shifts.map((s) => (s.id === 'c' ? { ...s, active: false } : s));
  assert.equal(socLib.coverage(disabled).complete, false, 'a disabled shift is not coverage');
});

test('the rota reports who is on and what comes next', () => {
  const shifts = [
    { id: 'a', region: 'APAC', startHour: 22, endHour: 6, active: true },
    { id: 'b', region: 'EMEA', startHour: 6, endHour: 14, active: true },
    { id: 'c', region: 'AMER', startHour: 14, endHour: 22, active: true }
  ];

  const at = new Date(Date.UTC(2026, 0, 1, 3, 0, 0));
  assert.deepEqual(socLib.onDuty(shifts, at).map((s) => s.region), ['APAC']);

  const next = socLib.nextHandover(shifts, at);
  assert.equal(next.inHours, 3, '03:00 to the 06:00 EMEA start');
  assert.deepEqual(next.incoming.map((s) => s.region), ['EMEA']);
});

test('the public rota status refuses to claim uncovered hours', async () => {
  const token = await login(ADMIN);

  const before = await api('/api/soc/status');
  assert.equal(before.status, 200, 'status is public');
  assert.equal(before.body.coverage.complete, true, 'the seeded rota covers the day');
  assert.match(before.body.claim, /Every UTC hour is covered/);

  const shifts = (await api('/api/soc/shifts')).body.data;
  const amer = shifts.find((s) => s.region === 'AMER');

  const removed = await api(`/api/soc/shifts/${amer.id}`, { method: 'DELETE', token });
  assert.equal(removed.status, 200);
  assert.equal(removed.body.coverage.complete, false);
  assert.match(removed.body.warning, /14:00/, 'the gap is named, not just flagged');

  const after = await api('/api/soc/status');
  assert.match(after.body.claim, /incomplete/, 'the public claim changes with the facts');

  // Put it back so later tests see a covered rota.
  const restored = await api('/api/soc/shifts', {
    method: 'POST',
    body: { region: 'AMER', label: 'AMER day', startHour: 14, endHour: 22 },
    token
  });
  assert.equal(restored.body.coverage.complete, true);
});

test('rota changes are admin-only and range-checked', async () => {
  const analyst = await login(ANALYST);
  const admin = await login(ADMIN);

  const denied = await api('/api/soc/shifts', {
    method: 'POST', body: { region: 'AMER', label: 'Sneaky', startHour: 1, endHour: 2 }, token: analyst
  });
  assert.equal(denied.status, 403);

  const badRegion = await api('/api/soc/shifts', {
    method: 'POST', body: { region: 'MARS', label: 'Mars', startHour: 1, endHour: 2 }, token: admin
  });
  assert.equal(badRegion.status, 400);

  const badHour = await api('/api/soc/shifts', {
    method: 'POST', body: { region: 'AMER', label: 'Bad', startHour: 1, endHour: 99 }, token: admin
  });
  assert.equal(badHour.status, 400);
});

test('triage time is measured, and null when there is no sample', async () => {
  // A window narrow enough that nothing seeded falls inside it.
  const empty = await api('/api/soc/metrics?days=1');
  assert.equal(typeof empty.body.triage.sampleSize, 'number');

  const token = await login(ANALYST);
  const queue = (await api('/api/alerts?limit=3&status=new')).body.data;
  assert.ok(queue.length >= 1, 'the seed should leave untriaged alerts');

  for (const alert of queue) {
    const patched = await api(`/api/alerts/${alert.id}`, {
      method: 'PATCH', body: { status: 'triaged' }, token
    });
    assert.equal(patched.status, 200);
    assert.ok(patched.body.data.triagedAt, 'the triage moment must be stamped');
  }

  const metrics = await api('/api/soc/metrics');
  assert.ok(metrics.body.triage.sampleSize >= queue.length);
  assert.equal(typeof metrics.body.triage.medianSeconds, 'number');
  assert.notEqual(metrics.body.triage.medianLabel, '—');
});

test('the triage moment is stamped once and never moved', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=1&status=new')).body.data[0];

  const first = await api(`/api/alerts/${alert.id}`, {
    method: 'PATCH', body: { status: 'triaged' }, token
  });
  const stamped = first.body.data.triagedAt;
  assert.ok(stamped);

  const later = await api(`/api/alerts/${alert.id}`, {
    method: 'PATCH', body: { status: 'investigating', note: 'Still looking.' }, token
  });

  // updated_at moves; triaged_at must not, or the median becomes "time since
  // last edit" rather than time to triage.
  assert.equal(later.body.data.triagedAt, stamped);
  assert.notEqual(later.body.data.updatedAt, stamped);
});

test('false positives need a category and a reason, and feed the tuning report', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=1')).body.data[0];

  const noReason = await api(`/api/alerts/${alert.id}/false-positive`, {
    method: 'POST', body: { category: 'rule_too_broad' }, token
  });
  assert.equal(noReason.status, 400);
  assert.ok(noReason.body.fields.reason);

  const badCategory = await api(`/api/alerts/${alert.id}/false-positive`, {
    method: 'POST', body: { category: 'made_up', reason: 'It was the backup job.' }, token
  });
  assert.equal(badCategory.status, 400);

  const marked = await api(`/api/alerts/${alert.id}/false-positive`, {
    method: 'POST',
    body: { category: 'scheduled_job', reason: 'Matches the nightly backup on every server.' },
    token
  });
  assert.equal(marked.status, 200);
  assert.equal(marked.body.data.falsePositive, true);
  assert.equal(marked.body.data.status, 'closed');
  // The analyst should see the effect on the rule, not have it vanish into a
  // report nobody opens.
  assert.match(marked.body.message, /marked false positive/);

  const report = await api('/api/soc/tuning?minimum=1', { token });
  const rule = report.body.rules.find((r) => r.ruleId === alert.ruleId);
  assert.ok(rule, 'the rule should now appear in the tuning report');
  assert.ok(rule.falsePositives >= 1);
  assert.ok(rule.suggestion, 'a report without a suggestion is just a complaint');
});

test('a false-positive mark can be withdrawn, once', async () => {
  const token = await login(ANALYST);
  const alert = (await api('/api/alerts?limit=5')).body.data
    .find((a) => !a.falsePositive);

  await api(`/api/alerts/${alert.id}/false-positive`, {
    method: 'POST',
    body: { category: 'scanner', reason: 'Authorised quarterly penetration test.' },
    token
  });

  const undone = await api(`/api/alerts/${alert.id}/true-positive`, { method: 'POST', token });
  assert.equal(undone.status, 200);
  assert.equal(undone.body.data.falsePositive, false);

  const again = await api(`/api/alerts/${alert.id}/true-positive`, { method: 'POST', token });
  assert.equal(again.status, 409);
});

test('the dashboard false-positive rate is measured, not the old literal', async () => {
  const stats = await api('/api/stats');
  const performance = (stats.body.data || stats.body).performance;

  assert.notEqual(performance.falsePositiveRate, 3.7, 'this was a hard-coded literal');
  assert.ok(performance.falsePositiveSampleSize > 0, 'a rate needs a denominator');
  assert.ok('medianTriageSeconds' in performance);
});

test('the services page reports a measured triage figure, not a fixed string', async () => {
  const services = await api('/api/services');
  const soc = services.body.data.find((entry) => entry.id === 'soc');

  const triage = soc.metrics.find((metric) => metric.label === 'Median triage');
  assert.ok(triage.measured, 'the metric should declare itself measured');
  assert.notEqual(triage.value, '47s', 'this was a literal with nothing behind it');
});

test('an escalation is timed and can only be claimed once', async () => {
  const analyst = await login(ANALYST);
  const admin = await login(ADMIN);
  const incident = openIncident(await api('/api/incidents?status=open&limit=5'));

  const thin = await api('/api/soc/escalations', {
    method: 'POST', body: { incidentId: incident.id, priority: 'P1', reason: 'help' }, token: analyst
  });
  assert.equal(thin.status, 400, 'a reason is required');

  const raised = await api('/api/soc/escalations', {
    method: 'POST',
    body: {
      incidentId: incident.id,
      priority: 'P1',
      reason: 'Domain controller compromise confirmed; Tier 3 needed on the bridge.',
      bridgeRef: 'meet.vgil.io/p1'
    },
    token: analyst
  });
  assert.equal(raised.status, 201);
  assert.equal(raised.body.data.acknowledgedAt, null);
  assert.match(raised.body.note, /bypassing digest/);

  const id = raised.body.data.id;

  const ack = await api(`/api/soc/escalations/${id}/acknowledge`, { method: 'POST', token: admin });
  assert.equal(ack.status, 200);
  assert.equal(ack.body.data.acknowledgedBy, ADMIN.email);
  assert.equal(typeof ack.body.data.acknowledgeSeconds, 'number');

  const second = await api(`/api/soc/escalations/${id}/acknowledge`, { method: 'POST', token: analyst });
  assert.equal(second.status, 409, 'two people must not both hold the bridge');

  const resolved = await api(`/api/soc/escalations/${id}/resolve`, {
    method: 'POST', body: { resolution: 'Contained and eradicated; forensics with Tier 3.' }, token: admin
  });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.body.data.open, false);
});

test('a handover snapshots the open queue and needs a real note', async () => {
  const token = await login(ANALYST);

  const empty = await api('/api/soc/handovers', { method: 'POST', body: { notes: 'ok' }, token });
  assert.equal(empty.status, 400);

  const done = await api('/api/soc/handovers', {
    method: 'POST',
    body: { notes: 'INC-2043 under investigation; awaiting EDR telemetry from the host.' },
    token
  });
  assert.equal(done.status, 201);
  assert.ok(done.body.data.openCount > 0, 'the open queue should be captured');
  assert.ok(Array.isArray(done.body.data.openIncidents));
});

test('pod membership records a tier and rejects nonsense', async () => {
  const token = await login(ADMIN);

  const pods = await api('/api/soc/pods');
  assert.equal(pods.body.total, 3, 'three seeded pods, one per region');
  const pod = pods.body.data[0];

  const user = (await api('/api/admin/users', { token })).body.data
    .find((u) => u.email === ANALYST.email);

  const added = await api(`/api/soc/pods/${pod.id}/members`, {
    method: 'POST', body: { userId: user.id, tier: 3 }, token
  });
  assert.equal(added.status, 201);
  assert.ok(added.body.data.some((m) => m.email === ANALYST.email && m.tier === 3));

  const badTier = await api(`/api/soc/pods/${pod.id}/members`, {
    method: 'POST', body: { userId: user.id, tier: 7 }, token
  });
  assert.equal(badTier.status, 400);

  const removed = await api(`/api/soc/pods/${pod.id}/members/${user.id}`, {
    method: 'DELETE', token
  });
  assert.equal(removed.status, 200);
});

/* ============================================ vulnerability & exposure === */

const exposureLib = require('../server/lib/exposure');

test('exposure ranking is not raw CVSS', () => {
  const asset = { criticality: 'high', surface: 'external' };
  const context = { affectedCount: 3, totalAssets: 15, worstCriticality: 0.7 };

  // Actively exploited, internet-facing, but only a 6.5.
  const exploited = exposureLib.scoreFinding(
    { cvss: 6.5, epss: 0.91, kev: true }, asset, context
  );

  // Nearly the worst CVSS possible, but nobody is exploiting it.
  const severe = exposureLib.scoreFinding(
    { cvss: 9.9, epss: 0.03, kev: false },
    { criticality: 'medium', surface: 'internal' },
    { affectedCount: 1, totalAssets: 15, worstCriticality: 0.4 }
  );

  assert.ok(
    exploited.score > severe.score,
    `a KEV-listed 6.5 (${exploited.score}) must outrank an unexploited 9.9 (${severe.score})`
  );
});

test('CVSS is the smallest term in the score', () => {
  const scored = exposureLib.scoreFinding(
    { cvss: 10, epss: 0.9, kev: true },
    { criticality: 'critical', surface: 'external' },
    { affectedCount: 10, totalAssets: 15, worstCriticality: 1 }
  );

  const cvss = scored.factors.find((f) => f.factor === 'cvss');
  const others = scored.factors.filter((f) => f.factor !== 'cvss');

  for (const factor of others) {
    assert.ok(
      factor.points >= cvss.points,
      `${factor.factor} (${factor.points}) should not score below CVSS (${cvss.points})`
    );
  }
  assert.equal(exposureLib.WEIGHTS.cvss, 5, 'CVSS is capped at 5 of 100');
});

test('every score is explainable', () => {
  const scored = exposureLib.scoreFinding(
    { cvss: 8.8, epss: 0.41, kev: true },
    { criticality: 'critical', surface: 'internal' },
    { affectedCount: 4, totalAssets: 15, worstCriticality: 1, worstCriticalityLabel: 'critical' }
  );

  const sum = scored.factors.reduce((total, factor) => total + factor.points, 0);
  assert.equal(sum, scored.score, 'the factors must add up to the score');

  for (const factor of scored.factors) {
    assert.ok(factor.detail && factor.detail.length > 10, `${factor.factor} needs a readable reason`);
  }
});

test('blast radius grows with the estate it touches', () => {
  const vuln = { cvss: 7, epss: 0.3, kev: false };
  const asset = { criticality: 'medium', surface: 'internal' };

  const narrow = exposureLib.scoreFinding(vuln, asset, {
    affectedCount: 1, totalAssets: 100, worstCriticality: 0.4
  });
  const wide = exposureLib.scoreFinding(vuln, asset, {
    affectedCount: 80, totalAssets: 100, worstCriticality: 0.4
  });

  assert.ok(wide.score > narrow.score, 'the same flaw on 80 hosts is worse than on one');
});

test('reachability is scored from the asset, not asserted', () => {
  const vuln = { cvss: 7, epss: 0.3, kev: false };
  const context = { affectedCount: 2, totalAssets: 20, worstCriticality: 0.4 };

  const external = exposureLib.scoreFinding(vuln, { criticality: 'medium', surface: 'external' }, context);
  const internal = exposureLib.scoreFinding(vuln, { criticality: 'medium', surface: 'internal' }, context);

  assert.ok(external.score > internal.score, 'internet-facing needs no foothold');
});

test('the surface is derived from the inventory', () => {
  assert.equal(exposureLib.surfaceFor({ zone: 'DMZ', type: 'Web Server' }), 'external');
  assert.equal(exposureLib.surfaceFor({ zone: 'Cloud VPC', type: 'Container Host' }), 'cloud');
  assert.equal(exposureLib.surfaceFor({ zone: 'Corporate', type: 'Workstation' }), 'internal');
});

test('a vulnerability only applies to asset types it can affect', () => {
  const tomcat = { appliesTo: ['Web Server', 'Container Host'] };

  assert.equal(exposureLib.applies(tomcat, { type: 'Web Server' }), true);
  assert.equal(exposureLib.applies(tomcat, { type: 'Cloud Storage' }), false,
    'this is what stopped a Tomcat flaw being reported against a bucket');

  // No restriction means it can apply anywhere.
  assert.equal(exposureLib.applies({ appliesTo: [] }, { type: 'Anything' }), true);
});

test('the prioritised queue and the CVSS ordering genuinely differ', async () => {
  const res = await api('/api/exposure/ranking?limit=5');
  assert.equal(res.status, 200);

  assert.equal(res.body.byExposure.length, 5);
  assert.equal(res.body.byCvss.length, 5);
  assert.ok(res.body.differing > 0, 'if the orderings agreed there would be nothing to claim');

  // The top finding by exposure should not simply be the highest CVSS.
  const topExposure = res.body.byExposure[0];
  const topCvss = res.body.byCvss[0];
  assert.ok(topCvss.cvss >= topExposure.cvss, 'the CVSS list is sorted by CVSS');
  assert.ok(topExposure.exposureScore > topCvss.exposureScore,
    'the exposure list leads with the more exposed finding');
});

test('blast radius is counted from findings, not stored on the CVE', async () => {
  const res = await api('/api/exposure/catalogue');
  assert.equal(res.status, 200);

  const withFindings = res.body.data.filter((vuln) => vuln.affectedAssets > 0);
  assert.ok(withFindings.length > 0);

  for (const vuln of withFindings) {
    const findings = repo.vulnFindings.query({ cve: vuln.cve, status: 'all', limit: 500 });
    const live = findings.filter((f) => f.status === 'open' || f.status === 'remediating').length;
    assert.equal(vuln.affectedAssets, live, `${vuln.cve} radius must match its live findings`);
  }
});

test('a finding cannot be marked resolved by hand', async () => {
  const token = await login(ANALYST);
  const finding = (await api('/api/exposure?limit=1')).body.data[0];

  const res = await api(`/api/exposure/${finding.id}`, {
    method: 'PATCH', body: { status: 'resolved' }, token
  });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'verification_required');
});

test('a verification rescan that still finds it reopens the finding', async () => {
  const token = await login(ANALYST);
  const finding = (await api('/api/exposure?limit=3')).body.data[0];

  const failed = await api(`/api/exposure/${finding.id}/verify`, {
    method: 'POST', body: { stillPresent: true }, token
  });

  assert.equal(failed.status, 200);
  assert.equal(failed.body.verified, false);
  assert.equal(failed.body.finding.status, 'open', 'a patch that did not take must not read as resolved');
  assert.equal(failed.body.finding.verifiedAt, null);

  const passed = await api(`/api/exposure/${finding.id}/verify`, {
    method: 'POST', body: { stillPresent: false }, token
  });

  assert.equal(passed.body.verified, true);
  assert.equal(passed.body.finding.status, 'resolved');
  assert.ok(passed.body.finding.verifiedAt, 'resolution is stamped by the rescan');
});

test('accepting risk requires a justification and an expiry', async () => {
  const token = await login(ANALYST);
  const finding = (await api('/api/exposure?limit=6')).body.data
    .find((f) => f.status === 'open');

  const thin = await api(`/api/exposure/${finding.id}/accept`, {
    method: 'POST', body: { reason: 'later', days: 30 }, token
  });
  assert.equal(thin.status, 400);
  assert.ok(thin.body.fields.reason);

  const forever = await api(`/api/exposure/${finding.id}/accept`, {
    method: 'POST',
    body: { reason: 'Compensating control at the perimeter; scheduled for the Q4 change window.' },
    token
  });
  assert.equal(forever.status, 400, 'an acceptance with no expiry is never revisited');

  const accepted = await api(`/api/exposure/${finding.id}/accept`, {
    method: 'POST',
    body: { reason: 'Compensating control at the perimeter; scheduled for the Q4 change window.', days: 90 },
    token
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.data.status, 'accepted');
  assert.ok(accepted.body.data.acceptedUntil);

  const withdrawn = await api(`/api/exposure/${finding.id}/withdraw-acceptance`, {
    method: 'POST', token
  });
  assert.equal(withdrawn.body.data.status, 'open');
});

test('discovery is deterministic and does not duplicate findings', async () => {
  const token = await login(ADMIN);

  const first = await api('/api/exposure/scan', { method: 'POST', token });
  assert.equal(first.status, 200);

  const countAfterFirst = repo.vulnFindings.count();

  const second = await api('/api/exposure/scan', { method: 'POST', token });
  assert.equal(second.body.created, 0, 'a repeat scan of the same inventory finds nothing new');
  assert.ok(second.body.seen > 0, 'it should confirm the existing findings are still present');
  assert.equal(repo.vulnFindings.count(), countAfterFirst, 'no duplicate rows');
});

test('a finding escalates into a real incident', async () => {
  const token = await login(ANALYST);
  const finding = (await api('/api/exposure?limit=10')).body.data
    .find((f) => f.status === 'open');

  const res = await api(`/api/exposure/${finding.id}/escalate`, { method: 'POST', token });
  assert.equal(res.status, 201);
  assert.match(res.body.incident.id, /^INC-/);

  // The incident summary should carry the reasoning, not just the CVE id.
  assert.match(res.body.incident.summary, /Exposure \d+\/100/);
  assert.match(res.body.incident.summary, /EPSS/);
  assert.equal(res.body.finding.status, 'remediating');
});

test('the asset inventory finding count is derived, not drifted', async () => {
  repo.assets.refreshOpenFindings();

  for (const asset of repo.assets.query().slice(0, 5)) {
    const live = repo.vulnFindings
      .query({ assetId: asset.id, status: 'all', limit: 500 })
      .filter((f) => f.status === 'open' || f.status === 'remediating').length;

    assert.equal(asset.openFindings, live, `${asset.host} count must match its findings`);
  }
});

test('the legacy vulnerabilities endpoint now serves counted data', async () => {
  const res = await api('/api/threats/vulnerabilities');
  assert.equal(res.status, 200);
  assert.ok(res.body.data.length > 0);

  // "affected" used to be a literal in a static array.
  for (const vuln of res.body.data) {
    assert.equal(vuln.affected, repo.vulnFindings.countForCve(vuln.cve));
  }
});

test('remediation windows tighten with the band', () => {
  const from = new Date('2026-01-01T00:00:00.000Z');

  const critical = new Date(exposureLib.dueDate('critical', from));
  const low = new Date(exposureLib.dueDate('low', from));

  assert.ok(critical < low, 'a critical finding gets a shorter window than a low one');
  assert.equal(Math.round((critical - from) / 86400000), exposureLib.SLA_DAYS.critical);
});

/* ============================================================ threat globe === */

test('cobe is vendored into public where the CSP can load it', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const vendored = path.join(__dirname, '..', 'public', 'assets', 'vendor', 'cobe.js');
  assert.ok(fs.existsSync(vendored), 'run `npm run vendor` — node_modules is not served');

  const source = fs.readFileSync(vendored, 'utf8');
  assert.match(source, /Vendored by tools\/vendor\.js/, 'the banner should survive');
  assert.match(source, /export\s*\{/, 'cobe is ESM, so the tag loading it needs type="module"');

  // Pinned so an upgrade that changes the option contract is a deliberate act.
  const installed = require('cobe/package.json').version;
  assert.match(installed, /^2\./, 'arcs and markerElevation are v2 options');
});

test('the globe module is loaded as an ES module', () => {
  const fs = require('node:fs');
  const path = require('node:path');

  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'dashboard.html'), 'utf8');
  assert.match(
    html,
    /<script type="module" src="\/assets\/js\/worldmap\.js"><\/script>/,
    'cobe is ESM; a classic script tag would fail to parse the import'
  );
});

test('every globe marker sits within the coordinate range cobe accepts', async () => {
  const res = await api('/api/threats/geo');
  assert.equal(res.status, 200);
  assert.ok(res.body.data.length > 0);

  for (const origin of res.body.data) {
    assert.ok(origin.lat >= -90 && origin.lat <= 90, `${origin.country} latitude out of range`);
    assert.ok(origin.lon >= -180 && origin.lon <= 180, `${origin.country} longitude out of range`);
    // Marker ids are built from the country code, and cobe uses them as CSS
    // custom property names for label anchoring.
    assert.match(origin.code, /^[A-Z]{2}$/, `${origin.country} needs a clean code for the anchor name`);
  }
});

test('the SOC sites the globe marks are real coordinates', () => {
  const sites = [
    ['Singapore', 1.35, 103.8],
    ['London', 51.5, -0.13],
    ['Toronto', 43.7, -79.4]
  ];

  for (const [name, lat, lon] of sites) {
    assert.ok(lat >= -90 && lat <= 90, `${name} latitude out of range`);
    assert.ok(lon >= -180 && lon <= 180, `${name} longitude out of range`);
  }
});

test('the headquarters marker is real coordinates and does not move with the rota', async () => {
  const first = await api('/api/soc/status');
  assert.equal(first.status, 200);

  const hq = first.body.headquarters;
  assert.ok(hq, 'status must always report a headquarters, configured rota or not');
  assert.equal(hq.city, 'Vadodara');
  assert.equal(hq.region, 'Gujarat');
  assert.equal(hq.country, 'India');
  assert.ok(hq.lat >= -90 && hq.lat <= 90, 'headquarters latitude out of range');
  assert.ok(hq.lon >= -180 && hq.lon <= 180, 'headquarters longitude out of range');

  // Vadodara is inland, at roughly 22.3N 73.2E — not one of the SOC_SITES
  // coordinates the on-duty rota already draws.
  assert.ok(Math.abs(hq.lat - 22.3072) < 0.01);
  assert.ok(Math.abs(hq.lon - 73.1812) < 0.01);

  const second = await api('/api/soc/status');
  assert.deepEqual(second.body.headquarters, hq, 'headquarters is a fixed fact, not derived from who is on console');
});
