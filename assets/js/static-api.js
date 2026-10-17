/**
 * VGIL static demo backend — GitHub Pages build only.
 *
 * GitHub Pages serves files, not a Node process, so this script stands in for
 * the Express API inside the browser. It answers every `fetch()` to `/api/...`
 * and the `/api/alerts/stream` EventSource from a snapshot of a real server
 * (assets/data/demo.json), applies filters/sorting/paging the way the API
 * does, and keeps the visitor's own changes (triage, escalations, sign-ups)
 * in localStorage so the demo behaves like a working console.
 *
 * Loaded before api.js by tools/build-pages.js. Not used by `npm start`.
 */
(function () {
  'use strict';

  var BASE = (document.currentScript && document.currentScript.getAttribute('data-base')) || '';
  var STATE_KEY = 'vgil.demo.state';
  var realFetch = window.fetch.bind(window);

  var DEMO_PASSWORDS = { 'admin@vgil.io': 'Vgil#Admin2026', 'analyst@vgil.io': 'Vgil#Demo2026' };

  /* ------------------------------------------------------------ data load */

  var data = null;
  var ready = realFetch(BASE + '/assets/data/demo.json')
    .then(function (r) { return r.json(); })
    .then(function (d) {
      data = d;
      rebaseTimes(d, Date.now() - new Date(d.snapshotAt).getTime());
      loadState();
      return d;
    });

  /** Shift every ISO timestamp so the snapshot always reads as "just now". */
  var ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
  function rebaseTimes(node, delta) {
    if (Array.isArray(node)) {
      for (var i = 0; i < node.length; i++) {
        if (typeof node[i] === 'string' && ISO.test(node[i])) node[i] = shift(node[i], delta);
        else if (node[i] && typeof node[i] === 'object') rebaseTimes(node[i], delta);
      }
    } else if (node && typeof node === 'object') {
      Object.keys(node).forEach(function (k) {
        var v = node[k];
        if (typeof v === 'string' && ISO.test(v)) node[k] = shift(v, delta);
        else if (v && typeof v === 'object') rebaseTimes(v, delta);
      });
    }
  }
  function shift(iso, delta) {
    return new Date(new Date(iso).getTime() + delta).toISOString();
  }

  /* ------------------------------------------------------- visitor state */

  // patches: "/alerts/ID" → fields merged over the snapshot record
  // created: "/incidents" → records the visitor added
  // deleted: "/admin/webhooks/ID" → true
  // users: registered demo accounts { email: { user, hash } }
  var state = { patches: {}, created: {}, deleted: {}, users: {}, seq: 1 };

  function loadState() {
    try {
      var raw = localStorage.getItem(STATE_KEY);
      if (raw) state = Object.assign(state, JSON.parse(raw));
    } catch (e) {}
  }
  function saveState() {
    try {
      localStorage.setItem(STATE_KEY, JSON.stringify(state));
    } catch (e) {}
  }

  function currentUser() {
    try {
      return JSON.parse(localStorage.getItem('vgil.user') || 'null');
    } catch (e) {
      return null;
    }
  }

  function uid(prefix) {
    return prefix + '-' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).slice(2, 6).toUpperCase();
  }

  function clone(v) {
    return v === undefined ? v : JSON.parse(JSON.stringify(v));
  }

  /* ------------------------------------------------------------- lists */

  /** Longest snapshot list path that prefixes `path`. */
  function listFor(path) {
    var best = null;
    Object.keys(data.lists).forEach(function (base) {
      if ((path === base || path.indexOf(base + '/') === 0) && (!best || base.length > best.length)) best = base;
    });
    return best;
  }

  function keyOf(item) {
    return item.id !== undefined ? item.id : item.indicator;
  }

  /** The list's records with the visitor's additions, edits and deletions applied. */
  function records(base) {
    var created = state.created[base] || [];
    var stream = base === '/alerts' ? streamAlerts : [];
    var rows = stream.concat(created.slice().reverse(), data.lists[base].data || []);
    return rows
      .filter(function (r) { return !state.deleted[base + '/' + keyOf(r)]; })
      .map(function (r) {
        var p = state.patches[base + '/' + keyOf(r)];
        return p ? Object.assign({}, r, p) : r;
      });
  }

  function findRecord(base, id) {
    var rows = records(base);
    for (var i = 0; i < rows.length; i++) if (String(keyOf(rows[i])) === String(id)) return rows[i];
    return null;
  }

  var RESERVED = ['page', 'limit', 'sort', 'order', 'q', 'since'];

  function queryList(base, params) {
    var rows = records(base);

    Object.keys(params).forEach(function (k) {
      if (RESERVED.indexOf(k) !== -1 || params[k] === '') return;
      var wanted = String(params[k]).toLowerCase().split(',');
      rows = rows.filter(function (r) {
        if (!(k in r)) return true; // unknown filter: the server ignores it too
        var v = r[k];
        if (Array.isArray(v)) return v.some(function (x) { return wanted.indexOf(String(x).toLowerCase()) !== -1; });
        if (typeof v === 'boolean') return String(v) === wanted[0];
        return wanted.indexOf(String(v).toLowerCase()) !== -1;
      });
    });

    if (params.q) {
      var q = String(params.q).toLowerCase();
      rows = rows.filter(function (r) { return JSON.stringify(r).toLowerCase().indexOf(q) !== -1; });
    }

    if (params.since) {
      var since = new Date(params.since).getTime();
      if (!isNaN(since)) {
        rows = rows.filter(function (r) {
          var t = r.ts || r.openedAt || r.createdAt;
          return !t || new Date(t).getTime() >= since;
        });
      }
    }

    if (params.sort) {
      var field = params.sort;
      var dir = params.order === 'asc' ? 1 : -1;
      var SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      rows = rows.slice().sort(function (a, b) {
        var x = a[field], y = b[field];
        if (field === 'severity') { x = SEV[x]; y = SEV[y]; }
        if (x === y) return 0;
        if (x === undefined || x === null) return 1;
        if (y === undefined || y === null) return -1;
        return (x > y ? 1 : -1) * dir;
      });
    }

    var template = data.lists[base];
    var out = Object.assign({}, template);
    var total = rows.length;

    if (template.pagination || params.page || params.limit) {
      var limit = Math.max(1, Math.min(500, parseInt(params.limit, 10) || (template.pagination ? template.pagination.limit : total) || 25));
      var page = Math.max(1, parseInt(params.page, 10) || 1);
      var start = (page - 1) * limit;
      out.data = rows.slice(start, start + limit);
      if (template.pagination) {
        out.pagination = {
          page: page,
          limit: limit,
          total: total,
          pages: Math.max(1, Math.ceil(total / limit)),
          hasNext: start + limit < total,
          hasPrev: page > 1
        };
      }
    } else {
      out.data = rows;
    }
    if ('total' in template) out.total = total;
    return clone(out);
  }

  /* ----------------------------------------------------------- responses */

  function reply(status, body, contentType) {
    var text = typeof body === 'string' ? body : JSON.stringify(body);
    return new Response(text, {
      status: status,
      headers: { 'Content-Type': contentType || 'application/json; charset=utf-8' }
    });
  }
  function ok(body) { return reply(200, body); }
  function created(body) { return reply(201, body); }
  function fail(status, error, message, fields) {
    return reply(status, { error: error, message: message, fields: fields });
  }
  function demoOnly() {
    return fail(501, 'demo_mode', 'This action needs the full VGIL server. It is turned off in the GitHub Pages demo.');
  }

  /** Swaps the snapshot's admin identity for whoever is signed in. */
  function asCurrentUser(body) {
    var user = currentUser();
    if (!user || !body) return body;
    if (body.user && body.user.email) body.user = Object.assign({}, body.user, user);
    if (body.data && body.data.email && !Array.isArray(body.data)) body.data = Object.assign({}, body.data, user);
    return body;
  }

  /* ---------------------------------------------------------- the router */

  function handle(method, path, params, body, rawQuery) {
    var user = currentUser();

    if (/^\/admin(\/|$)/.test(path) && (!user || user.role !== 'admin')) {
      return fail(user ? 403 : 401, user ? 'forbidden' : 'unauthorized',
        user ? 'Administrator role required.' : 'Sign in to continue.');
    }

    if (path.indexOf('/auth/') === 0) return auth(method, path, body);
    if (method === 'GET') return get(path, params, rawQuery);
    return write(method, path, body || {}, user);
  }

  function get(path, params, rawQuery) {
    if (path === '/health' || path === '/ready') {
      return ok(Object.assign({}, data.routes['GET ' + path], { time: new Date().toISOString(), mode: 'static-demo' }));
    }
    if (path === '/account') return ok(asCurrentUser(clone(data.routes['GET /account'])));

    var text = data.text['GET ' + path];
    if (text) return reply(200, text.body, text.ct);

    var base = listFor(path);
    if (base && path === base) return ok(queryList(base, params));

    var exact = data.routes['GET ' + path + (rawQuery ? '?' + rawQuery : '')];
    if (exact) return ok(clone(exact));

    if (base) {
      var id = decodeURIComponent(path.slice(base.length + 1));
      if (id.indexOf('/') === -1) {
        var rec = findRecord(base, id);
        if (!rec) return fail(404, 'not_found', 'Not found.');
        var detail = data.routes['GET ' + path];
        var merged = detail && detail.data ? Object.assign({}, detail.data, rec) : rec;
        return ok(Object.assign({}, clone(detail) || {}, { data: clone(merged) }));
      }
    }

    var plain = data.routes['GET ' + path];
    if (plain) return ok(clone(plain));

    // Same route with different query string: reuse what was recorded.
    var prefix = 'GET ' + path + '?';
    var similar = Object.keys(data.routes).filter(function (k) { return k.indexOf(prefix) === 0; })[0];
    if (similar) return ok(clone(data.routes[similar]));

    return fail(404, 'not_found', 'No such endpoint in the static demo.');
  }

  /* ---------------------------------------------------------------- auth */

  function sha(text) {
    if (!(window.crypto && crypto.subtle)) return Promise.resolve(text);
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
    });
  }

  function session(user) {
    return {
      user: Object.assign({}, user, { lastLogin: new Date().toISOString() }),
      token: 'demo.' + user.role + '.' + Math.random().toString(36).slice(2),
      expiresAt: Date.now() + 12 * 3600 * 1000
    };
  }

  function passwordStrength(password) {
    var issues = [];
    if (password.length < 10) issues.push('at least 10 characters');
    if (!/[a-z]/.test(password)) issues.push('a lowercase letter');
    if (!/[A-Z]/.test(password)) issues.push('an uppercase letter');
    if (!/[0-9]/.test(password)) issues.push('a number');
    if (!/[^A-Za-z0-9]/.test(password)) issues.push('a symbol');
    if (['password', 'qwerty', '12345', 'letmein', 'admin', 'welcome'].some(function (c) {
      return password.toLowerCase().indexOf(c) !== -1;
    })) issues.push('no common dictionary words');
    return { ok: issues.length === 0, issues: issues, score: Math.max(0, 5 - issues.length) };
  }

  function auth(method, path, body) {
    body = body || {};
    var email = String(body.email || '').trim().toLowerCase();

    if (path === '/auth/me') {
      var u = currentUser();
      return u ? ok({ user: u }) : fail(401, 'unauthorized', 'Sign in to continue.');
    }
    if (path === '/auth/logout') return ok({ ok: true });

    if (path === '/auth/password-check') {
      var s = passwordStrength(String(body.password || ''));
      var labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
      return ok({ score: s.score, label: labels[s.score] || 'Very weak', ok: s.ok, issues: s.issues });
    }

    if (path === '/auth/login') {
      if (DEMO_PASSWORDS[email]) {
        if (body.password !== DEMO_PASSWORDS[email]) {
          return fail(401, 'invalid_credentials', 'Email or password is incorrect.');
        }
        return ok(session(email === 'admin@vgil.io' ? data.users.admin : data.users.analyst));
      }
      var known = state.users[email];
      if (!known) return fail(401, 'invalid_credentials', 'Email or password is incorrect.');
      return sha(String(body.password || '')).then(function (h) {
        return h === known.hash ? ok(session(known.user)) : fail(401, 'invalid_credentials', 'Email or password is incorrect.');
      });
    }

    if (path === '/auth/register') {
      var fields = {};
      var name = String(body.name || '').trim();
      if (name.length < 2) fields.name = 'Enter your name.';
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) fields.email = 'Enter a valid email address.';
      var strength = passwordStrength(String(body.password || ''));
      if (!strength.ok) fields.password = 'Password needs ' + strength.issues.join(', ') + '.';
      if (DEMO_PASSWORDS[email] || state.users[email]) fields.email = 'An account with that email already exists.';
      if (Object.keys(fields).length) return fail(400, 'validation_failed', 'Please fix the highlighted fields.', fields);

      var user = {
        id: uid('USR'),
        name: name,
        email: email,
        role: 'analyst',
        org: String(body.company || body.org || 'Independent'),
        title: 'SOC Analyst',
        createdAt: new Date().toISOString(),
        lastLogin: null,
        disabled: false,
        mfaEnabled: false,
        demo: true,
        mfaConfirmedAt: null
      };
      return sha(String(body.password)).then(function (h) {
        state.users[email] = { user: user, hash: h };
        saveState();
        return created(session(user));
      });
    }

    // MFA challenge, password reset: need email delivery or a real secret.
    return demoOnly();
  }

  /* -------------------------------------------------------------- writes */

  function write(method, path, body, user) {
    var actor = user ? user.email : 'visitor';
    var now = new Date().toISOString();

    if (path === '/contact' && method === 'POST') {
      return ok({
        ok: true,
        reference: uid('REQ'),
        sla: '1 business day',
        message: 'Request received (demo). On the full server this is stored and routed to a security engineer.'
      });
    }
    if (path === '/threats/lookup') return ok(lookup(String(body.indicator || '').trim()));
    if (path === '/threats/posture-scan') return postureScan(String(body.domain || ''));

    // Account security and credentials cannot be faked meaningfully.
    if (/^\/account\/(password|mfa|api-keys)/.test(path) && method !== 'DELETE') return demoOnly();
    if (/^\/admin\/api-keys/.test(path)) return demoOnly();

    if (!user) return fail(401, 'unauthorized', 'Sign in to continue.');

    var m = path.match(/^\/alerts\/([^/]+)\/(escalate|false-positive|true-positive)$/);
    if (m && method === 'POST') return alertAction(m[1], m[2], body, actor, now);

    var base = listFor(path);

    if (method === 'PATCH' || method === 'PUT') {
      if (base && path !== base) {
        var id = decodeURIComponent(path.slice(base.length + 1));
        var rec = findRecord(base, id);
        if (!rec) return fail(404, 'not_found', 'Not found.');
        var patch = Object.assign({}, state.patches[base + '/' + id] || {});
        Object.keys(body).forEach(function (k) {
          if (k === 'note') return;
          patch[k] = body[k];
        });
        if (body.note) {
          patch.notes = (rec.notes || []).concat([{ ts: now, author: actor, text: String(body.note) }]);
        }
        if (body.status && body.status !== 'new' && !rec.triagedAt && base === '/alerts') {
          patch.triagedAt = now;
          patch.triagedBy = actor;
        }
        if (base === '/incidents' && body.status) {
          patch.timeline = (rec.timeline || []).concat([{ ts: now, actor: actor, entry: 'Status changed to ' + body.status + '.' }]);
          if (body.status === 'closed') patch.closedAt = now;
        }
        patch.updatedAt = now;
        state.patches[base + '/' + id] = patch;
        saveState();
        return ok({ data: Object.assign({}, rec, patch) });
      }
      // Settings-style PATCH (e.g. /account, /account/notifications): echo it back.
      var current = data.routes['GET ' + path] || {};
      return ok(asCurrentUser(Object.assign({}, clone(current), body.prefs ? { prefs: body.prefs } : {}, { ok: true })));
    }

    if (method === 'DELETE') {
      state.deleted[path] = true;
      saveState();
      return ok({ ok: true, message: 'Removed (demo).' });
    }

    if (method === 'POST' && base && path === base) {
      var item = Object.assign({ id: base === '/incidents' ? nextIncidentId() : uid('DEM') }, body, {
        createdAt: now,
        updatedAt: now,
        createdBy: actor
      });
      if (base === '/incidents') {
        item = Object.assign({ status: 'new', openedAt: now, closedAt: null, analyst: actor, timeline: [] }, item);
        item.timeline = [{ ts: now, actor: actor, entry: 'Incident opened.' }];
      }
      (state.created[base] = state.created[base] || []).push(item);
      saveState();
      return created({ data: item });
    }

    // Anything else (webhook tests, shifts, digests…): acknowledge it.
    return ok({ ok: true, message: 'Done (demo — nothing is sent from the static site).', data: Object.assign({ id: uid('DEM') }, body) });
  }

  function nextIncidentId() {
    var max = 0;
    records('/incidents').forEach(function (i) {
      var n = parseInt(String(i.id).replace(/\D/g, ''), 10);
      if (n > max) max = n;
    });
    return 'INC-' + String(max + 1).padStart(4, '0');
  }

  function alertAction(id, action, body, actor, now) {
    var alert = findRecord('/alerts', id);
    if (!alert) return fail(404, 'not_found', 'Alert not found.');
    var key = '/alerts/' + id;
    var patch = Object.assign({}, state.patches[key] || {});

    if (action === 'escalate') {
      var existing = records('/incidents').filter(function (i) { return i.sourceAlertId === id; })[0];
      if (existing) {
        return reply(409, { error: 'already_escalated', message: 'Alert already escalated as ' + existing.id + '.', data: existing });
      }
      var incident = {
        id: nextIncidentId(),
        title: alert.rule + ' on ' + alert.host,
        severity: alert.severity,
        status: 'triaged',
        priority: alert.severity === 'critical' ? 'P1' : alert.severity === 'high' ? 'P2' : 'P3',
        summary: alert.description,
        ruleId: alert.ruleId,
        rule: alert.rule,
        technique: alert.technique,
        tactic: alert.tactic,
        assetId: alert.assetId,
        host: alert.host,
        zone: alert.zone,
        owner: alert.owner,
        analyst: actor,
        sourceAlertId: alert.id,
        openedAt: now,
        acknowledgedAt: now,
        closedAt: null,
        updatedAt: now,
        timeline: [
          { ts: now, actor: 'VGIL Detection Engine', entry: 'Detection ' + alert.id + ' fired: ' + alert.rule + '.' },
          { ts: now, actor: actor, entry: 'Escalated to incident from the alert console.' }
        ]
      };
      (state.created['/incidents'] = state.created['/incidents'] || []).push(incident);
      Object.assign(patch, { status: 'investigating', incidentId: incident.id, assignee: actor, updatedAt: now });
      state.patches[key] = patch;
      saveState();
      return created({ data: incident });
    }

    if (action === 'false-positive') {
      var reason = String(body.reason || '');
      if (!body.category || reason.length < 8) {
        return fail(400, 'validation_failed', 'Please fix the highlighted fields.', {
          category: body.category ? undefined : 'Choose a category.',
          reason: reason.length < 8 ? 'Reason must be at least 8 characters.' : undefined
        });
      }
      Object.assign(patch, {
        falsePositive: true, fpCategory: body.category, fpReason: reason, fpMarkedBy: actor, fpMarkedAt: now,
        status: 'closed', updatedAt: now,
        notes: (alert.notes || []).concat([{ ts: now, author: actor, text: 'Marked false positive. ' + reason }])
      });
      state.patches[key] = patch;
      saveState();
      return ok({ data: Object.assign({}, alert, patch), rule: null, message: 'Recorded.' });
    }

    if (!alert.falsePositive) {
      return reply(409, { error: 'not_marked', message: 'That alert is not marked as a false positive.' });
    }
    Object.assign(patch, {
      falsePositive: false, fpCategory: null, fpReason: null, fpMarkedBy: null, fpMarkedAt: null,
      status: 'investigating', updatedAt: now,
      notes: (alert.notes || []).concat([{ ts: now, author: actor, text: 'False-positive mark removed; reopened for investigation.' }])
    });
    state.patches[key] = patch;
    saveState();
    return ok({ data: Object.assign({}, alert, patch) });
  }

  /* --------------------------------------------------- interactive tools */

  // Small deterministic hash standing in for the server's sha256 digest bytes.
  function digestBytes(text) {
    var out = [];
    var h = 2166136261;
    for (var n = 0; n < 16; n++) {
      for (var i = 0; i < text.length; i++) {
        h ^= text.charCodeAt(i) + n * 131;
        h = Math.imul(h, 16777619) >>> 0;
      }
      out.push(h & 255);
    }
    return out;
  }

  function classify(value) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ipv4';
    if (/^[a-f0-9]{64}$/i.test(value)) return 'sha256';
    if (/^[a-f0-9]{40}$/i.test(value)) return 'sha1';
    if (/^[a-f0-9]{32}$/i.test(value)) return 'md5';
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value)) return 'domain';
    if (/^https?:\/\//i.test(value)) return 'url';
    if (/\.[a-z0-9]{2,4}$/i.test(value)) return 'filename';
    return 'unknown';
  }

  function lookup(raw) {
    var iocs = data.lists['/threats/iocs'].data || [];
    var rules = data.lists['/threats/rules'].data || [];
    var known = iocs.filter(function (i) { return i.indicator.toLowerCase() === raw.toLowerCase(); })[0];
    var checkedAt = new Date().toISOString();

    if (known) {
      return {
        data: {
          indicator: raw, type: known.type, verdict: 'malicious', confidence: known.confidence,
          severity: known.severity, actor: known.actor, tags: known.tags, firstSeen: known.firstSeen,
          description: known.description,
          sources: ['VGIL Threat Graph', 'Partner Feed', 'Honeypot Network'],
          relatedDetections: rules.filter(function (r) {
            return known.tags.some(function (t) { return r.tactic.toLowerCase().indexOf(t.split('-')[0]) !== -1; });
          }).slice(0, 3).map(function (r) { return { id: r.id, name: r.name, technique: r.technique }; })
        },
        checkedAt: checkedAt
      };
    }

    var score = digestBytes(raw.toLowerCase())[0] % 100;
    var verdict = score > 96 ? 'malicious' : score > 88 ? 'suspicious' : 'clean';
    return {
      data: {
        indicator: raw, type: classify(raw), verdict: verdict,
        confidence: verdict === 'clean' ? Math.max(60, 100 - score) : score,
        severity: verdict === 'malicious' ? 'high' : verdict === 'suspicious' ? 'medium' : 'info',
        actor: null,
        tags: verdict === 'clean' ? ['no-known-association'] : ['unclassified', 'low-prevalence'],
        firstSeen: null,
        description: verdict === 'clean'
          ? 'No association with tracked infrastructure, campaigns or malware families in the VGIL threat graph.'
          : 'Low-prevalence indicator with weak signals. Not confirmed malicious — corroborate before blocking.',
        sources: ['VGIL Threat Graph'],
        relatedDetections: []
      },
      checkedAt: checkedAt
    };
  }

  function postureScan(input) {
    var raw = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(raw)) {
      return fail(400, 'validation_failed', 'Enter a valid domain.', { domain: 'Enter a valid domain, e.g. example.com' });
    }
    var d = digestBytes(raw);
    var checks = [
      { id: 'tls', name: 'TLS configuration', detail: 'TLS 1.3 offered, weak ciphers disabled', weight: 15 },
      { id: 'hsts', name: 'HSTS enforced', detail: 'Strict-Transport-Security with a long max-age', weight: 10 },
      { id: 'csp', name: 'Content Security Policy', detail: 'CSP present and restrictive', weight: 12 },
      { id: 'spf', name: 'SPF record', detail: 'Sender policy published with a hard fail', weight: 10 },
      { id: 'dmarc', name: 'DMARC policy', detail: 'DMARC set to quarantine or reject', weight: 13 },
      { id: 'dnssec', name: 'DNSSEC', detail: 'Zone signed and validating', weight: 8 },
      { id: 'headers', name: 'Security headers', detail: 'X-Frame-Options and nosniff present', weight: 10 },
      { id: 'exposure', name: 'Exposed services', detail: 'No unexpected admin ports reachable', weight: 12 },
      { id: 'leaks', name: 'Credential exposure', detail: 'No corporate credentials in known breach sets', weight: 10 }
    ].map(function (c, i) { return Object.assign(c, { pass: d[i + 1] % 100 > 30 }); });

    var earned = 0, possible = 0;
    checks.forEach(function (c) { possible += c.weight; if (c.pass) earned += c.weight; });
    var score = Math.round((earned / possible) * 100);
    return ok({
      data: {
        domain: raw,
        score: score,
        grade: score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 55 ? 'D' : 'F',
        scannedAt: new Date().toISOString(),
        checks: checks,
        passed: checks.filter(function (c) { return c.pass; }).length,
        failed: checks.filter(function (c) { return !c.pass; }).length,
        recommendations: checks.filter(function (c) { return !c.pass; }).map(function (c) {
          return 'Remediate: ' + c.name + ' — ' + c.detail + '.';
        }),
        disclaimer: 'Heuristic demonstration assessment based on the supplied hostname. It does not send traffic to the target and is not a substitute for an authorised external assessment.'
      }
    });
  }

  /* ------------------------------------------------------- fetch shim */

  function apiPath(url) {
    var u = new URL(url, location.href);
    if (u.origin !== location.origin) return null;
    var marker = BASE + '/api/';
    if (u.pathname.indexOf(marker) !== 0) return null;
    return u;
  }

  window.fetch = function (input, init) {
    var url = typeof input === 'string' ? input : input && input.url;
    var u = url && apiPath(url);
    if (!u) return realFetch(input, init);

    init = init || {};
    var method = String(init.method || (input && input.method) || 'GET').toUpperCase();
    var body = null;
    if (init.body) {
      try {
        body = JSON.parse(init.body);
      } catch (e) {
        body = {};
      }
    }
    var params = {};
    u.searchParams.forEach(function (v, k) { params[k] = v; });
    var path = u.pathname.slice(BASE.length + 4).replace(/\/$/, '') || '/';

    return ready.then(function () {
      // A short, variable delay so loading states look like a real network.
      return new Promise(function (resolve) { setTimeout(resolve, 60 + Math.random() * 140); });
    }).then(function () {
      return handle(method, path, params, body, u.search.slice(1));
    });
  };

  /* -------------------------------------------------- live alert stream */

  var streamAlerts = [];

  function FakeEventSource(url) {
    this.url = url;
    this.readyState = 0;
    this._listeners = {};
    this._timers = [];
    var self = this;
    ready.then(function () { self._start(); });
  }
  FakeEventSource.prototype.addEventListener = function (name, fn) {
    (this._listeners[name] = this._listeners[name] || []).push(fn);
  };
  FakeEventSource.prototype.removeEventListener = function (name, fn) {
    var list = this._listeners[name] || [];
    var i = list.indexOf(fn);
    if (i !== -1) list.splice(i, 1);
  };
  FakeEventSource.prototype._emit = function (name, payload) {
    if (this.readyState === 2) return;
    var evt = { type: name, data: JSON.stringify(payload) };
    (this._listeners[name] || []).forEach(function (fn) { fn(evt); });
    if (name === 'message' && typeof this.onmessage === 'function') this.onmessage(evt);
  };
  FakeEventSource.prototype._start = function () {
    var self = this;
    if (self.readyState === 2) return;
    self.readyState = 1;
    if (typeof self.onopen === 'function') self.onopen({ type: 'open' });
    self._emit('connected', { ts: new Date().toISOString(), message: 'VGIL detection stream established (static demo)' });
    records('/alerts').slice(0, 8).reverse().forEach(function (a) { self._emit('alert', a); });

    var tick = function () {
      var a = newAlert();
      streamAlerts.unshift(a);
      if (streamAlerts.length > 200) streamAlerts.pop();
      self._emit('alert', a);
      self._timers.push(setTimeout(tick, 3500 + Math.random() * 5500));
    };
    self._timers.push(setTimeout(tick, 2500));
    self._timers.push(setInterval(function () {
      self._emit('heartbeat', { ts: new Date().toISOString(), viewers: 1 });
    }, 25000));
  };
  FakeEventSource.prototype.close = function () {
    this.readyState = 2;
    this._timers.forEach(function (t) { clearTimeout(t); clearInterval(t); });
  };
  FakeEventSource.CONNECTING = 0;
  FakeEventSource.OPEN = 1;
  FakeEventSource.CLOSED = 2;

  /** A fresh detection: a real rule fired against a real asset from the snapshot. */
  function newAlert() {
    var pool = data.lists['/alerts'].data;
    var template = pool[Math.floor(Math.random() * pool.length)];
    var asset = pool[Math.floor(Math.random() * pool.length)];
    var confidence = Math.max(40, Math.min(99, template.confidence + Math.round((Math.random() - 0.5) * 16)));
    return Object.assign({}, template, {
      id: uid('ALT'),
      ts: new Date().toISOString(),
      assetId: asset.assetId, host: asset.host, ip: asset.ip, zone: asset.zone,
      assetType: asset.assetType, criticality: asset.criticality, owner: asset.owner,
      user: asset.user,
      confidence: confidence,
      risk: Math.max(1, Math.min(100, template.risk + Math.round((Math.random() - 0.5) * 12))),
      status: 'new', assignee: null, incidentId: undefined, falsePositive: false, notes: []
    });
  }

  var RealEventSource = window.EventSource;
  window.EventSource = function (url, opts) {
    var u = apiPath(url);
    if (u) return new FakeEventSource(url);
    return new RealEventSource(url, opts);
  };
  window.EventSource.CONNECTING = 0;
  window.EventSource.OPEN = 1;
  window.EventSource.CLOSED = 2;

  window.VGIL_STATIC_DEMO = {
    reset: function () {
      try { localStorage.removeItem(STATE_KEY); } catch (e) {}
      location.reload();
    }
  };
})();
