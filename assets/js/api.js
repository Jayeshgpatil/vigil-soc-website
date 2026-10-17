/**
 * VGIL API client + session store.
 * Exposed as window.VGIL for the page-level scripts.
 */
(function () {
  'use strict';

  var BASE = '/vigil-soc-website/api';
  var TOKEN_KEY = 'vgil.token';
  var USER_KEY = 'vgil.user';

  /* --------------------------------------------------------------- session */

  var session = {
    token: function () {
      try {
        return localStorage.getItem(TOKEN_KEY);
      } catch (e) {
        return null;
      }
    },

    user: function () {
      try {
        var raw = localStorage.getItem(USER_KEY);
        return raw ? JSON.parse(raw) : null;
      } catch (e) {
        return null;
      }
    },

    set: function (token, user) {
      try {
        localStorage.setItem(TOKEN_KEY, token);
        localStorage.setItem(USER_KEY, JSON.stringify(user));
      } catch (e) {
        /* storage disabled — session stays in-memory for this page only */
      }
    },

    clear: function () {
      try {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
      } catch (e) {}
    },

    isAuthed: function () {
      return !!session.token();
    }
  };

  /* ----------------------------------------------------------- http layer */

  /**
   * Thin fetch wrapper. Rejects with an Error carrying `.status`, `.code`
   * and `.fields` so form handlers can render per-field validation errors.
   */
  function request(path, options) {
    options = options || {};

    var headers = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';

    var token = session.token();
    if (token && options.auth !== false) headers.Authorization = 'Bearer ' + token;

    return fetch(BASE + path, {
      method: options.method || 'GET',
      headers: Object.assign(headers, options.headers || {}),
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined
    })
      .then(function (res) {
        var isJson = (res.headers.get('content-type') || '').indexOf('json') !== -1;
        return (isJson ? res.json() : res.text()).then(function (payload) {
          if (res.ok) return payload;

          var err = new Error(
            (payload && payload.message) || 'Request failed (' + res.status + ')'
          );
          err.status = res.status;
          err.code = payload && payload.error;
          err.fields = (payload && payload.fields) || {};
          err.payload = payload;

          // An expired or revoked token should not leave a stale identity behind.
          if (res.status === 401 && session.isAuthed() && path !== '/auth/login') {
            session.clear();
          }
          throw err;
        });
      })
      .catch(function (err) {
        if (err instanceof TypeError) {
          var netErr = new Error('Cannot reach the VGIL API. Is the server running?');
          netErr.status = 0;
          netErr.code = 'network_error';
          netErr.fields = {};
          throw netErr;
        }
        throw err;
      });
  }

  function qs(params) {
    var parts = [];
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v === undefined || v === null || v === '') return;
      parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
    });
    return parts.length ? '?' + parts.join('&') : '';
  }

  /* ------------------------------------------------------------ endpoints */

  var api = {
    health: function () {
      return request('/health');
    },
    stats: function () {
      return request('/stats');
    },
    services: function () {
      return request('/services');
    },
    pricing: function () {
      return request('/pricing');
    },
    assets: function (params) {
      return request('/assets' + qs(params));
    },
    contact: function (body) {
      return request('/contact', { method: 'POST', body: body });
    },

    alerts: function (params) {
      return request('/alerts' + qs(params));
    },
    alert: function (id) {
      return request('/alerts/' + encodeURIComponent(id));
    },
    alertFilters: function () {
      return request('/alerts/meta/filters');
    },
    updateAlert: function (id, body) {
      return request('/alerts/' + encodeURIComponent(id), { method: 'PATCH', body: body });
    },
    escalate: function (id) {
      return request('/alerts/' + encodeURIComponent(id) + '/escalate', { method: 'POST' });
    },

    incidents: function (params) {
      return request('/incidents' + qs(params));
    },
    incident: function (id) {
      return request('/incidents/' + encodeURIComponent(id));
    },
    createIncident: function (body) {
      return request('/incidents', { method: 'POST', body: body });
    },
    updateIncident: function (id, body) {
      return request('/incidents/' + encodeURIComponent(id), { method: 'PATCH', body: body });
    },

    actors: function (params) {
      return request('/threats/actors' + qs(params));
    },
    actor: function (id) {
      return request('/threats/actors/' + encodeURIComponent(id));
    },
    iocs: function (params) {
      return request('/threats/iocs' + qs(params));
    },
    lookup: function (indicator) {
      return request('/threats/lookup', { method: 'POST', body: { indicator: indicator } });
    },
    vulnerabilities: function () {
      return request('/threats/vulnerabilities');
    },
    geo: function () {
      return request('/threats/geo');
    },
    rules: function (params) {
      return request('/threats/rules' + qs(params));
    },
    attackMatrix: function () {
      return request('/threats/attack-matrix');
    },
    postureScan: function (domain) {
      return request('/threats/posture-scan', { method: 'POST', body: { domain: domain } });
    },
    feed: function () {
      return request('/threats/feed');
    },

    config: function () {
      return request('/config', { auth: false });
    },

    account: function () {
      return request('/account');
    },
    updateAccount: function (body) {
      return request('/account', { method: 'PATCH', body: body });
    },
    changePassword: function (body) {
      return request('/account/password', { method: 'POST', body: body });
    },
    sessions: function () {
      return request('/account/sessions');
    },
    revokeOtherSessions: function () {
      return request('/account/sessions', { method: 'DELETE' });
    },

    adminUsers: function () {
      return request('/admin/users');
    },
    adminUpdateUser: function (id, body) {
      return request('/admin/users/' + encodeURIComponent(id), { method: 'PATCH', body: body });
    },
    adminStats: function () {
      return request('/admin/stats');
    },
    adminAudit: function (limit) {
      return request('/admin/audit' + qs({ limit: limit }));
    },

    login: function (email, password) {
      return request('/auth/login', {
        method: 'POST',
        auth: false,
        body: { email: email, password: password }
      });
    },
    /**
     * Completes a challenged sign-in. Accepts a TOTP code or a recovery code;
     * the server decides which it was and reports it back as `method`.
     */
    loginMfa: function (challenge, code) {
      return request('/auth/login/mfa', {
        method: 'POST',
        auth: false,
        body: { challenge: challenge, code: code }
      });
    },
    verifyReset: function (token) {
      return request('/auth/reset/verify', { method: 'POST', auth: false, body: { token: token } });
    },
    completeReset: function (token, password) {
      return request('/auth/reset', {
        method: 'POST',
        auth: false,
        body: { token: token, password: password }
      });
    },
    register: function (body) {
      return request('/auth/register', { method: 'POST', auth: false, body: body });
    },
    me: function () {
      return request('/auth/me');
    },
    logout: function () {
      return request('/auth/logout', { method: 'POST' }).catch(function () {
        // Local sign-out must succeed even if the server call fails.
        return null;
      });
    },
    passwordCheck: function (password) {
      return request('/auth/password-check', {
        method: 'POST',
        auth: false,
        body: { password: password }
      });
    }
  };

  /* ----------------------------------------------------------- SSE stream */

  /**
   * Subscribes to the live detection stream.
   * @param {Object} handlers map of event name → callback
   * @returns {{close: Function}}
   */
  function stream(handlers) {
    if (typeof EventSource === 'undefined') return { close: function () {} };

    var es = new EventSource(BASE + '/alerts/stream');
    var closed = false;

    Object.keys(handlers || {}).forEach(function (name) {
      if (name === 'error') return;
      es.addEventListener(name, function (evt) {
        var data = null;
        try {
          data = JSON.parse(evt.data);
        } catch (e) {
          return;
        }
        handlers[name](data);
      });
    });

    es.addEventListener('error', function () {
      // EventSource reconnects on its own; surface state for the UI badge.
      if (handlers.error && !closed) handlers.error(es.readyState);
    });

    return {
      close: function () {
        closed = true;
        es.close();
      },
      raw: es
    };
  }

  window.VGIL = {
    api: api,
    session: session,
    request: request,
    stream: stream,
    qs: qs
  };
})();
