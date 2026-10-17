/**
 * Administration page: accounts, roles, storage stats, audit trail, export.
 *
 * The server enforces the admin role on every route here; this script only
 * decides what to show. A non-admin who loads the page gets a clear message
 * rather than a wall of failed requests.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  if (!V.session.isAuthed()) return; // main.js already redirected

  var me = V.session.user() || {};

  /* --------------------------------------------------------------- gating */

  function denyAccess(message) {
    var box = $('#admin-denied');
    box.replaceChildren();

    box.appendChild(el('strong', null, 'Administrator access required. '));
    box.appendChild(document.createTextNode(message));

    var link = el('a', 'link-arrow', 'Back to the console');
    link.href = '/vigil-soc-website/dashboard.html';
    link.style.display = 'inline-flex';
    link.style.marginLeft = '.5rem';
    box.appendChild(link);

    box.hidden = false;
    $('#admin-body').hidden = true;
    $('#export-btn').disabled = true;
  }

  if (me.role !== 'admin') {
    denyAccess(
      'You are signed in as ' + (me.role || 'an analyst') + '. Ask an administrator to change your role.'
    );
    return;
  }

  /* ---------------------------------------------------------------- stats */

  function formatBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(0) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  function setStat(key, value, sub) {
    var v = $('[data-astat="' + key + '"]');
    var s = $('[data-astat-sub="' + key + '"]');
    if (v) v.textContent = value;
    if (s) s.textContent = sub;
  }

  V.api
    .adminStats()
    .then(function (res) {
      var d = res.data;
      setStat('users', window.VG.num(d.counts.users), d.counts.sessions + ' sessions recorded');
      setStat('alerts', window.VG.num(d.counts.alerts), d.counts.alertNotes + ' analyst notes');
      setStat('size', formatBytes(d.database.sizeBytes), d.database.journalMode.toUpperCase() + ' journal');
      setStat('schema', 'v' + d.database.schemaVersion, d.database.driver);
    })
    .catch(function (err) {
      if (err.status === 403) return denyAccess(err.message);
      window.VG.toast('Could not load stats', err.message, 'crit');
    });

  /* ---------------------------------------------------------------- users */

  var userRows = $('#user-rows');

  function roleSelect(user) {
    var select = el('select', 'select');
    select.style.minWidth = '104px';
    select.style.padding = '.25rem .5rem';
    select.style.fontSize = '.78rem';

    ['analyst', 'admin'].forEach(function (r) {
      var opt = el('option', null, r);
      opt.value = r;
      if (user.role === r) opt.selected = true;
      select.appendChild(opt);
    });

    // Protected accounts render the role but cannot change it.
    var locked = user.demo || user.id === me.id;
    select.disabled = locked;
    select.title = user.demo
      ? 'Shared demo accounts cannot be modified'
      : user.id === me.id
      ? 'You cannot change your own role'
      : 'Change role';

    select.addEventListener('change', function () {
      updateUser(user, { role: select.value }, select);
    });

    return select;
  }

  function updateUser(user, patch, control) {
    if (control) control.disabled = true;

    V.api
      .adminUpdateUser(user.id, patch)
      .then(function (res) {
        var what = Object.keys(patch)[0];
        window.VG.toast(
          'Account updated',
          user.email + ' → ' + what + ' ' + patch[what] +
            (res.sessionsRevoked ? ' (' + res.sessionsRevoked + ' session(s) revoked)' : '')
        );
        return loadUsers();
      })
      .catch(function (err) {
        window.VG.toast('Update refused', err.message, 'crit');
        if (control) control.disabled = false;
        loadUsers();
      });
  }

  function loadUsers() {
    return V.api
      .adminUsers()
      .then(function (res) {
        userRows.replaceChildren();
        $('#user-count').textContent = res.total + ' accounts';
        $('#admin-note').textContent =
          res.admins + ' admin · ' + res.disabled + ' disabled';

        res.data.forEach(function (u) {
          var tr = el('tr');

          var name = el('td', 'strong');
          name.textContent = u.name;
          if (u.id === me.id) {
            name.appendChild(document.createTextNode(' '));
            name.appendChild(el('span', 'badge sev-ok', 'you'));
          }
          if (u.demo) {
            name.appendChild(document.createTextNode(' '));
            name.appendChild(el('span', 'badge', 'demo'));
          }
          tr.appendChild(name);

          tr.appendChild(el('td', 'cell-mono', u.email));

          var role = el('td');
          role.appendChild(roleSelect(u));
          tr.appendChild(role);

          tr.appendChild(el('td', null, u.org || '—'));

          var created = el('td', 'cell-mono');
          created.textContent = window.VG.timeAgo(u.createdAt);
          created.title = window.VG.fullTime(u.createdAt);
          tr.appendChild(created);

          var seen = el('td', 'cell-mono');
          seen.textContent = u.lastLogin ? window.VG.timeAgo(u.lastLogin) : 'never';
          if (u.lastLogin) seen.title = window.VG.fullTime(u.lastLogin);
          tr.appendChild(seen);

          var state = el('td');
          state.appendChild(
            u.disabled
              ? el('span', 'badge badge-dot sev-critical', 'disabled')
              : el('span', 'badge badge-dot sev-ok', 'active')
          );
          tr.appendChild(state);

          var action = el('td');
          var locked = u.demo || u.id === me.id;

          if (!locked) {
            var btn = el(
              'button',
              'btn btn-sm ' + (u.disabled ? 'btn-ghost' : 'btn-danger'),
              u.disabled ? 'Enable' : 'Disable'
            );
            btn.type = 'button';
            btn.addEventListener('click', function () {
              updateUser(u, { disabled: u.disabled ? 'false' : 'true' }, btn);
            });
            action.appendChild(btn);
          } else {
            action.appendChild(el('span', 'text-dim', '—'));
          }
          tr.appendChild(action);

          userRows.appendChild(tr);
        });

        if (window.VGFx) window.VGFx.cascade(userRows.children, { step: 35 });
      })
      .catch(function (err) {
        if (err.status === 403) return denyAccess(err.message);
        userRows.replaceChildren(
          window.VG.errorCell(8, 'Could not load accounts: ' + err.message)
        );
      });
  }

  loadUsers();

  /* ---------------------------------------------------------------- audit */

  var auditRows = $('#audit-rows');

  V.api
    .adminAudit(60)
    .then(function (res) {
      auditRows.replaceChildren();

      if (!res.data.length) {
        auditRows.appendChild(window.VG.errorCell(4, 'No audit entries yet.'));
        return;
      }

      res.data.forEach(function (a) {
        var tr = el('tr');

        var when = el('td', 'cell-mono');
        when.textContent = window.VG.timeAgo(a.ts);
        when.title = window.VG.fullTime(a.ts);
        tr.appendChild(when);

        var action = el('td');
        var failed = a.action.indexOf('failed') !== -1;
        action.appendChild(
          el('span', 'badge mono ' + (failed ? 'sev-critical' : ''), a.action)
        );
        tr.appendChild(action);

        tr.appendChild(el('td', null, a.detail || '—'));
        tr.appendChild(el('td', 'cell-mono', a.ip || '—'));

        auditRows.appendChild(tr);
      });
    })
    .catch(function (err) {
      if (err.status === 403) return;
      auditRows.replaceChildren(
        window.VG.errorCell(4, 'Could not load audit trail: ' + err.message)
      );
    });

  /* --------------------------------------------------------------- export */

  $('#export-btn').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;
    btn.textContent = 'Exporting…';

    // Fetched with the bearer token rather than navigated to, since a plain
    // link cannot carry the Authorization header.
    fetch('/vigil-soc-website/api/admin/export', {
      headers: { Authorization: 'Bearer ' + V.session.token() }
    })
      .then(function (res) {
        if (!res.ok) throw new Error('Export failed (' + res.status + ')');
        return res.blob();
      })
      .then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = el('a');
        a.href = url;
        a.download = 'vgil-export-' + new Date().toISOString().slice(0, 10) + '.json';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        window.VG.toast('Export ready', 'Download started.');
      })
      .catch(function (err) {
        window.VG.toast('Export failed', err.message, 'crit');
      })
      .then(function () {
        btn.disabled = false;
        btn.textContent = 'Export tenant data';
      });
  });

  /* ==================================================================
     EVENT WEBHOOKS
     ================================================================== */

  var HOOK_EVENTS = [
    ['incident.opened', 'Incident opened'],
    ['incident.escalated', 'Status changed'],
    ['incident.closed', 'Incident closed'],
    ['alert.critical', 'Critical alert'],
    ['auth.mfa.disabled', '2FA turned off']
  ];

  function buildEventChecks() {
    var host = $('#hook-events');
    if (!host) return;

    host.textContent = '';

    HOOK_EVENTS.forEach(function (pair, index) {
      var label = document.createElement('label');
      label.className = 'flex gap-sm items-center';
      label.style.cssText = 'font-size:.85rem;cursor:pointer';

      var box = document.createElement('input');
      box.type = 'checkbox';
      box.name = 'events';
      box.value = pair[0];
      // The common case is "tell me when something opens", so it starts ticked.
      box.checked = index === 0;

      label.appendChild(box);
      label.appendChild(document.createTextNode(pair[1]));
      host.appendChild(label);
    });
  }

  function hookStateBadge(hook) {
    var badge = document.createElement('span');

    if (!hook.active) {
      badge.className = 'badge';
      badge.textContent = 'Paused';
    } else if (hook.failureCount >= 3) {
      badge.className = 'badge is-crit';
      badge.textContent = 'Failing (' + hook.failureCount + ')';
    } else if (hook.lastStatus === 'delivered') {
      badge.className = 'badge is-ok';
      badge.textContent = 'Healthy';
    } else if (hook.lastStatus) {
      badge.className = 'badge is-high';
      badge.textContent = 'Last failed';
    } else {
      badge.className = 'badge is-info';
      badge.textContent = 'Untested';
    }

    return badge;
  }

  function renderHooks(hooks) {
    var body = $('#hook-rows');
    if (!body) return;

    body.textContent = '';

    var count = $('#hook-count');
    if (count) {
      var active = hooks.filter(function (h) { return h.active; }).length;
      count.textContent = active + ' ACTIVE';
    }

    if (!hooks.length) {
      body.appendChild(window.VG.errorCell(5, 'No webhooks configured.'));
      return;
    }

    hooks.forEach(function (hook) {
      var row = document.createElement('tr');

      var url = document.createElement('td');
      url.className = 'mono';
      url.style.cssText = 'max-width:280px;overflow:hidden;text-overflow:ellipsis';
      // Operator-supplied text, so textContent rather than innerHTML.
      url.textContent = hook.url;
      if (hook.description) {
        var note = document.createElement('div');
        note.className = 'text-muted';
        note.style.fontSize = '.78rem';
        note.textContent = hook.description;
        url.appendChild(note);
      }
      row.appendChild(url);

      var events = document.createElement('td');
      events.style.fontSize = '.8rem';
      events.textContent = hook.events.join(', ');
      row.appendChild(events);

      var state = document.createElement('td');
      state.appendChild(hookStateBadge(hook));
      row.appendChild(state);

      var last = document.createElement('td');
      if (hook.lastAttemptAt) {
        last.textContent = window.VG.timeAgo(hook.lastAttemptAt);
        if (hook.lastError) {
          var err = document.createElement('div');
          err.className = 'text-muted';
          err.style.cssText = 'font-size:.75rem;color:var(--crit)';
          err.textContent = hook.lastError;
          last.appendChild(err);
        }
      } else {
        last.textContent = 'never';
      }
      row.appendChild(last);

      var actions = document.createElement('td');
      actions.className = 'flex gap-sm wrap-flex';

      var test = document.createElement('button');
      test.className = 'btn btn-ghost btn-sm';
      test.type = 'button';
      test.textContent = 'Test';
      test.addEventListener('click', function () {
        test.disabled = true;
        test.textContent = 'Sending…';
        V.request('/admin/webhooks/' + encodeURIComponent(hook.id) + '/test', { method: 'POST' })
          .then(function (res) {
            window.VG.toast(
              res.delivered ? 'Delivered' : 'Delivery failed',
              res.message,
              res.delivered ? 'ok' : 'crit'
            );
            loadHooks();
          })
          .catch(function (err) {
            window.VG.toast('Test failed', err.message, 'crit');
            test.disabled = false;
            test.textContent = 'Test';
          });
      });
      actions.appendChild(test);

      var pause = document.createElement('button');
      pause.className = 'btn btn-ghost btn-sm';
      pause.type = 'button';
      pause.textContent = hook.active ? 'Pause' : 'Resume';
      pause.addEventListener('click', function () {
        V.request('/admin/webhooks/' + encodeURIComponent(hook.id), {
          method: 'PATCH',
          body: { active: !hook.active }
        })
          .then(function () {
            window.VG.toast(
              hook.active ? 'Paused' : 'Resumed',
              hook.url,
              'ok'
            );
            loadHooks();
          })
          .catch(function (err) {
            window.VG.toast('Could not update', err.message, 'crit');
          });
      });
      actions.appendChild(pause);

      var remove = document.createElement('button');
      remove.className = 'btn btn-ghost btn-sm';
      remove.type = 'button';
      remove.textContent = 'Remove';
      remove.addEventListener('click', function () {
        if (!confirm('Remove this webhook? Deliveries to ' + hook.url + ' stop immediately.')) return;
        V.request('/admin/webhooks/' + encodeURIComponent(hook.id), { method: 'DELETE' })
          .then(function () {
            window.VG.toast('Webhook removed', hook.url, 'ok');
            loadHooks();
          })
          .catch(function (err) {
            window.VG.toast('Could not remove', err.message, 'crit');
          });
      });
      actions.appendChild(remove);

      row.appendChild(actions);
      body.appendChild(row);
    });
  }

  function loadHooks() {
    return V.request('/admin/webhooks')
      .then(function (res) { renderHooks(res.data || []); })
      .catch(function (err) {
        var body = $('#hook-rows');
        if (body) {
          body.textContent = '';
          body.appendChild(window.VG.errorCell(5, 'Could not load webhooks: ' + err.message));
        }
      });
  }

  var hookForm = $('#hook-form');
  if (hookForm) {
    buildEventChecks();

    window.VG.bindForm(
      hookForm,
      function (values) {
        // bindForm flattens FormData, which keeps only the last value for a
        // repeated name, so the checkboxes are read from the DOM instead.
        var events = Array.prototype.slice
          .call(hookForm.querySelectorAll('input[name="events"]:checked'))
          .map(function (box) { return box.value; });

        if (!events.length) {
          return Promise.reject(
            Object.assign(new Error('Choose at least one event.'), {
              fields: { events: 'Choose at least one event.' }
            })
          );
        }

        return V.request('/admin/webhooks', {
          method: 'POST',
          body: { url: values.url, description: values.description, events: events }
        });
      },
      {
        busyText: 'Adding…',
        onSuccess: function (res) {
          var panel = $('#hook-created');
          var secret = $('#hook-secret');
          if (secret) secret.textContent = res.secret;
          if (panel) panel.hidden = false;

          hookForm.reset();
          buildEventChecks();
          loadHooks();
        }
      }
    );
  }

  var hookCopy = $('#hook-copy');
  if (hookCopy) {
    hookCopy.addEventListener('click', function () {
      var text = $('#hook-secret').textContent;

      function done() {
        window.VG.toast('Copied', 'Signing secret copied.', 'ok');
      }

      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, function () {
          window.VG.toast('Copy failed', 'Select the text and copy it manually.', 'warn');
        });
      } else {
        window.VG.toast('Copy manually', 'Select the secret and copy it.', 'warn');
      }
    });
  }

  loadHooks();
})();
