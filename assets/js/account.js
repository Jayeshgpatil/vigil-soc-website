/**
 * Account page: profile, password change and session management.
 * Every request here acts on the caller's own account — no user id is ever
 * sent, so this page cannot be pointed at somebody else.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var el = window.VG.el;

  if (!V.session.isAuthed()) return; // main.js already redirected

  /* ------------------------------------------------------------- profile */

  function fillProfile(user) {
    $('#name').value = user.name || '';
    $('#title').value = user.title || '';
    $('#org').value = user.org || '';
    $('#email-ro').value = user.email || '';

    var badge = $('[data-role-badge]');
    badge.textContent = user.role;
    badge.className = 'badge mono ' + (user.role === 'admin' ? 'sev-ok' : '');

    // Keep the cached identity in step, so the header greeting updates too.
    V.session.set(V.session.token(), user);
  }

  V.api
    .me()
    .then(function (res) {
      fillProfile(res.user);
    })
    .catch(function (err) {
      if (err.status === 401) {
        location.href = '/vigil-soc-website/login.html?next=/account.html';
        return;
      }
      window.VG.toast('Could not load profile', err.message, 'crit');
    });

  window.VG.bindForm(
    $('#profile-form'),
    function (values) {
      // Only send fields that were actually filled in; the API rejects an
      // entirely empty patch.
      var patch = {};
      ['name', 'title', 'org'].forEach(function (k) {
        if (values[k]) patch[k] = values[k];
      });
      return V.api.updateAccount(patch);
    },
    {
      busyText: 'Saving…',
      onSuccess: function (res, form, showNotice) {
        fillProfile(res.user);
        showNotice('Profile updated.', 'notice-ok');
        window.VG.toast('Saved', 'Your profile has been updated.');
      }
    }
  );

  /* ------------------------------------------------------------ password */

  // Live strength meter, scored by the same server rules that will accept or
  // reject the password on submit.
  var pw = $('#newPassword');
  var meter = $('#pw-strength');
  var hint = $('#pw-hint');
  var debounce;

  pw.addEventListener('input', function () {
    var value = pw.value;

    if (!value) {
      meter.className = 'strength';
      hint.textContent =
        'Minimum 10 characters with upper and lower case, a number and a symbol.';
      return;
    }

    clearTimeout(debounce);
    debounce = setTimeout(function () {
      V.api
        .passwordCheck(value)
        .then(function (res) {
          meter.className = 'strength s' + res.score;
          hint.textContent = res.ok
            ? res.label + ' — this password is acceptable.'
            : res.label + ' — still needs ' + res.issues.join(', ') + '.';
        })
        .catch(function () {});
    }, 220);
  });

  var pwForm = $('#password-form');
  var pwNotice = $('[data-pw-notice]');

  window.VG.bindForm(
    pwForm,
    function (values) {
      return V.api.changePassword({
        currentPassword: values.currentPassword,
        newPassword: values.newPassword
      });
    },
    {
      busyText: 'Updating…',
      onSuccess: function (res) {
        pwForm.reset();
        meter.className = 'strength';
        hint.textContent =
          'Minimum 10 characters with upper and lower case, a number and a symbol.';

        pwNotice.className = 'notice notice-ok mb-2';
        pwNotice.textContent =
          'Password updated. ' +
          res.otherSessionsRevoked +
          ' other session(s) signed out.';
        pwNotice.hidden = false;

        window.VG.toast('Password changed', 'Other devices have been signed out.');
        loadSessions();
      }
    }
  );

  // bindForm renders field errors into [data-err]; the password form's own
  // notice slot is separate from the profile form's, so point it at ours.
  pwForm.addEventListener('submit', function () {
    pwNotice.hidden = true;
  });

  /* ------------------------------------------------------------ sessions */

  var rows = $('#session-rows');

  function loadSessions() {
    return V.api
      .sessions()
      .then(function (res) {
        rows.replaceChildren();
        $('[data-session-count]').textContent = res.active + ' active';

        if (!res.data.length) {
          rows.appendChild(window.VG.errorCell(3, 'No sessions recorded.'));
          return;
        }

        res.data.forEach(function (s) {
          var tr = el('tr');

          var when = el('td', 'cell-mono');
          when.textContent = window.VG.timeAgo(s.issuedAt);
          when.title = window.VG.fullTime(s.issuedAt);
          tr.appendChild(when);

          tr.appendChild(el('td', 'cell-mono', s.ip || 'unknown'));

          var state = el('td');
          if (s.current) {
            state.appendChild(el('span', 'badge badge-dot sev-ok', 'this device'));
          } else if (s.revoked) {
            state.appendChild(el('span', 'badge', 'signed out'));
          } else if (s.active) {
            state.appendChild(el('span', 'badge badge-dot sev-medium', 'active'));
          } else {
            state.appendChild(el('span', 'badge', 'expired'));
          }
          tr.appendChild(state);

          rows.appendChild(tr);
        });

        if (window.VGFx) window.VGFx.cascade(rows.children, { step: 40 });
      })
      .catch(function (err) {
        rows.replaceChildren(
          window.VG.errorCell(3, 'Could not load sessions: ' + err.message)
        );
      });
  }

  loadSessions();

  $('#revoke-others').addEventListener('click', function () {
    var btn = this;
    btn.disabled = true;

    V.api
      .revokeOtherSessions()
      .then(function (res) {
        window.VG.toast(
          'Signed out elsewhere',
          res.revoked + ' session(s) revoked. This device stays signed in.'
        );
        return loadSessions();
      })
      .catch(function (err) {
        window.VG.toast('Could not revoke', err.message, 'crit');
      })
      .then(function () {
        btn.disabled = false;
      });
  });

  /* ==================================================================
     TWO-FACTOR AUTHENTICATION
     ==================================================================
     Three mutually exclusive states — off, mid-enrolment, on — plus a
     one-shot recovery-code panel. Enrolment is staged server-side through a
     pending secret, so abandoning it here leaves the account exactly as it
     was rather than half-protected.
     ================================================================== */

  var mfaState = { enabled: false, pending: false, secret: null };

  function showMfaState() {
    var off = $('#mfa-off');
    var setup = $('#mfa-setup');
    var on = $('#mfa-on');
    if (!off) return;

    off.hidden = mfaState.enabled || mfaState.secret !== null;
    setup.hidden = mfaState.secret === null;
    on.hidden = !mfaState.enabled;

    var badge = $('#mfa-badge');
    if (badge) {
      badge.textContent = mfaState.enabled ? 'ON' : mfaState.secret ? 'SETTING UP' : 'OFF';
      badge.className = 'badge mono ' + (mfaState.enabled ? 'is-ok' : 'is-high');
    }
  }

  function loadMfa() {
    return V.request('/account/mfa')
      .then(function (res) {
        mfaState.enabled = res.enabled;
        mfaState.pending = res.pending;

        var since = $('#mfa-since');
        if (since) since.textContent = res.confirmedAt ? window.VG.fullTime(res.confirmedAt) : '—';

        var remaining = $('#mfa-remaining');
        if (remaining) remaining.textContent = res.recoveryCodesRemaining;

        // Warn before someone is down to their last way back in.
        if (res.enabled && res.recoveryCodesRemaining <= 2) {
          window.VG.toast(
            'Recovery codes running low',
            res.recoveryCodesRemaining + ' left. Generate a new set.',
            'warn'
          );
        }

        showMfaState();
      })
      .catch(function () {
        /* the panel simply stays in its loading state */
      });
  }

  /** Renders the one-time list of recovery codes. */
  function showRecoveryCodes(codes) {
    var panel = $('#mfa-codes');
    var list = $('#mfa-codes-list');
    if (!panel || !list) return;

    list.textContent = '';
    codes.forEach(function (code) {
      var item = document.createElement('li');
      item.textContent = code;
      item.style.padding = '2px 0';
      list.appendChild(item);
    });

    panel.hidden = false;
    panel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    list.dataset.codes = codes.join('\n');
  }

  var enrolForm = $('#mfa-enrol-form');
  if (enrolForm) {
    window.VG.bindForm(
      enrolForm,
      function (values) {
        return V.request('/account/mfa/enrol', { method: 'POST', body: { password: values.password } });
      },
      {
        busyText: 'Starting…',
        onSuccess: function (res) {
          mfaState.secret = res.secret;

          var secret = $('#mfa-secret');
          if (secret) secret.textContent = res.manualEntry;

          // On a phone this opens the authenticator directly; on a desktop a
          // password manager registered for otpauth:// picks it up.
          var link = $('#mfa-deeplink');
          if (link) link.href = res.otpauthUrl;

          enrolForm.reset();
          showMfaState();

          var code = $('#mfa-confirm-code');
          if (code) code.focus();
        }
      }
    );
  }

  var confirmForm = $('#mfa-confirm-form');
  if (confirmForm) {
    window.VG.bindForm(
      confirmForm,
      function (values) {
        return V.request('/account/mfa/confirm', { method: 'POST', body: { code: values.code } });
      },
      {
        busyText: 'Verifying…',
        onSuccess: function (res) {
          mfaState.enabled = true;
          mfaState.secret = null;
          confirmForm.reset();
          showRecoveryCodes(res.recoveryCodes);
          loadMfa();
          window.VG.toast('Two-factor authentication on', 'Save your recovery codes.', 'ok');
        }
      }
    );
  }

  var cancelEnrol = $('#mfa-cancel');
  if (cancelEnrol) {
    cancelEnrol.addEventListener('click', function () {
      // Purely local: the pending secret is never armed, and starting again
      // replaces it.
      mfaState.secret = null;
      showMfaState();
    });
  }

  var copySecret = $('#mfa-copy-secret');
  if (copySecret) {
    copySecret.addEventListener('click', function () {
      copy($('#mfa-secret').textContent.replace(/\s/g, ''), 'Setup key copied');
    });
  }

  var regen = $('#mfa-regen');
  if (regen) {
    regen.addEventListener('click', function () {
      var password = prompt('Confirm your password to generate new recovery codes:');
      if (!password) return;

      V.request('/account/mfa/recovery-codes', { method: 'POST', body: { password: password } })
        .then(function (res) {
          showRecoveryCodes(res.recoveryCodes);
          loadMfa();
          window.VG.toast('New recovery codes', 'The previous set no longer works.', 'ok');
        })
        .catch(function (err) {
          window.VG.toast('Could not regenerate', err.message, 'crit');
        });
    });
  }

  var disableShow = $('#mfa-disable-show');
  if (disableShow) {
    disableShow.addEventListener('click', function () {
      var form = $('#mfa-disable-form');
      form.hidden = !form.hidden;
      if (!form.hidden) $('#mfa-disable-password').focus();
    });
  }

  var disableForm = $('#mfa-disable-form');
  if (disableForm) {
    window.VG.bindForm(
      disableForm,
      function (values) {
        return V.request('/account/mfa/disable', {
          method: 'POST',
          body: { password: values.password, code: values.code }
        });
      },
      {
        busyText: 'Turning off…',
        onSuccess: function () {
          mfaState.enabled = false;
          mfaState.secret = null;
          disableForm.reset();
          disableForm.hidden = true;
          $('#mfa-codes').hidden = true;
          loadMfa();
          window.VG.toast('Two-factor authentication off', 'Your account is password-only again.', 'warn');
        }
      }
    );
  }

  var copyCodes = $('#mfa-copy-codes');
  if (copyCodes) {
    copyCodes.addEventListener('click', function () {
      copy($('#mfa-codes-list').dataset.codes || '', 'Recovery codes copied');
    });
  }

  var printCodes = $('#mfa-print-codes');
  if (printCodes) {
    printCodes.addEventListener('click', function () {
      window.print();
    });
  }

  var codesDone = $('#mfa-codes-done');
  if (codesDone) {
    codesDone.addEventListener('click', function () {
      var panel = $('#mfa-codes');
      panel.hidden = true;
      // Drop the plaintext from the DOM once acknowledged.
      $('#mfa-codes-list').textContent = '';
      delete $('#mfa-codes-list').dataset.codes;
    });
  }

  /* ==================================================================
     API KEYS
     ================================================================== */

  function renderKeys(keys) {
    var body = $('#key-rows');
    if (!body) return;

    body.textContent = '';

    var live = keys.filter(function (key) { return !key.revoked; });

    var count = $('#key-count');
    if (count) count.textContent = live.length + (live.length === 1 ? ' KEY' : ' KEYS');

    if (!keys.length) {
      body.appendChild(window.VG.errorCell(5, 'No API keys yet.'));
      return;
    }

    keys.forEach(function (key) {
      var row = document.createElement('tr');

      var name = document.createElement('td');
      name.textContent = key.name;
      if (key.revoked) name.style.opacity = '.5';
      row.appendChild(name);

      var prefix = document.createElement('td');
      prefix.className = 'mono';
      // Only the stored prefix — the rest of the key exists nowhere on the
      // server, so there is nothing further to show.
      prefix.textContent = key.prefix + '…';
      row.appendChild(prefix);

      var created = document.createElement('td');
      created.textContent = window.VG.timeAgo(key.createdAt);
      row.appendChild(created);

      var used = document.createElement('td');
      used.textContent = key.lastUsedAt ? window.VG.timeAgo(key.lastUsedAt) : 'never';
      row.appendChild(used);

      var actions = document.createElement('td');
      if (key.revoked) {
        var badge = document.createElement('span');
        badge.className = 'badge is-crit';
        badge.textContent = 'Revoked';
        actions.appendChild(badge);
      } else {
        var button = document.createElement('button');
        button.className = 'btn btn-ghost btn-sm';
        button.type = 'button';
        button.textContent = 'Revoke';
        button.addEventListener('click', function () {
          if (!confirm('Revoke "' + key.name + '"? Anything using it stops working immediately.')) return;
          V.request('/account/api-keys/' + encodeURIComponent(key.id), { method: 'DELETE' })
            .then(function () {
              window.VG.toast('Key revoked', key.name + ' can no longer authenticate.', 'ok');
              loadKeys();
            })
            .catch(function (err) {
              window.VG.toast('Could not revoke', err.message, 'crit');
            });
        });
        actions.appendChild(button);
      }
      row.appendChild(actions);

      body.appendChild(row);
    });
  }

  function loadKeys() {
    return V.request('/account/api-keys')
      .then(function (res) { renderKeys(res.data || []); })
      .catch(function (err) {
        var body = $('#key-rows');
        if (body) {
          body.textContent = '';
          body.appendChild(window.VG.errorCell(5, err.message));
        }
      });
  }

  var keyForm = $('#key-form');
  if (keyForm) {
    window.VG.bindForm(
      keyForm,
      function (values) {
        return V.request('/account/api-keys', { method: 'POST', body: { name: values.name } });
      },
      {
        busyText: 'Creating…',
        onSuccess: function (res) {
          var panel = $('#key-created');
          var secret = $('#key-secret');
          if (secret) secret.textContent = res.secret;
          if (panel) panel.hidden = false;
          keyForm.reset();
          loadKeys();
        }
      }
    );
  }

  var keyCopy = $('#key-copy');
  if (keyCopy) {
    keyCopy.addEventListener('click', function () {
      copy($('#key-secret').textContent, 'API key copied');
    });
  }

  /** Clipboard with a fallback for insecure origins, where the API is absent. */
  function copy(text, message) {
    function done() {
      window.VG.toast('Copied', message, 'ok');
    }

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
      fallback();
    }

    function fallback() {
      var area = document.createElement('textarea');
      area.value = text;
      area.setAttribute('readonly', '');
      area.style.cssText = 'position:fixed;left:-9999px';
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand('copy');
        done();
      } catch (err) {
        window.VG.toast('Copy failed', 'Select the text and copy it manually.', 'warn');
      }
      document.body.removeChild(area);
    }
  }

  loadMfa();
  loadKeys();

  /* ==================================================================
     EMAIL ALERTING
     ================================================================== */

  var notifyForm = $('#notify-form');

  function renderNotifyLog(rows) {
    var body = $('#notify-log');
    if (!body) return;

    body.textContent = '';

    if (!rows.length) {
      body.appendChild(window.VG.errorCell(3, 'No messages yet.'));
      return;
    }

    rows.forEach(function (entry) {
      var row = document.createElement('tr');

      var when = document.createElement('td');
      when.textContent = window.VG.timeAgo(entry.createdAt);
      when.title = window.VG.fullTime(entry.createdAt);
      row.appendChild(when);

      var subject = document.createElement('td');
      subject.textContent = entry.subject;
      row.appendChild(subject);

      var status = document.createElement('td');
      var badge = document.createElement('span');
      badge.className =
        'badge ' + (entry.status === 'sent' ? 'is-ok' : entry.status === 'failed' ? 'is-crit' : '');
      // "spooled" is not a failure; it means there is no relay configured and
      // the message was recorded instead of sent.
      badge.textContent = entry.status;
      if (entry.error) badge.title = entry.error;
      status.appendChild(badge);
      row.appendChild(status);

      body.appendChild(row);
    });
  }

  function fillNotifySelects(options, prefs) {
    var severity = $('#n-severity');
    if (severity && !severity.options.length) {
      options.severities.forEach(function (value) {
        var option = document.createElement('option');
        option.value = value;
        option.textContent = value.charAt(0).toUpperCase() + value.slice(1) + ' and above';
        severity.appendChild(option);
      });
    }
    if (severity) severity.value = prefs.minSeverity;

    var cadence = $('#n-cadence');
    var labels = { immediate: 'As it happens', hourly: 'Hourly digest', daily: 'Daily digest' };
    if (cadence && !cadence.options.length) {
      options.cadences.forEach(function (value) {
        var option = document.createElement('option');
        option.value = value;
        option.textContent = labels[value] || value;
        cadence.appendChild(option);
      });
    }
    if (cadence) cadence.value = prefs.cadence;
  }

  function loadNotifications() {
    return V.request('/account/notifications')
      .then(function (res) {
        var prefs = res.prefs;

        $('#n-enabled').checked = prefs.emailEnabled;
        $('#n-incident').checked = prefs.onIncident;
        $('#n-critical').checked = prefs.onCritical;
        $('#n-assignment').checked = prefs.onAssignment;
        $('#n-quiet').value = prefs.quietHours || '';
        fillNotifySelects(res.options, prefs);

        var badge = $('#notify-badge');
        if (badge) {
          badge.textContent = prefs.emailEnabled ? 'ON' : 'OFF';
          badge.className = 'badge mono ' + (prefs.emailEnabled ? 'is-ok' : '');
        }

        // Say plainly what will happen. A settings page that implies mail is
        // going out when no relay exists is worse than one that admits it.
        var transport = $('#notify-transport');
        if (transport) {
          if (res.transport.mode === 'smtp') {
            transport.hidden = true;
          } else {
            transport.hidden = false;
            transport.className = 'notice notice-warn mb-2';
            transport.textContent = res.transport.note;
          }
        }

        var digestBtn = $('#n-digest');
        var pending = $('#n-pending');
        if (digestBtn && pending) {
          pending.textContent = res.pendingDigest;
          digestBtn.hidden = res.pendingDigest === 0;
        }
      })
      .catch(function () {
        /* leave the panel in its default state */
      })
      .then(function () {
        return V.request('/account/notifications/log')
          .then(function (res) { renderNotifyLog(res.data || []); })
          .catch(function () {});
      });
  }

  if (notifyForm) {
    window.VG.bindForm(
      notifyForm,
      function (values) {
        return V.request('/account/notifications', {
          method: 'PATCH',
          body: {
            emailEnabled: $('#n-enabled').checked,
            onIncident: $('#n-incident').checked,
            onCritical: $('#n-critical').checked,
            onAssignment: $('#n-assignment').checked,
            minSeverity: values.minSeverity,
            cadence: values.cadence,
            // An empty string clears the window rather than storing "".
            quietHours: values.quietHours || ''
          }
        });
      },
      {
        busyText: 'Saving…',
        onSuccess: function (res) {
          window.VG.toast(
            'Settings saved',
            res.prefs.emailEnabled
              ? 'Email alerting is on for ' + res.prefs.minSeverity + ' and above.'
              : 'Email alerting is off.',
            'ok'
          );
          loadNotifications();
        }
      }
    );

    var testBtn = $('#n-test');
    if (testBtn) {
      testBtn.addEventListener('click', function () {
        testBtn.disabled = true;
        testBtn.textContent = 'Sending…';
        V.request('/account/notifications/test', { method: 'POST' })
          .then(function (res) {
            window.VG.toast(
              res.status === 'sent' ? 'Test sent' : res.status === 'spooled' ? 'Test recorded' : 'Test failed',
              res.message,
              res.status === 'failed' ? 'crit' : 'ok'
            );
            loadNotifications();
          })
          .catch(function (err) {
            window.VG.toast('Test failed', err.message, 'crit');
          })
          .then(function () {
            testBtn.disabled = false;
            testBtn.textContent = 'Send a test';
          });
      });
    }

    var digestBtn = $('#n-digest');
    if (digestBtn) {
      digestBtn.addEventListener('click', function () {
        digestBtn.disabled = true;
        V.request('/account/notifications/digest', { method: 'POST' })
          .then(function (res) {
            window.VG.toast('Digest', res.message, 'ok');
            loadNotifications();
          })
          .catch(function (err) {
            window.VG.toast('Could not send', err.message, 'crit');
          })
          .then(function () {
            digestBtn.disabled = false;
          });
      });
    }

    loadNotifications();
  }
})();
