/**
 * Password reset page.
 *
 * The token arrives in the query string. It is checked with the server before
 * the form is shown, so somebody following a link that has expired or already
 * been used is told so immediately rather than after typing a new password
 * twice.
 */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;

  var token = new URLSearchParams(location.search).get('token') || '';

  var checking = $('#reset-checking');
  var invalid = $('#reset-invalid');
  var formWrap = $('#reset-form-wrap');
  var done = $('#reset-done');
  var form = $('#reset-form');

  function show(section) {
    [checking, invalid, formWrap, done].forEach(function (node) {
      if (node) node.hidden = node !== section;
    });
  }

  function fail(message) {
    var reason = $('#reset-invalid-reason');
    if (reason) reason.textContent = message;
    show(invalid);
  }

  /* ------------------------------------------------------- token check */

  if (!token) {
    fail('No reset token was supplied. Use the full link you were given.');
    return;
  }

  V.api
    .verifyReset(token)
    .then(function (res) {
      var email = $('#reset-email');
      // Already masked by the server — the page is reachable without a
      // session, so it must not confirm a full address to whoever opens it.
      if (email) email.textContent = res.email || 'your account';
      show(formWrap);
      var field = $('#password');
      if (field) field.focus();
    })
    .catch(function (err) {
      fail(err.message || 'This link is not valid.');
    });

  /* ------------------------------------------------- strength feedback */

  var bar = $('#pw-bar');
  var label = $('#pw-label');
  var strengthTimer = null;

  var passwordField = $('#password');
  if (passwordField && bar) {
    passwordField.addEventListener('input', function () {
      clearTimeout(strengthTimer);
      var value = passwordField.value;

      if (!value) {
        bar.style.width = '0%';
        bar.className = '';
        if (label) label.textContent = 'Use at least 12 characters, mixing letters, numbers and symbols.';
        return;
      }

      // Debounced: this is a network call on every keystroke otherwise.
      strengthTimer = setTimeout(function () {
        V.api
          .passwordCheck(value)
          .then(function (res) {
            bar.style.width = ((res.score + 1) / 6) * 100 + '%';
            bar.className = res.ok ? 'ok' : res.score >= 2 ? 'mid' : 'weak';
            if (label) {
              label.textContent = res.ok
                ? res.label + ' — good to go.'
                : res.label + (res.issues.length ? ' — needs ' + res.issues.join(', ') + '.' : '');
            }
          })
          .catch(function () {
            /* the server-side check on submit is the one that counts */
          });
      }, 220);
    });
  }

  /* ---------------------------------------------------------- submit */

  if (form) {
    window.VG.bindForm(
      form,
      function (values) {
        // Checked here purely so the mismatch is caught before a round trip;
        // the server never sees or needs the confirmation field.
        if (values.password !== values.confirm) {
          return Promise.reject(
            Object.assign(new Error('Those passwords do not match.'), {
              fields: { confirm: 'Those passwords do not match.' }
            })
          );
        }
        return V.api.completeReset(token, values.password);
      },
      {
        busyText: 'Updating…',
        onSuccess: function (res) {
          var detail = $('#reset-done-detail');
          if (detail && res.sessionsRevoked) {
            detail.textContent =
              'You can sign in with your new password now. ' +
              res.sessionsRevoked +
              ' existing session' +
              (res.sessionsRevoked === 1 ? ' was' : 's were') +
              ' signed out.';
          }
          show(done);
          // The token is spent; drop it from the address bar so a reload or a
          // shared URL does not carry a dead credential.
          history.replaceState(null, '', '/reset.html');
        }
      }
    );
  }
})();
