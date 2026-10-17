/** Sign-in and sign-up forms, plus the live password strength meter. */
(function () {
  'use strict';

  var V = window.VGIL;
  var $ = window.VG.$;
  var $$ = window.VG.$$;

  /** Only allow same-origin, path-only redirects — never an absolute URL. */
  function safeNext() {
    var next = new URLSearchParams(location.search).get('next');
    if (!next) return '/vigil-soc-website/dashboard.html';
    if (next.charAt(0) !== '/' || next.indexOf('//') === 0) return '/vigil-soc-website/dashboard.html';
    return next;
  }

  function afterAuth(res) {
    V.session.set(res.token, res.user);
    window.VG.toast('Welcome, ' + res.user.name.split(' ')[0], 'Session established.');
    setTimeout(function () {
      location.href = safeNext();
    }, 500);
  }

  /* ------------------------------------------------- deployment features */

  /**
   * The sign-in page ships the demo credentials hidden, and the sign-up page
   * assumes registration is open. Both are corrected from /api/config, so a
   * production deployment never advertises a shared admin password and a
   * locked-down one says so before the visitor fills the form.
   */
  function applyDeploymentConfig() {
    V.api.config()
      .then(function (cfg) {
        var creds = $('#demo-creds');
        if (creds && cfg.demoMode) creds.hidden = false;

        var closed = $('#registration-closed');
        if (closed && !cfg.registrationOpen) {
          closed.textContent =
            'Sign-up is disabled on this deployment. Ask an administrator for an account.';
          closed.hidden = false;

          var form = $('#signup-form');
          if (form) {
            form.querySelectorAll('input, button').forEach(function (n) {
              n.disabled = true;
            });
          }
        }
      })
      .catch(function () {
        // Config unreachable: leave the safe defaults in place.
      });
  }

  applyDeploymentConfig();

  /* --------------------------------------------------------------- login */

  var loginForm = $('#login-form');

  if (loginForm) {
    // Already signed in? Go straight through.
    if (V.session.isAuthed()) location.href = safeNext();

    // Held between the two steps. Never persisted: it is a credential, it is
    // valid for five minutes, and a reload should restart the sign-in.
    var pendingChallenge = null;

    window.VG.bindForm(
      loginForm,
      function (values) {
        return V.api.login(values.email, values.password);
      },
      {
        busyText: 'Authenticating…',
        onSuccess: function (res) {
          // A second factor is enrolled: the password step produced a
          // challenge rather than a session, so swap in the code form.
          if (res && res.mfaRequired) {
            pendingChallenge = res.challenge;
            showMfaStep(res);
            return;
          }
          afterAuth(res);
        }
      }
    );

    var mfaStep = $('#mfa-step');
    var mfaForm = $('#mfa-form');

    function showMfaStep(res) {
      loginForm.hidden = true;
      var intro = $('#login-intro');
      if (intro) intro.hidden = true;
      mfaStep.hidden = false;

      var recoveryHint = $('#mfa-recovery-hint');
      if (recoveryHint) recoveryHint.hidden = !res.recoveryAvailable;

      var code = $('#mfa-code');
      if (code) {
        code.value = '';
        code.focus();
      }
    }

    if (mfaForm) {
      window.VG.bindForm(
        mfaForm,
        function (values) {
          if (!pendingChallenge) {
            return Promise.reject(
              Object.assign(new Error('That sign-in attempt expired. Enter your password again.'), {
                status: 401
              })
            );
          }
          return V.api.loginMfa(pendingChallenge, values.code);
        },
        {
          busyText: 'Verifying…',
          onSuccess: function (res) {
            if (res.notice) window.VG.toast('Recovery code used', res.notice, 'warn');
            afterAuth(res);
          }
        }
      );

      // A wrong code invalidates nothing, so let the user retype rather than
      // sending them back to the password step.
      var back = $('#mfa-back');
      if (back) {
        back.addEventListener('click', function () {
          pendingChallenge = null;
          mfaStep.hidden = true;
          loginForm.hidden = false;
          var intro = $('#login-intro');
          if (intro) intro.hidden = false;
          $('#password').value = '';
          $('#password').focus();
        });
      }
    }

    var DEMO = {
      analyst: ['analyst@vgil.io', 'Vgil#Demo2026'],
      admin: ['admin@vgil.io', 'Vgil#Admin2026']
    };

    $$('[data-fill]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var creds = DEMO[btn.dataset.fill];
        if (!creds) return;
        $('#email').value = creds[0];
        $('#password').value = creds[1];
        $('#email').classList.remove('invalid');
        $('#password').classList.remove('invalid');
      });
    });
  }

  /* -------------------------------------------------------------- signup */

  var signupForm = $('#signup-form');

  if (signupForm) {
    if (V.session.isAuthed()) location.href = '/vigil-soc-website/dashboard.html';

    window.VG.bindForm(
      signupForm,
      function (values) {
        return V.api.register({
          name: values.name,
          email: values.email,
          org: values.org,
          password: values.password
        });
      },
      { busyText: 'Creating account…', onSuccess: afterAuth }
    );

    // Live strength feedback, scored by the same server-side rules that
    // will reject the password on submit.
    var pw = $('#password');
    var meter = $('#strength');
    var hint = $('#strength-hint');
    var debounce;

    if (pw && meter) {
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
    }
  }
})();
