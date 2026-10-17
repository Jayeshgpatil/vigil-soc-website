'use strict';

/**
 * Builds public/reset.html from the login page's shell.
 *
 * Copying the header, footer and script tags by hand across a static site is
 * how they drift; deriving the new page from an existing one means the nav,
 * the theme bootstrap and the palette are identical by construction.
 */

const fs = require('fs');
const path = require('path');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const source = fs.readFileSync(path.join(PUBLIC_DIR, 'login.html'), 'utf8');

const MAIN = `<main class="auth-page">
  <div class="wrap" style="display:grid;place-items:center">
    <div class="auth-card">

      <!-- Shown while the token is being checked, so the form never appears
           for a link that turns out to be expired. -->
      <div id="reset-checking">
        <span class="eyebrow">Account recovery</span>
        <h2 style="font-size:1.6rem">Checking your link…</h2>
        <p class="text-muted mt-1" style="font-size:.9rem">One moment.</p>
      </div>

      <!-- Terminal state: no token, expired, already used, or unknown. -->
      <div id="reset-invalid" hidden>
        <span class="eyebrow">Account recovery</span>
        <h2 style="font-size:1.6rem">This link cannot be used</h2>
        <p class="text-muted mt-1" style="font-size:.9rem" id="reset-invalid-reason">
          The link is not valid.
        </p>
        <p class="text-muted mt-2" style="font-size:.85rem">
          Reset links are single-use and expire after an hour. Ask an administrator
          to issue a new one.
        </p>
        <a class="btn btn-ghost btn-block mt-2" href="/login.html">Back to sign in</a>
      </div>

      <div id="reset-form-wrap" hidden>
        <span class="eyebrow">Account recovery</span>
        <h2 style="font-size:1.6rem">Choose a new password</h2>
        <p class="text-muted mt-1" style="font-size:.9rem">
          Setting a new password for <span class="mono" id="reset-email">—</span>.
          Every other session on this account will be signed out.
        </p>

        <div class="notice notice-err mt-2" data-notice hidden></div>

        <form id="reset-form" class="mt-2" novalidate>
          <div class="field">
            <label for="password">New password</label>
            <input class="input mono" type="password" id="password" name="password"
                   autocomplete="new-password" placeholder="••••••••••••" required>
            <div class="meter mt-1" aria-hidden="true"><span id="pw-bar"></span></div>
            <div class="text-muted mt-1" style="font-size:.78rem" id="pw-label">
              Use at least 12 characters, mixing letters, numbers and symbols.
            </div>
            <div class="err" data-err="password"></div>
          </div>

          <div class="field">
            <label for="confirm">Confirm new password</label>
            <input class="input mono" type="password" id="confirm" name="confirm"
                   autocomplete="new-password" placeholder="••••••••••••" required>
            <div class="err" data-err="confirm"></div>
          </div>

          <button class="btn btn-primary btn-block btn-lg" type="submit">Set new password</button>
        </form>
      </div>

      <div id="reset-done" hidden>
        <span class="eyebrow">Account recovery</span>
        <h2 style="font-size:1.6rem">Password updated</h2>
        <p class="text-muted mt-1" style="font-size:.9rem" id="reset-done-detail">
          You can sign in with your new password now.
        </p>
        <a class="btn btn-primary btn-block mt-2" href="/login.html">Go to sign in</a>
      </div>

    </div>
  </div>
</main>`;

let html = source;

// Swap the page identity. The SEO tool regenerates the social block from
// these two, so they have to be right before it runs.
html = html.replace(
  /<title>[\s\S]*?<\/title>/,
  '<title>Reset your password — VGIL</title>'
);
html = html.replace(
  /<meta name="description" content="[^"]*">/,
  '<meta name="description" content="Set a new password for your VGIL console account using a single-use recovery link.">'
);

// Replace the whole main region.
html = html.replace(/<main class="auth-page">[\s\S]*?<\/main>/, MAIN);

// The login page's own controller does not apply here.
html = html.replace(
  '<script src="/assets/js/auth-pages.js"></script>',
  '<script src="/assets/js/reset.js"></script>'
);

// Any leftover login-only block (the demo credential panel) would be dead
// markup on this page.
html = html.replace(/<div class="demo-creds"[\s\S]*?<\/div>\s*(?=<\/div>)/, '');

fs.writeFileSync(path.join(PUBLIC_DIR, 'reset.html'), html);
console.log('wrote public/reset.html');
