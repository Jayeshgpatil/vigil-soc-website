/**
 * Theme bootstrap.
 *
 * Loaded from <head> without `defer` so it runs before the body paints. The
 * usual trick is an inline <script>, but the CSP here is `script-src 'self'`
 * with no nonce, so a same-origin file is the way to get the same timing
 * without punching a hole in the policy.
 *
 * Anything slower than this — waiting for DOMContentLoaded, or letting
 * main.js handle it — produces a visible flash of the wrong theme on every
 * navigation.
 *
 * Dark is the fixed default. An earlier version honoured
 * prefers-color-scheme, which meant a visitor on a light-mode operating
 * system was served a light site they had never asked for — the site's own
 * appearance changing out from under it. The palette is part of the design,
 * not a preference to be inferred, so it only ever changes when somebody
 * presses the toggle.
 */
(function () {
  'use strict';

  var KEY = 'vgil-theme';
  var DEFAULT = 'dark';
  var root = document.documentElement;

  /** An explicit choice, or null when the visitor has never made one. */
  function stored() {
    try {
      var value = localStorage.getItem(KEY);
      return value === 'light' || value === 'dark' ? value : null;
    } catch (err) {
      // Private browsing and blocked storage both throw here. The site works
      // fine without persistence; it just forgets between pages.
      return null;
    }
  }

  function effective() {
    return stored() || DEFAULT;
  }

  function apply(theme) {
    // The stylesheet is dark-first, so only "light" needs an attribute.
    if (theme === 'light') root.setAttribute('data-theme', 'light');
    else root.removeAttribute('data-theme');

    // Keeps the browser chrome (address bar, form controls) in step.
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#f4f7fa' : '#05080d');
  }

  function set(theme) {
    try {
      localStorage.setItem(KEY, theme);
    } catch (err) {
      /* not persistable — apply for this page anyway */
    }
    apply(theme);
    window.dispatchEvent(new CustomEvent('vgil:themechange', { detail: { theme: theme } }));
    return theme;
  }

  apply(effective());

  window.VGTheme = {
    get: effective,
    set: set,
    toggle: function () {
      return set(effective() === 'light' ? 'dark' : 'light');
    },
    /** Drops any override and returns to the site's own default. */
    clear: function () {
      try {
        localStorage.removeItem(KEY);
      } catch (err) {
        /* nothing to clear */
      }
      apply(DEFAULT);
    }
  };
})();
